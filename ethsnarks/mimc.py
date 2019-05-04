# Copyright (c) 2018 HarryR
# License: LGPL-3.0+

from functools import partial
from multiprocessing import Pool, cpu_count

try:
    # pysha3
    from sha3 import keccak_256
except ImportError:
    # pycryptodome
    from Crypto.Hash import keccak
    keccak_256 = lambda *args: keccak.new(*args, digest_bits=256)


# DEFAULT_MODULUS = 115792089237316195423570985008687907853269984665640564039457584006405596119041
# DEFAULT_EXPONENT = 3
# DEFAULT_FERMAT_EXP = (2*DEFAULT_MODULUS-1)//3
# DEFAULT_ROUNDS = 8192
# DEFAULT_SEED = b'mimc'

# this is the modulus for both bn128 and alt_bn128 curves
DEFAULT_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
DEFAULT_EXPONENT = 7
DEFAULT_FERMAT_EXP = (4*DEFAULT_MODULUS-3)//7
DEFAULT_ROUNDS = 91
DEFAULT_SEED = b'mimc'


def find_fermat_exp(e, p):
    for k in range(0, e):
        if (k * (p - 1) + 1) % e == 0:
            return (k * (p - 1) + 1)//e
    raise Exception('cannot find fermat exponent for e = {}'.format(e))

def to_bytes(*args):
    for i, _ in enumerate(args):
        if isinstance(_, str):
            yield _.encode('ascii')
        elif not isinstance(_, int) and hasattr(_, 'to_bytes'):
            # for 'F_p' or 'FQ' class etc.
            yield _.to_bytes('big')
        elif isinstance(_, bytes):
            yield _
        else:
            # Try conversion to integer first?
            yield int(_).to_bytes(32, 'big')


def H(*args):
    data = b''.join(to_bytes(*args))
    hashed = keccak_256(data).digest()
    return int.from_bytes(hashed, 'big')

# assert H(123) == 38632140595220392354280998614525578145353818029287874088356304829962854601866

mimc_constants_cache = {}

"""
Generate a sequence of round constants

These can hard-coded into circuits or generated on-demand
"""
def mimc_constants(seed=DEFAULT_SEED, p=DEFAULT_MODULUS, R=DEFAULT_ROUNDS):
    key = seed
    if key not in mimc_constants_cache:
        mimc_constants_cache[key] = []
        if isinstance(seed, str):
            seed = seed.encode('ascii')
        if isinstance(seed, bytes):
            # pre-hash byte strings before use
            seed = H(seed)
        else:
            seed = int(seed)

        for _ in range(R):
            seed = H(seed)
            mimc_constants_cache[key].append(seed)
    for c in mimc_constants_cache[key]:
        yield c


"""
The MiMC cipher: https://eprint.iacr.org/2016/492

 First round

            x    k
            |    |
            |    |
           (+)---|     X[0] = x + k
            |    |
    C[0] --(+)   |     Y[0] = X[0] + C[0]
            |    |
          (n^7)  |     Z[0] = Y[0]^7
            |    |
*****************************************
 per-round  |    |
            |    |
           (+)---|     X[i] = Z[i-1] + k
            |    |
    C[i] --(+)   |     Y[i] = X[i] + C[i]
            |    |
          (n^7)  |     Z[i] = Y[i]^7
            |    |
*****************************************
 Last round
            |    |
           (+)---'     result = Z.back() + k
            |
          result
"""
def mimc(x, k, seed=DEFAULT_SEED, p=DEFAULT_MODULUS, e=DEFAULT_EXPONENT, R=DEFAULT_ROUNDS):
    assert R > 2
    # TODO: assert gcd(p-1, e) == 1
    for c_i in list(mimc_constants(seed, p, R)):
        a = (x + k + c_i) % p
        x = pow(a, e, p)
    return (x + k) % p

def mimc_inverse(x, k, seed=DEFAULT_SEED, p=DEFAULT_MODULUS, e=DEFAULT_FERMAT_EXP, R=DEFAULT_ROUNDS):
    assert R > 2
    # TODO: assert gcd(p-1, e) == 1
    for c_i in list(mimc_constants(seed, p, R))[::-1]:
        a = pow((x - k) % p, e, p)
        x = (a - c_i) % p
    return (x - k) % p

def mimc_partial(k, seed, p, e, R, x):
    return mimc(x, k, seed, p, e, R)

def mimc_encrypt(data, k, seed=DEFAULT_SEED, p=DEFAULT_MODULUS, e=DEFAULT_EXPONENT, R=DEFAULT_ROUNDS):
    with Pool(cpu_count()) as pool:
        return pool.map(partial(mimc_partial, k, seed, p, e, R), data)

def mimc_encrypt_file(k, inpath, outpath, seed=DEFAULT_SEED, p=DEFAULT_MODULUS, e=DEFAULT_EXPONENT, R=DEFAULT_ROUNDS):
    with open(inpath, 'rb') as f:
        data = []
        size = 0
        while True:
            block = f.read(31) # 256 bits
            if len(block) == 0:
                break
            size += len(block)
            data.append(int.from_bytes(block, 'big'))
        data.append(size)
        print([x.to_bytes(32, 'big').hex() for x in data])
        data = mimc_encrypt(data, k, seed, p, e, R)
        print([x.to_bytes(32, 'big').hex() for x in data])
        with open(outpath, 'wb') as f:
            for x in data:
                f.write(x.to_bytes(32, 'big'))
            return
        raise Exception('failed to write file {}'.format(outpath))
    raise Exception('failed to read file {}'.format(inpath))

def mimc_inverse_partial(k, seed, p, e, R, x):
    return mimc_inverse(x, k, seed, p, e, R)

def mimc_decrypt(data, k, seed=DEFAULT_SEED, p=DEFAULT_MODULUS, e=DEFAULT_FERMAT_EXP, R=DEFAULT_ROUNDS):
    with Pool(cpu_count()) as pool:
        return pool.map(partial(mimc_inverse_partial, k, seed, p, e, R), data)

def mimc_decrypt_file(k, inpath, outpath, seed=DEFAULT_SEED, p=DEFAULT_MODULUS, e=DEFAULT_FERMAT_EXP, R=DEFAULT_ROUNDS):
    with open(inpath, 'rb') as f:
        data = []
        while True:
            block = f.read(32) # 256 bits
            if len(block) == 0:
                break
            data.append(int.from_bytes(block, 'big'))
        data = mimc_decrypt(data, k, seed, p, e, R)
        size = data.pop()
        assert (size + 30)//31 == len(data)
        with open(outpath, 'wb') as f:
            for x in data:
                f.write(x.to_bytes(min(31, size), 'big'))
                size -= 31
            return
        raise Exception('failed to write file {}'.format(outpath))
    raise Exception('failed to read file {}'.format(inpath))


"""
The Miyaguchi–Preneel single-block-length one-way compression
function is an extended variant of Matyas–Meyer–Oseas. It was
independently proposed by Shoji Miyaguchi and Bart Preneel.

H_i = E_{H_{i-1}}(m_i) + {H_{i-1}} + m_i

The previous output is used as the key for
the next iteration.

or..

             m_i
              |
              |----,
              |    |
              v    |
H_{i-1}--,-->[E]   |
         |    |    |
         `-->(+)<--'
              |
              v
             H_i

@param x list of inputs
@param k initial key
"""
def mimc_hash(x, k=0, seed=DEFAULT_SEED, p=DEFAULT_MODULUS, e=DEFAULT_EXPONENT, R=DEFAULT_ROUNDS):
    for x_i in x:
        r = mimc(x_i, k, seed, p, e, R)
        k = (k + x_i + r) % p
    return k

def _main():
    import argparse
    parser = argparse.ArgumentParser("MiMC")
    parser.add_argument('-p', '--modulus', metavar='N', type=int, default=DEFAULT_MODULUS, help='SNARK scalar fialed modulus')
    parser.add_argument('-r', '--rounds', metavar='N', type=int, default=DEFAULT_ROUNDS, help='number of rounds')
    parser.add_argument('-e', '--exponent', metavar='N', type=int, default=DEFAULT_EXPONENT, help='exponent for round function')
    parser.add_argument('-s', '--seed', type=bytes, default=DEFAULT_SEED, help='seed for round constants')
    parser.add_argument('-k', '--key', type=int, default=0, help='initial key')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='display settings')
    parser.add_argument('cmd', nargs='?', default='test')
    parser.add_argument('subargs', nargs='*')
    args = parser.parse_args()

    modulus = args.modulus
    exponent = args.exponent
    fermat_exp = find_fermat_exp(exponent, modulus)
    rounds = args.rounds
    seed = args.seed
    key = int(args.key)
    cmd = args.cmd

    if args.verbose:
        print('# exponent', exponent)
        print('# rounds', rounds)
        print('# seed', seed)
        print('# key', key)

    if cmd == "test":
        # With default parameters, known results
        assert mimc(1, 1) == 2447343676970420247355835473667983267115132689045447905848734383579598297563
        assert mimc_hash([1,1]) == 4087330248547221366577133490880315793780387749595119806283278576811074525767

        # Verify cross-compatibility with EVM/Solidity implementation
        assert mimc(3703141493535563179657531719960160174296085208671919316200479060314459804651,
                    134551314051432487569247388144051420116740427803855572138106146683954151557,
                    b'mimc') == 11437467823393790387399137249441941313717686441929791910070352316474327319704
        assert mimc_hash([3703141493535563179657531719960160174296085208671919316200479060314459804651,
                        134551314051432487569247388144051420116740427803855572138106146683954151557],
                       918403109389145570117360101535982733651217667914747213867238065296420114726,
                       b'mimc') == 15683951496311901749339509118960676303290224812129752890706581988986633412003
        print('OK')
        return 0

    elif cmd == "constants":
        for x in mimc_constants(seed, modulus, rounds):
            print(x % modulus)  # hex(x), x)

    elif cmd == "encrypt":
        data = [int(x) for x in args.subargs]
        result = mimc_encrypt(data, key, seed, modulus, exponent, rounds)
        print(result)
    
    elif cmd == "encrypt_file":
        mimc_encrypt_file(key, args.subargs[0], args.subargs[1])
    
    elif cmd == "decrypt_file":
        mimc_decrypt_file(key, args.subargs[0], args.subargs[1])

    elif cmd == "decrypt":
        data = [int(x) for x in args.subargs]
        result = mimc_decrypt(data, key, seed, modulus, fermat_exp, rounds)
        print(result)

    elif cmd == "hash":
        result = mimc_hash([int(x) for x in args.subargs], key, seed, modulus, exponent, rounds)
        print(result)

    else:
        parser.print_help()
        return 1

    return 0
        

if __name__ == "__main__":
    import sys
    sys.exit(_main())
