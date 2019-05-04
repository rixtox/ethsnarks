import hashlib
import math

from functools import partial
from multiprocessing import Pool, cpu_count
from ethsnarks.mimc import mimc_hash
from ethsnarks.field import FQ, SNARK_SCALAR_FIELD

def mimc_hash_partial(iv, data):
    return mimc_hash(data, iv)

def merkle_root(data, iv=0):
    if len(data) == 0:
        raise Exception('merkle_root: empty data')
    if len(data) == 1:
        return mimc_hash(data, iv)
    with Pool(cpu_count()) as p:
        nodes = p.map(partial(mimc_hash_partial, iv), [data[i*2:(i+1)*2] for i in range(0, len(data)//2)])
    if len(data)%2 == 1:
        nodes.append(data[-1])
    if len(nodes) == 1:
        return nodes[0]
    return merkle_root(nodes, mimc_hash([iv], iv))

def merkle_root_file(path):
    with open(path, 'rb') as f:
        data = []
        size = 0
        while True:
            block = f.read(31) # MiMC modulus is less than 254 bits
            if len(block) == 0:
                break
            size += len(block)
            data.append(int.from_bytes(block, 'big'))
        data.append(size)
        return merkle_root(data)
    raise Exception('failed to read file {}'.format(path))

def _main():
    import argparse
    parser = argparse.ArgumentParser("MerkleTree2")
    parser.add_argument('cmd', nargs='?', default='test')
    parser.add_argument('subargs', nargs='*')
    args = parser.parse_args()

    cmd = args.cmd

    if cmd == "raw":
        data = [int(x) for x in args.subargs]
        root = merkle_root(data)
        print(root)
    
    elif cmd == 'file':
        root = merkle_root_file(args.subargs[0])
        print(root.to_bytes(32, 'big').hex())

    else:
        parser.print_help()
        return 1

    return 0
        

if __name__ == "__main__":
    import sys
    sys.exit(_main())
