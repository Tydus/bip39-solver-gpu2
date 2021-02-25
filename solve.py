#!/usr/bin/python3


import sys
import time
import numpy
import struct
import secrets
import pyopencl
import binascii

file_list = ["common", "ripemd", "sha2", "secp256k1_common", "secp256k1_scalar", "secp256k1_field", "secp256k1_group", "secp256k1_prec", "secp256k1", "address", "mnemonic_constants", "bruteforce"];

n = 65536

def main():

    ctx = pyopencl.create_some_context()
    queue = pyopencl.CommandQueue(ctx)
    mf = pyopencl.mem_flags

    target_pkhash = binascii.unhexlify(sys.argv[1])
    target_pkhash_g = pyopencl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=target_pkhash)
    target_pkhash_len = len(target_pkhash)

    kernel = pyopencl.Program(ctx, "\n".join(open('cl/%s.cl' % i, 'r').read() for i in file_list)).build()

    bruteforce = kernel.bruteforce
    bruteforce.set_scalar_arg_dtypes([None, None, numpy.uint8])

    print("Built kernel")

    while True:
        mnemonic_start = numpy.array(struct.unpack('!4Q', secrets.token_bytes(32)), dtype=numpy.uint64)
        mnemonic_start_g = pyopencl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=mnemonic_start)

        t0 = time.time()

        bruteforce(queue, [n], None, mnemonic_start_g, target_pkhash_g, target_pkhash_len).wait()

        print("%.2f Keys / s" % (n / (time.time() - t0)))


if __name__ == "__main__":
    main()
