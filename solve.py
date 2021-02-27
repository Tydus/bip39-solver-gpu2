#!/usr/bin/python3

import sys
import time
import numpy
import struct
import getpass
import secrets
import pyopencl
import binascii

file_list = ["common", "ripemd", "sha2", "secp256k1_common", "secp256k1_scalar", "secp256k1_field", "secp256k1_group", "secp256k1_prec", "secp256k1", "address", "mnemonic_constants", "bruteforce"];

class Bruteforce(object):
    def __init__(self, worksize=65536, password=''):
        self.ctx = pyopencl.create_some_context()
        self.queue = pyopencl.CommandQueue(self.ctx)

        self.worksize = worksize
        mf = pyopencl.mem_flags

        kernel = pyopencl.Program(self.ctx, "\n".join(open('cl/%s.cl' % i, 'r').read() for i in file_list)).build()
        print("Built kernel", file=sys.stderr)

        assert len(password) < 116
        salt = ('mnemonic' + password + '\0\0\0\1').encode('ascii')
        self.salt_g = pyopencl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=salt)
        self.salt_len = len(salt)

        self.bruteforce = kernel.bruteforce
        self.bruteforce.set_scalar_arg_dtypes([None, None, numpy.uint8, None, numpy.uint8])


    def do_work(self, target_pkhash, iter=99999999999):
        mf = pyopencl.mem_flags

        target_pkhash_g = pyopencl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=target_pkhash)
        target_pkhash_len = len(target_pkhash)
        
        for _ in range(iter):
            t0 = time.time()

            mnemonic_start = numpy.array(struct.unpack('!4Q', secrets.token_bytes(32)), dtype=numpy.uint64)
            mnemonic_start_g = pyopencl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=mnemonic_start)

            self.bruteforce(
                self.queue,
                [self.worksize],
                None,
                mnemonic_start_g,
                target_pkhash_g, target_pkhash_len,
                self.salt_g, self.salt_len,
            ).wait()

            print("%.2f Keys / s" % (self.worksize / (time.time() - t0)), file=sys.stderr)

def main():
    worksize = 65536
    if len(sys.argv) == 3: worksize = int(sys.argv[2])

    password = getpass.getpass()
    password2 = getpass.getpass('Password again: ')
    assert password == password2, "Password mismatch"

    bruteforce = Bruteforce(worksize, password=password)

    bruteforce.do_work(binascii.unhexlify('0000'), iter=3)
    bruteforce.do_work(binascii.unhexlify('ffff'), iter=3)

    print("====== Sanity check finished ======")

    bruteforce.do_work(binascii.unhexlify(sys.argv[1]))


if __name__ == "__main__":
    main()
