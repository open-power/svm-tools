#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# 
# Copyright 2019 IBM Corp.
#
"""
esm_digest
"""

import argparse
import binascii
import os
import platform
import subprocess
import sys
import tempfile

from Cryptodome.Hash import SHA512

import libfdt
from libfdt import QUIET_NOTFOUND

from .rtas_sha512 import rtas_sha512_txt

EIGHT_KB = 8192
FILE_CHUNK_SZ = 65536
debug_level = 0

#
# CLI
#

class AbspathAction(argparse.Action):  # pylint: disable=R0903
    """Custom action to ensure absolute paths to files."""

    def __call__(self, parser, namespace, value, option_string=None):
        value = os.path.abspath(value)
        setattr(namespace, self.dest, value)

def parse_cmd_line(args, description):
    """Parse  command line arguments."""
    formatter_class = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(prog="esm_digest",
        description=description, formatter_class=formatter_class,
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    create = "%(prog)s [-v] -f file -a args -i initramfs -k kernel"
    parser_create = subparsers.add_parser("create", usage=create)
    parser_create.add_argument("-v", action="count", default=0,
        dest="verbose")
    parser_create.add_argument("-f", dest="file", metavar="file",
        action=AbspathAction, required=True)
    parser_create.add_argument("-a", dest="bootargs", metavar="bootargs",
        required=True)
    parser_create.add_argument("-i", dest="initramfs", metavar="initramfs",
        action=AbspathAction, required=True)
    parser_create.add_argument("-k", dest="kernel", metavar="kernel",
        action=AbspathAction, required=True)
    parser_create.set_defaults(func=esmd_create)

    parsed_args = parser.parse_args(args)

    parsed_args.func(parsed_args)

#
# Utility functions.
#

def err(status, message):
    message = message + '\n'
    sys.stderr.write(message)
    sys.exit(status)

def dbg(level, message):
    if debug_level < level:
        return
    message = f'esm: debug{level}: ' + message + '\n'
    sys.stderr.write(message)
    
def dbg1(message):
    dbg(1, message)

def dbg2(message):
    dbg(2, message)

def file_write(path, contents):
    try:
        with open(path, mode='wb') as output:
            output.write(contents)
    except OSError as e:
        err(1, f'{path}: {e.strerror}')

def sha512_from_file(path):
    """Get sha512 of file contents.

    Args:
        path (str): Path to file.

    Returns:
        sha512 digest.
    """

    sha512 = SHA512.new()

    try:
        with open(path, mode='rb') as input:
            fbuf = input.read(FILE_CHUNK_SZ)
            while len(fbuf) > 0:
                sha512.update(fbuf)
                fbuf = input.read(FILE_CHUNK_SZ)
    except OSError as e:
        err(1, f'{path}: {e.strerror}')

    return sha512.digest()

def sha512_from_str(str):

    sha512 = SHA512.new()

    sha512.update(str)

    return sha512.digest()

def esmd_rtas_digest():

    # rtas_hex is the sha512 of the rtas.bin file.
    rtas_hex = binascii.unhexlify(rtas_sha512_txt.strip())

    return rtas_hex

def esmd_objcopy_run(infile, outfile):

    mach = platform.machine()
    objcopy_cmd = 'objcopy'

    if 'ppc64' not in mach:
        cross = os.environ['CROSS_COMPILE']
        if cross is None:
            err(1, f'{mach} needs cross tools. Please set CROSS_COMPILE')
        objcopy_cmd = cross + objcopy_cmd

    objcopy_args = [ objcopy_cmd,
            '-O',
            'binary',
            '-S',
            infile,
            outfile ]

    proc = subprocess.run(
            args = objcopy_args,
            universal_newlines = True,
            stdout = subprocess.PIPE)

    if proc.returncode is not 0:
        err(1, f'{objcopy_args} failed rc {proc.returncode}')

def esmd_kernel_digest(path):

    sha512 = SHA512.new()

    if not os.path.isfile(path):
        err(1, f'{path}: not found')

    with tempfile.NamedTemporaryFile() as temp:
        esmd_objcopy_run(path, temp.name)
        fbuf = temp.read(FILE_CHUNK_SZ)
        while len(fbuf) > 0:
            sha512.update(fbuf)
            fbuf = temp.read(FILE_CHUNK_SZ)
        kernel_size = os.path.getsize(temp.name)

    return sha512.digest(), kernel_size

def esmd_create_fdt(bootargs, initramfs, kernel):

    fdt = libfdt.Fdt.create_empty_tree(EIGHT_KB)
    fdt.setprop_str(0, 'compatible', 'ibm,esm')

    # Create the empty digests subnode.
    digests_offset = fdt.add_subnode(0, 'digests')

    fdt.setprop_str(digests_offset, 'algorithm', 'SHA512')

    rtas_digest = esmd_rtas_digest()
    fdt.setprop(digests_offset, 'rtas', rtas_digest)

    kernel_digest, kernel_size = esmd_kernel_digest(kernel)
    fdt.setprop(digests_offset, 'kernel', kernel_digest)
    fdt.setprop(digests_offset, 'kernel-size',
        (kernel_size).to_bytes(4,byteorder="big"))

    initramfs_digest = sha512_from_file(initramfs)
    fdt.setprop(digests_offset, 'initrd', initramfs_digest)

    bootargs_digest = sha512_from_str(bootargs.encode())
    fdt.setprop(digests_offset, 'bootargs', bootargs_digest)

    return fdt

def esmd_create(args):
    esmd_create_digest(args.file, args.bootargs, args.initramfs, args.kernel)

def esmd_create_digest(digest_file, bootargs, initramfs, kernel):

    fdt = esmd_create_fdt(bootargs, initramfs, kernel)
    if fdt is None:
    	err(1, '{} failed', 'esmd_create_fdt')

    fdt.pack()
    file_write(digest_file, fdt.as_bytearray())

def main(args=None):
    """The main routine."""
    parse_cmd_line(args, description="ESM Digest")
