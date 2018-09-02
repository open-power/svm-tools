#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
svm
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

DFLT_PEF_CPIO_PATH = 'opt/ibm/pef'

class AbspathAction(argparse.Action):  # pylint: disable=R0903
    """Custom action to ensure absolute paths to files."""

    def __call__(self, parser, namespace, value, option_string=None):
        value = os.path.abspath(value)
        setattr(namespace, self.dest, value)

def parse_cmd_line(args, description):
    """Parse  command line arguments."""
    formatter_class = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(prog="svm",
        description=description, formatter_class=formatter_class
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    add = "%(prog)s -i initramfs -b esm -f file"
    parser_add = subparsers.add_parser("add", usage=add)
    parser_add.add_argument("-i", dest="initramfs", metavar="initramfs",
        required=True)
    parser_add.add_argument("-b", dest="blob", metavar="blob",
        required=True)
    parser_add.add_argument("-f", dest="file", metavar="file",
        required=True)
    parser_add.set_defaults(func=svm_add)

    make = "%(prog)s -y config"
    parser_make = subparsers.add_parser("make", usage=make)
    parser_make.add_argument("-y", dest="config", metavar="config",
        required=True)
    parser_make.set_defaults(func=svm_make)

    parsed_args = parser.parse_args(args)

    parsed_args.func(parsed_args)

def svm_add(args):
    with tempfile.TemporaryDirectory() as tmpdir:
        cpio_dir = os.path.join(tmpdir, 'cpio_dir')
        cpio_path = os.path.join(cpio_dir, DFLT_PEF_CPIO_PATH)
        os.makedirs(cpio_path)
        shutil.copy(args.blob, cpio_path)

        cpio_file = os.path.join(tmpdir, 'esm_blob.cpio')
        svm_create_cpio(cpio_dir, cpio_file)
        svm_cat_files([cpio_file, args.initramfs], args.file)


def svm_make(args):
    print(f"In function {args.func} args {args}")

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


def svm_cat_files(file_list, new_file):

    with open(new_file, 'wb') as outfile:
        for file in file_list:
            with open(file, 'rb') as infile:
                outfile.write(infile.read())


def svm_create_cpio(cpio_dir, cpio_file):

    args_find = ['find', '.', '-print0']
    args_cpio = ['cpio', '--null', '--create', '--quiet',
            '--format=newc', '-F', cpio_file ]

    process_find = subprocess.Popen(args_find, stdout=subprocess.PIPE,
                                    shell=False, cwd=cpio_dir)
    process_cpio = subprocess.Popen(args_cpio, stdin=process_find.stdout,
                                  stdout=subprocess.PIPE, shell=False,
                                  cwd=cpio_dir)

    # Allow process_find to receive a SIGPIPE if process_cpio exits.
    process_find.stdout.close()

    stdout, stderr = process_cpio.communicate()

    if process_cpio.returncode is not 0:
        err(1, f'svm_create_esmb_cpio: failed {stderr} rc {process_cpio.returncode}')


def main(args=None):
    """The main routine."""
    parse_cmd_line(args, description="svm")

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
