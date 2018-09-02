#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# 
# Copyright 2019 IBM Corp.
#
"""
svm_tool
"""

import os
import argparse

from .version import __version__
from .esm import esm
from .svm import svm

class AbspathAction(argparse.Action):  # pylint: disable=R0903
    """Custom action to ensure absolute paths to files."""

    def __call__(self, parser, namespace, value, option_string=None):
        value = os.path.abspath(value)
        setattr(namespace, self.dest, value)

def parse_cmd_line(args, description):
    """Parse  command line arguments."""
    formatter_class = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(prog="svm_tool",
        description=description, formatter_class=formatter_class,
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    subparsers = parser.add_subparsers(dest="command")
    parser.set_defaults(func=handle_svm_args)

    svm = "%(prog)s ..."
    parser_svm = subparsers.add_parser("svm", help="svm help", usage=svm)
    parser_svm.set_defaults(func=call_svm)

    esm = "%(prog)s ..."
    parser_esm = subparsers.add_parser("esm", help="esm help", usage=esm)
    parser_esm.set_defaults(func=call_esm)

    parsed_args, unknown_args = parser.parse_known_args(args)

    parsed_args.func(parsed_args, unknown_args)

def call_svm(args, unknown_args):
    svm.main(unknown_args)

def call_esm(args, unknown_args):
    esm.main(unknown_args)

def handle_svm_args(args, unknown_args):
    print(f"In function {args.func} args {unknown_args}")

def main(args=None):
    """The main routine."""
    parse_cmd_line(args, description="SVM Tool")
