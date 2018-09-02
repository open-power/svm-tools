# SPDX-License-Identifier: BSD-3-Clause
import sys

if __name__ == '__main__':
    from .esm import main

    sys.exit(main(args=sys.argv[1:]))
