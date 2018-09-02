import sys

if __name__ == '__main__':
    from .svm_tool import main

    sys.exit(main(args=sys.argv[1:]))
