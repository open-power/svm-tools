#!/usr/bin/env python3

import os
import sys
import yaml

if __name__ == '__main__':
    yml_files = ["svm_blob.yml"]
    cwd = os.getcwd()
    for i in yml_files:
        print(f"Parsing {i}")
        path = os.path.join(cwd, 'tests', 'cfg_files', i)
        with open(path, 'r') as stream:
            data_list = yaml.safe_load(stream)
            if not isinstance(data_list, list):
                sys.stderr.write(f'{path} invalid format')
                sys.exit(1)
            for entry in data_list:
                if len(entry) != 1:
                    sys.stderr.write(f'{entry} invalid format')
                    sys.exit(1)
                for key in entry:
                    print(f'key: {key}')
                    print (f'entry: {entry[key]}')
