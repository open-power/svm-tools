#!/usr/bin/python3

import lzma
import json

with lzma.open('tests/attachments/guest/file-1.dump.xz', 'w') as dump_file:
    json_str = json.dumps(json.loads(
        open("tests/attachments/guest/file-1.json","r").read()), ensure_ascii=False)
    dump_file.write(
            json_str.encode(encoding='utf-8', errors='strict'))
    assert True

with lzma.open('tests/attachments/guest/file-2.dump.xz', 'w') as dump_file:
    json_str = json.dumps(json.loads(
        open("tests/attachments/guest/file-2.json","r").read()), ensure_ascii=False)
    dump_file.write(
            json_str.encode(encoding='utf-8', errors='strict'))
    assert True

