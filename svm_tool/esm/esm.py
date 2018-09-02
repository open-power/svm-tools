#! /usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import getpass
import os
import re
import sys
import tempfile

from Cryptodome import Random
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
import libfdt
from libfdt import QUIET_NOTFOUND
import yaml

from ..esm_digest.esm_digest import esmd_create_digest

EIGHT_KB = 8192
debug_level = 0
dryrun = False

def main(args=None):
    parser = argparse.ArgumentParser(prog="esm")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    attach = "%(prog)s [-nv] [-c comment] [-r name] -b blob -f file -s seckey"
    parser_attach = subparsers.add_parser("attach", usage=attach)
    parser_attach.add_argument("-n", action="store_true", dest="dryrun")
    parser_attach.add_argument("-v", action="count", default=0,
        dest="verbose")
    parser_attach.add_argument("-c", default="", dest="comment",
        metavar="comment")
    parser_attach.add_argument("-r", default="", dest="name", metavar="name")
    parser_attach.add_argument("-b", dest="blob", metavar="blob",
        required=True)
    parser_attach.add_argument("-f", dest="file", metavar="file",
        required=True)
    parser_attach.add_argument("-s", dest="seckey", metavar="seckey",
        required=True)
    parser_attach.set_defaults(func=esm_attach)

    authorize = "%(prog)s [-nv] [-c comment] -b blob -p pubkey -s seckey"
    parser_authorize = subparsers.add_parser("authorize", usage=authorize)
    parser_authorize.add_argument("-n", action="store_true", dest="dryrun")
    parser_authorize.add_argument("-v", action="count", default=0,
        dest="verbose")
    parser_authorize.add_argument("-c", default="", dest="comment",
        metavar="comment")
    parser_authorize.add_argument("-b", dest="blob", metavar="blob",
        required=True)
    parser_authorize.add_argument("-p", dest="pubkey", metavar="pubkey",
        required=True)
    parser_authorize.add_argument("-s", dest="seckey", metavar="seckey",
        required=True)
    parser_authorize.set_defaults(func=esm_authorize)

    create = "%(prog)s [-nv] [-c comment] -b blob -p pubkey"
    parser_create = subparsers.add_parser("create", usage=create)
    parser_create.add_argument("-n", action="store_true", dest="dryrun")
    parser_create.add_argument("-v", action="count", default=0, dest="verbose")
    parser_create.add_argument("-c", default="", dest="comment",
        metavar="comment")
    parser_create.add_argument("-b", dest="blob", metavar="blob",
        required=True)
    parser_create.add_argument("-p", dest="pubkey", metavar="pubkey",
        required=True)
    parser_create.set_defaults(func=esm_create)

    detach = "%(prog)s [-nv] -b blob -f file"
    parser_detach = subparsers.add_parser("detach", usage=detach)
    parser_detach.add_argument("-n", action="store_true", dest="dryrun")
    parser_detach.add_argument("-v", action="count", default=0,
        dest="verbose")
    parser_detach.add_argument("-b", dest="blob", metavar="blob",
        required=True)
    parser_detach.add_argument("-f", dest="file", metavar="file",
        required=True)
    parser_detach.set_defaults(func=esm_detach)

    digest = "%(prog)s [-nv] [-c comment] -b blob -s seckey -a args -i initramfs -k kernel"
    parser_digest = subparsers.add_parser("digest", usage=digest)
    parser_digest.add_argument("-n", action="store_true", dest="dryrun")
    parser_digest.add_argument("-v", action="count", default=0,
        dest="verbose")
    parser_digest.add_argument("-c", default="", dest="comment",
        metavar="comment")
    parser_digest.add_argument("-b", dest="blob", metavar="blob",
        required=True)
    parser_digest.add_argument("-s", dest="seckey", metavar="seckey",
        required=True)
    parser_digest.add_argument("-a", dest="bootargs", metavar="bootargs",
        required=True)
    parser_digest.add_argument("-i", dest="initramfs", metavar="initramfs",
        required=True)
    parser_digest.add_argument("-k", dest="kernel", metavar="kernel",
        required=True)
    parser_digest.set_defaults(func=esm_digest)

    display = "%(prog)s [-v] -b blob"
    parser_display = subparsers.add_parser("display", usage=display)
    parser_display.add_argument("-v", action="count", default=0,
        dest="verbose")
    parser_display.add_argument("-b", dest="blob", metavar="blob",
        required=True)
    parser_display.set_defaults(func=esm_display)

    extract = "%(prog)s [-nv] [-c comment] -b blob -f file -s seckey"
    parser_extract = subparsers.add_parser("extract", usage=extract)
    parser_extract.add_argument("-n", action="store_true", dest="dryrun")
    parser_extract.add_argument("-v", action="count", default=0,
        dest="verbose")
    parser_extract.add_argument("-b", dest="blob", metavar="blob",
        required=True)
    parser_extract.add_argument("-f", dest="file", metavar="file",
        required=True)
    parser_extract.add_argument("-s", dest="seckey", metavar="seckey",
        required=True)
    parser_extract.set_defaults(func=esm_extract)

    generate = "%(prog)s [-nv] -p pubkey -s seckey"
    parser_generate = subparsers.add_parser("generate", usage=generate)
    parser_generate.add_argument("-n", action="store_true", dest="dryrun")
    parser_generate.add_argument("-v", action="count", default=0,
        dest="verbose")
    parser_generate.add_argument("-p", dest="pubkey", metavar="pubkey",
        required=True)
    parser_generate.add_argument("-s", dest="seckey", metavar="seckey",
        required=True)
    parser_generate.set_defaults(func=esm_generate)

    make = "%(prog)s [-nv] -b blob -y config"
    parser_make = subparsers.add_parser("make", usage=make)
    parser_make.add_argument("-n", action="store_true", dest="dryrun")
    parser_make.add_argument("-v", action="count", default=0,
        dest="verbose")
    parser_make.add_argument("-b", dest="blob", metavar="blob",
        required=True)
    parser_make.add_argument("-y", dest="config", metavar="config",
        required=True)
    parser_make.set_defaults(func=esm_make)

    revoke = "%(prog)s [-nv] [-c comment] -b blob -p pubkey"
    parser_revoke = subparsers.add_parser("revoke", usage=revoke)
    parser_revoke.add_argument("-n", action="store_true", dest="dryrun")
    parser_revoke.add_argument("-v", action="count", default=0, dest="verbose")
    parser_revoke.add_argument("-b", dest="blob", metavar="blob",
        required=True, type=str)
    parser_revoke.add_argument("-p", dest="pubkey", metavar="pubkey",
        required=True, type=str)
    parser_revoke.set_defaults(func=esm_revoke)

    args = parser.parse_args(args)

    global debug_level
    debug_level = args.verbose
    if hasattr(args, 'dryrun'):
        global dryrun
        dryrun = args.dryrun

    args.func(args)

    return 0

#
# Utility functions.
#

def err(status, fmt, *args):
    message = 'esm: ' + fmt.format(*args) + '\n'
    sys.stderr.write(message)
    sys.exit(status)

def dbg(level, fmt, *args):
    if debug_level < level:
        return
    message = 'esm: debug{}: '.format(level) + fmt.format(*args) + '\n'
    sys.stderr.write(message)
    
def dbg1(fmt, *args):
    dbg(1, fmt, *args)

def dbg2(fmt, *args):
    dbg(2, fmt, *args)

def file_atomic_replace(path, new_contents):
    # rename(2) is atomic if the new path is on the same file system,
    # so use path's directory as a working directory.
    directory = os.path.dirname(path)
    tmp = tempfile.NamedTemporaryFile(delete=False, dir=directory)
    dbg1('writing updated contents to {}', tmp.name)
    try:
        tmp.write(new_contents)
    except OSError as e:
        err(1, '{}: {}', tmp.name, e.strerror)
    dbg1('replacing {} with updated file', path)
    try:
        os.replace(tmp.name, path)
    except OSError as e:
        err(1, 'rename {} to {}: {}', tmp.name, path)

def file_read(path):
    try:
        file_contents = open(path, 'rb').read()
    except OSError as e:
        err(1, '{}: {}', path, e.strerror)
    return file_contents

def file_write(path, contents):
    try:
        with open(path, mode='wb') as output:
            output.write(contents)
    except OSError as e:
        err(1, '{}: {}', path, e.strerror)

def read_passphrase(prompt):
    try:
        passphrase = getpass.getpass(prompt=prompt)
    except EOFError as e:
        sys.stderr.write('\n')	# prettier
        pass
    except KeyboardInterrupt:
        sys.stderr.write('\n')	# prettier
        raise
    return passphrase

# Decrypt the master symkey with the private key in seckey_path.
# Returns the decrypted binary key to the caller.
def extract_symkey(fdt, seckey_path, password=None):
    # Unlock the secret key.
    seckey_contents = file_read(seckey_path)
    prompt = "Enter passphrase for key '{}':".format(seckey_path)
    passphrase = ""

    if password is None:
        passphrase = read_passphrase(prompt)
    else:
        passphrase = password

    try:
        rsa_seckey = RSA.import_key(seckey_contents, passphrase=passphrase)
    except ValueError as e:
        err(1, '{}: {}', seckey_path, *e.args)

    # Prepare a pubkey hash from our secret key.
    rsa_pubkey = rsa_seckey.publickey()
    # XXX The exported key sometimes seems to be missing a trailing
    # newline.  Unsure if this is actually a bug, but the hashes won't
    # match without it.
    rsa_pubkey_pem = rsa_pubkey.export_key()
    if rsa_pubkey_pem[-1] != b'\n':
        rsa_pubkey_pem += b'\n'
    sha256 = SHA256.new()
    sha256.update(bytearray(rsa_pubkey_pem))
    user_pubkey_hash = sha256.digest()
    dbg2('{} (pubkey): SHA256: {}', seckey_path, user_pubkey_hash.hex())

    # Find a matching lockbox.
    lockboxes_offset = fdt.path_offset('/lockboxes')
    offset = fdt.first_subnode(lockboxes_offset)
    fingerprint_offset = 0
    while offset >= 0:
        fingerprint_offset = fdt.subnode_offset(offset, 'pubkey-fingerprint')
        lockbox_pubkey_hash = fdt.getprop(fingerprint_offset, 'hash')
        dbg2('{}: SHA256: {}', fdt.get_name(offset), lockbox_pubkey_hash.hex())
        if user_pubkey_hash == lockbox_pubkey_hash:
            break
        offset = fdt.next_subnode(offset, QUIET_NOTFOUND)

    if offset < 0:
        err(1, '{}: Not an authorized key', seckey_path)

    # Decrypt the master symkey.
    encrypted_symkey = fdt.getprop(offset, 'encrypted-symkey')
    rsa_cipher = PKCS1_OAEP.new(rsa_seckey, hashAlgo=SHA256)
    symkey = rsa_cipher.decrypt(encrypted_symkey)

    return symkey

#
# Input validation.
#

# Check whether the name meets the Devicetree Specification criteria.
def node_name_is_valid(name):
    regex = re.compile('^[A-Za-z][0-9A-Za-z,._+-]{0,30}\Z')
    return regex.match(name) != None

def validate_esm(fdt, path):
    try:
        valid_esm(fdt)
    except Exception as e:
        err(1, '{} is invalid: {}', path, *e.args)

def valid_esm(fdt):
    root_properties = { "compatible" : valid_compatible }
    root_nodes = {
        "lockboxes" : valid_lockboxes,
        "digest" : valid_digests,
        "file" : valid_files
    }
    nodes_found = set()
    properties_found = set()
    root_offset = 0

    prop_offset = fdt.first_property_offset(root_offset, QUIET_NOTFOUND)
    while prop_offset >= 0:
        prop = fdt.get_property_by_offset(prop_offset)
        if prop.name not in root_properties:
            raise Exception('unexpected property: {}'.format(prop.name))
        properties_found.add(prop.name)
        prop_value = fdt.getprop(root_offset, prop.name)
        root_properties[prop.name](prop_value)
        prop_offset = fdt.next_property_offset(prop_offset, QUIET_NOTFOUND)
    for prop_name in root_properties:
        if prop_name not in properties_found:
            raise Exception('missing property: {}', prop_name)

    subnode_offset = fdt.first_subnode(root_offset, QUIET_NOTFOUND)
    while subnode_offset >= 0:
        subnode_name = fdt.get_name(subnode_offset)
        if subnode_name not in root_nodes:
            raise Exception('unexpected node: {}'.format(subnode_name))
        nodes_found.add(subnode_name)
        root_nodes[subnode_name](fdt, subnode_offset)
        subnode_offset = fdt.next_subnode(subnode_offset, QUIET_NOTFOUND)
    for node in root_nodes:
        if node not in nodes_found:
            raise Exception('missing node: {}', node)

def valid_compatible(bytes):
    string = bytes.as_str()
    if string != 'ibm,esm':
        raise Exception('compatible is invalid: {}'.format(string))

def valid_lockboxes(fdt, offset):
    origin_lockbox_found = False

    lockbox_offset = fdt.first_subnode(offset)
    while lockbox_offset >= 0:
        lockbox_name = fdt.get_name(lockbox_offset)
        if lockbox_name == 'origin-lockbox':
            origin_lockbox_found = True
        else:
            valid_lockbox_name(lockbox_name)
        valid_lockbox(fdt, lockbox_offset)
        lockbox_offset = fdt.next_subnode(lockbox_offset, QUIET_NOTFOUND)

    if not origin_lockbox_found:
        raise Exception('missing node: origin-lockbox')

def valid_lockbox_name(name):
    exc = Exception('lockbox name is invalid: {}'.format(name))

    tokens = name.split('-')
    if len(tokens) != 2:
        raise exc
    if tokens[0] != 'lockbox':
        raise exc
    try:
        num = int(tokens[1])
    except Exception as e:
        raise exc
    if num < 1:
        raise exc

def valid_lockbox(fdt, offset):
    lockbox_nodes = { 'pubkey-fingerprint' : valid_pubkey_fingerprint }
    lockbox_properties = { 'untrusted-comment', 'encrypted-symkey' }
    nodes_found = set()
    properties_found = set()
    
    prop_offset = fdt.first_property_offset(offset, QUIET_NOTFOUND)
    while prop_offset >= 0:
        prop = fdt.get_property_by_offset(prop_offset)
        if prop.name not in lockbox_properties:
            raise Exception('unexpected property: {}'.format(prop.name))
        properties_found.add(prop.name)
        prop_offset = fdt.next_property_offset(prop_offset, QUIET_NOTFOUND)
    for prop_name in lockbox_properties:
        if prop_name not in properties_found:
            raise Exception('missing property: {}'.format(prop_name))

    subnode_offset = fdt.first_subnode(offset, QUIET_NOTFOUND)
    while subnode_offset >= 0:
        subnode_name = fdt.get_name(subnode_offset)
        if subnode_name not in lockbox_nodes:
            err(1, '{}: unexpected node: {}', subnode_name)
        nodes_found.add(subnode_name)
        lockbox_nodes[subnode_name](fdt, subnode_offset)
        subnode_offset = fdt.next_subnode(subnode_offset, QUIET_NOTFOUND)
    for node in lockbox_nodes:
        if node not in nodes_found:
            raise Exception('missing node: {}'.format(node))

def valid_pubkey_fingerprint(fdt, offset):
    pubkey_fingerprint_properties = {
        'algorithm' : valid_pubkey_algorithm,
        'hash' : valid_hash
    }
    properties_found = set()

    prop_offset = fdt.first_property_offset(offset, QUIET_NOTFOUND)
    while prop_offset >= 0:
        prop = fdt.get_property_by_offset(prop_offset)
        if prop.name not in pubkey_fingerprint_properties:
            raise Exception('unexpected property: {}'.format(prop.name))
        properties_found.add(prop.name)
        prop_value = fdt.getprop(offset, prop.name)
        pubkey_fingerprint_properties[prop.name](prop_value)
        prop_offset = fdt.next_property_offset(prop_offset, QUIET_NOTFOUND)
    for prop_name in pubkey_fingerprint_properties:
        if prop_name not in properties_found:
            raise Exception('missing property: {}'.format(prop_name))

def valid_pubkey_algorithm(bytes):
    string = bytes.as_str()
    if string != 'SHA256':
        raise Exception('unsupported hash algorithm: {}'.format(string))

def valid_comment(bytes):
    string = bytes.as_str()
    if '\n' in string:
        raise Exception('comment is invalid: {}'.format(string))

def valid_hash(bytes):
    pass

def valid_digests(fdt, offset):
    pass

def valid_files(fdt, offset):
    file_offset = fdt.first_subnode(offset, QUIET_NOTFOUND)
    while file_offset >= 0:
        file_name = fdt.get_name(file_offset)
        if not node_name_is_valid(file_name):
            raise Exception('file name is invalid: {}'.format(file_name))
        valid_file(fdt, file_offset)
        file_offset = fdt.next_subnode(file_offset, QUIET_NOTFOUND)

def valid_file(fdt, offset):
    file_properties = {
        'algorithm': valid_file_algorithm,
        'ciphertext': valid_ciphertext,
        'iv': valid_iv,
        'mac': valid_mac,
        'untrusted-comment': valid_comment
    }
    properties_found = set()
    
    prop_offset = fdt.first_property_offset(offset, QUIET_NOTFOUND)
    while prop_offset >= 0:
        prop = fdt.get_property_by_offset(prop_offset)
        if prop.name not in file_properties:
            raise Exception('unexpected property: {}'.format(prop.name))
        properties_found.add(prop.name)
        prop_offset = fdt.next_property_offset(prop_offset, QUIET_NOTFOUND)
    for prop_name in file_properties:
        if prop_name not in properties_found:
            raise Exception('missing property: {}'.format(prop_name))

def valid_file_algorithm(bytes):
    string = bytes.as_str()
    if string != 'AES256-GCM':
        raise Exception('unsupported symmetric algorithm: {}'.format(string))

def valid_ciphertext(bytes):
    pass

def valid_iv(bytes):
    pass

def valid_mac(bytes):
    pass

#
# Subcommands
#

def esm_create(args):
    create(args.blob, args.pubkey, args.comment)

def create(blob, pubkey, comment):
    # New FDT with a "compatible" property.
    fdt = libfdt.Fdt.create_empty_tree(len(comment) + EIGHT_KB)
    fdt.setprop_str(0, 'compatible', 'ibm,esm')

    # Create the empty file subnode.
    fdt.add_subnode(0, 'file')

    # Create the empty digest subnode.
    fdt.add_subnode(0, 'digest')

    # Create the lockboxes subnode.
    lockbox_offset = fdt.add_subnode(0, 'lockboxes')

    # Create the master lockbox.
    origin_offset = fdt.add_subnode(lockbox_offset, 'origin-lockbox')

    # Add the comment.
    if '\n' in comment:
        err(1, 'comment cannot contain a newline')
    fdt.setprop_str(origin_offset, "untrusted-comment", comment)

    # Prepare the public key cipher.
    pubkey_contents = file_read(pubkey)
    try:
        rsa_pubkey = RSA.importKey(pubkey_contents)
    except ValueError as e:
        err(1, '{}: {}', pubkey, *e.args)
    if (rsa_pubkey.has_private()):
        err(1, '{}: Is a private key', pubkey)
    rsa_cipher = PKCS1_OAEP.new(rsa_pubkey, hashAlgo=SHA256)

    # Create, encrypt, and store the 256-bit symkey.
    random_source = Random.new()
    symkey = random_source.read(32)
    encrypted_symkey = rsa_cipher.encrypt(symkey)
    fdt.setprop(origin_offset, 'encrypted-symkey', encrypted_symkey)

    # Add the pubkey fingerprint.
    fingerprint_offset = fdt.add_subnode(origin_offset, 'pubkey-fingerprint')
    fdt.setprop_str(fingerprint_offset, 'algorithm', 'SHA256')
    sha256 = SHA256.new()
    sha256.update(pubkey_contents)
    pubkey_hash = sha256.digest()
    dbg2('{}: SHA256: {}'.format(pubkey, pubkey_hash.hex()))
    fdt.setprop(fingerprint_offset, 'hash', pubkey_hash)

    # Write the new blob.
    fdt.pack()
    if not dryrun:
        file_write(blob, fdt.as_bytearray())

def esm_authorize(args):
    authorize(args.blob, args.pubkey, args.comment, args.seckey, None)

def authorize(blob, pubkey, comment, seckey, password=None):
    blob_contents = file_read(blob)
    fdt = libfdt.Fdt(blob_contents)
    validate_esm(fdt, blob)

    # Prepare the pubkey hash.
    pubkey_contents = file_read(pubkey)
    sha256 = SHA256.new()
    sha256.update(pubkey_contents)
    pubkey_hash = sha256.digest()
    dbg2('{}: SHA256: {}', pubkey, pubkey_hash.hex())

    # Find the largest lockbox number.
    parent_offset = fdt.path_offset('/lockboxes')
    offset = fdt.first_subnode(parent_offset)
    max_lockbox_num = -1
    while offset > 0:
        lockbox_name = fdt.get_name(offset)
        fingerprint_offset = fdt.subnode_offset(offset, 'pubkey-fingerprint')
        lockbox_pubkey_hash = fdt.getprop(fingerprint_offset, 'hash')
        dbg2('{}: SHA256: {}', lockbox_name, lockbox_pubkey_hash.hex())
        if pubkey_hash == lockbox_pubkey_hash:
            break
        lockbox_num = -1
        if lockbox_name == 'origin-lockbox':
            lockbox_num = 0
        else:
            tokens = lockbox_name.split('-')
            lockbox_num = int(tokens[1])
        max_lockbox_num = max(max_lockbox_num, lockbox_num)
        offset = fdt.next_subnode(offset, libfdt.QUIET_NOTFOUND)

    # If the key is already authorized there's nothing more to do.
    if offset > 0:
        err(1, '{}: already authorized', pubkey)

    # Need more room for new lockbox.
    fdt.resize(fdt.totalsize() + len(comment) + EIGHT_KB)

    # Create a new lockbox and add the comment, if any.
    lockbox_name = "lockbox-{}".format(max_lockbox_num + 1)
    dbg1('{}: making new lockbox', lockbox_name)
    lockbox_offset = fdt.add_subnode(parent_offset, lockbox_name)

    if '\n' in comment:
        err(1, 'comment cannot contain a newline')
    fdt.setprop_str(lockbox_offset, "untrusted-comment", comment)

    # Add the pubkey fingerprint.
    fingerprint_offset = fdt.add_subnode(lockbox_offset, 'pubkey-fingerprint')
    fdt.setprop_str(fingerprint_offset, 'algorithm', 'SHA256')
    fdt.setprop(fingerprint_offset, 'hash', pubkey_hash)

    # Prepare the public key cipher.
    try:
        rsa_pubkey = RSA.importKey(pubkey_contents)
    except ValueError as e:
        err(1, '{}: {}', pubkey, *e.args)
    rsa_cipher = PKCS1_OAEP.new(rsa_pubkey, hashAlgo=SHA256)

    # Add the encrypted symkey.
    symkey = extract_symkey(fdt, seckey, password)
    encrypted_symkey = rsa_cipher.encrypt(symkey)
    fdt.setprop(lockbox_offset, 'encrypted-symkey', encrypted_symkey)

    # Write out the updated blob.
    fdt.pack()
    if not dryrun:
        file_atomic_replace(blob, fdt.as_bytearray())

def esm_revoke(args):
    header_contents = file_read(args.blob)
    fdt = libfdt.Fdt(header_contents)
    validate_esm(fdt, args.blob)

    # Prepare the pubkey hash.
    pubkey_contents = open(args.pubkey, 'rb').read()
    sha256 = SHA256.new()
    sha256.update(pubkey_contents)
    pubkey_hash = sha256.digest()
    dbg2('{}: SHA256: {}', args.pubkey, pubkey_hash.hex())

    # Find a matching lockbox.
    parent_offset = fdt.path_offset('/lockboxes')
    offset = fdt.first_subnode(parent_offset)
    while offset > 0:
        lockbox_name = fdt.get_name(offset)
        fingerprint_path = '/lockboxes/' + lockbox_name + '/pubkey-fingerprint'
        fingerprint_offset = fdt.path_offset(fingerprint_path)
        lockbox_pubkey_hash = fdt.getprop(fingerprint_offset, 'hash')
        dbg2('{}: SHA256: {}', lockbox_name, lockbox_pubkey_hash.hex())
        if pubkey_hash == lockbox_pubkey_hash:
            break
        offset = fdt.next_subnode(offset, libfdt.QUIET_NOTFOUND)

    # Not found.
    if offset <= 0:
        err(1, '{}: cannot revoke unauthorized key', args.pubkey)

    dbg1('{}: matching hash found', lockbox_name)

    # The origin key is a special case.  We can never revoke it.
    if lockbox_name == "origin-lockbox":
        err(1, '{}: cannot revoke origin key', args.pubkey)

    # Remove the lockbox.
    dbg1('{}: deleting lockbox', lockbox_name)
    fdt.del_node(offset)

    # Write out the updated blob.
    fdt.pack()
    if not dryrun:
        file_atomic_replace(args.blob, fdt.as_bytearray())

def esm_attach(args):
    attach(args.blob, args.file, args.comment, args.name, args.seckey, None)

def file_fdt_get(fdt, create=False):

    file_fdt = None
    file_path = '/file'
    file_offset = fdt.path_offset(file_path, QUIET_NOTFOUND)

    if file_offset == -libfdt.NOTFOUND:
        err(1, f'{file_path} not found')

    files_prop = fdt.getprop(file_offset, 'files-fdt', QUIET_NOTFOUND)
    if files_prop == -libfdt.NOTFOUND:
        # New File FDT with a "compatible" property.
        file_fdt = libfdt.Fdt.create_empty_tree(EIGHT_KB)
        file_fdt.setprop_str(0, 'compatible', 'ibm,esm-file')
        file_fdt.add_subnode(0, 'files')
        file_fdt.pack()
        fdt.resize(file_fdt.totalsize() + EIGHT_KB)
        fdt.setprop(file_offset, 'files-fdt', bytes(file_fdt.as_bytearray()))
    else:
        file_fdt = libfdt.Fdt(files_prop)

    return file_fdt

def file_fdt_put(fdt, file_fdt):
    file_fdt.pack()
    fdt.resize(file_fdt.totalsize() + EIGHT_KB)
    file_path = '/file'
    file_offset = fdt.path_offset(file_path, QUIET_NOTFOUND)
    if file_offset == -libfdt.NOTFOUND:
        err(1, f'{file_path} not found')
    fdt.setprop(file_offset, 'files-fdt', bytes(file_fdt.as_bytearray()))

def attach(blob, file, comment, name, seckey, password=None):
    blob_contents = file_read(blob)
    fdt = libfdt.Fdt(blob_contents)
    validate_esm(fdt, blob)

    file_fdt = file_fdt_get(fdt, create=True)

    # Load the attachment.
    file_contents = file_read(file)

    # Make room for the attachment, its comment, and other properties.
    file_fdt.resize(file_fdt.totalsize() + len(comment))
    file_fdt.resize(file_fdt.totalsize() + len(file_contents) + EIGHT_KB)

    # Check that the attachment name is acceptable.
    if name == '':
        node_name = os.path.basename(file)
    else:
        node_name = name
    if not node_name_is_valid(node_name):
        err(1, '{}: file name is invalid: {}', file, node_name)

    # Create a subnode in /file for the attachment.
    parent_offset = file_fdt.path_offset('/files')
    file_offset = file_fdt.add_subnode(parent_offset, node_name)
    file_fdt.setprop_str(file_offset, 'algorithm', 'AES256-GCM')

    if '\n' in comment:
        err(1, 'comment cannot contain a newline')
    file_fdt.setprop_str(file_offset, 'untrusted-comment', comment)

    # Encrypt and store the attachment in the subnode.
    symkey = extract_symkey(fdt, seckey, password)
    aes_cipher = AES.new(symkey, AES.MODE_GCM)
    ciphertext, mac = aes_cipher.encrypt_and_digest(file_contents)
    file_fdt.setprop(file_offset, 'ciphertext', ciphertext)
    file_fdt.setprop(file_offset, 'iv', aes_cipher.nonce)
    file_fdt.setprop(file_offset, 'mac', mac)

    # Update files-fdt
    file_fdt_put(fdt, file_fdt)

    # Write out the updated blob.
    fdt.pack()
    if not dryrun:
        file_atomic_replace(blob, fdt.as_bytearray())

def attach_digests(blob, file, comment, name, seckey, password=None):
    blob_contents = file_read(blob)
    fdt = libfdt.Fdt(blob_contents)
    validate_esm(fdt, blob)

    # Load the attachment.
    file_contents = file_read(file)

    # Make room for the attachment, its comment, and other properties.
    fdt.resize(fdt.totalsize() + len(comment))
    fdt.resize(fdt.totalsize() + len(file_contents) + EIGHT_KB)

    # Check that the attachment name is acceptable.
    if name == '':
        node_name = os.path.basename(file)
    else:
        node_name = name
    if not node_name_is_valid(node_name):
        err(1, '{}: file name is invalid: {}', file, node_name)

    # Create a subnode in /digest for the attachment.
    parent_offset = fdt.path_offset('/digest')
    file_offset = fdt.add_subnode(parent_offset, node_name)
    fdt.setprop_str(file_offset, 'algorithm', 'AES256-GCM')

    if '\n' in comment:
        err(1, 'comment cannot contain a newline')
    fdt.setprop_str(file_offset, 'untrusted-comment', comment)

    # Encrypt and store the attachment in the subnode.
    symkey = extract_symkey(fdt, seckey, password)
    aes_cipher = AES.new(symkey, AES.MODE_GCM)
    ciphertext, mac = aes_cipher.encrypt_and_digest(file_contents)
    fdt.setprop(file_offset, 'ciphertext', ciphertext)
    fdt.setprop(file_offset, 'iv', aes_cipher.nonce)
    fdt.setprop(file_offset, 'mac', mac)

    # Write out the updated blob.
    fdt.pack()
    if not dryrun:
        file_atomic_replace(blob, fdt.as_bytearray())

def esm_detach(args):
    blob_contents = file_read(args.blob)
    fdt = libfdt.Fdt(blob_contents)
    validate_esm(fdt, args.blob)

    # Find and delete the attachment.
    file_path = '/file/' + args.file
    file_offset = fdt.path_offset(file_path, QUIET_NOTFOUND)
    if file_offset == -libfdt.NOTFOUND:
        err(1, '{}: not attached', args.file)
    dbg1('{}: deleting node', file_path)
    fdt.del_node(file_offset)

    # Write out the updated blob.
    fdt.pack()
    if not dryrun:
        file_atomic_replace(args.blob, fdt.as_bytearray())

def esm_extract(args):
    blob_contents = file_read(args.blob)
    fdt = libfdt.Fdt(blob_contents)
    validate_esm(fdt, args.blob)

    # Find the attachment.
    file_path = '/file/' + args.file
    file_offset = fdt.path_offset(file_path, QUIET_NOTFOUND)
    if file_offset == -libfdt.NOTFOUND:
        err(1, '{}: not attached', args.file)

    # We only do AES256-GCM.
    algorithm = fdt.getprop(file_offset, 'algorithm').as_str()
    if algorithm != 'AES256-GCM':
        err(1, 'unsupported algorithm: {}', algorithm)

    # Grab the needed properties.
    ciphertext = fdt.getprop(file_offset, 'ciphertext')
    iv = fdt.getprop(file_offset, 'iv')
    mac = fdt.getprop(file_offset, 'mac')

    # Prepare our symmetric cipher.
    symkey = extract_symkey(fdt, args.seckey)
    aes_cipher = AES.new(symkey, AES.MODE_GCM, nonce=iv)

    # Decrypt and verify everything.
    plaintext = aes_cipher.decrypt(ciphertext)
    try:
        aes_cipher.verify(mac)
    except ValueError as e:
        err(1, '{}: cannot decrypt: wrong key or attachment corrupted', args.file)

    # Write the attached file's contents to the standard output.
    if not dryrun:
        print(plaintext.decode('ASCII'), end='')

def esm_digest(args):
    digest(args.bootargs, args.initramfs, args.kernel, args.seckey, None)

def digest(blob, comment, bootargs, initramfs, kernel, seckey, password=None):
    with tempfile.NamedTemporaryFile() as temp:
        esmd_create_digest(temp.name, bootargs, initramfs, kernel)
        blob_contents = file_read(temp.name)
        fdt = libfdt.Fdt(blob_contents)
        attach_digests(blob, temp.name, comment, 'digests-fdt', seckey, password)

def esm_display(args):
    blob_contents = file_read(args.blob)
    fdt = libfdt.Fdt(blob_contents)
    validate_esm(fdt, args.blob)

    dbg1('reading lockboxes')

    # Find the offset to each lockbox and note its number.
    parent_offset = fdt.path_offset('/lockboxes')
    lockbox_offset = fdt.first_subnode(parent_offset)
    offset_by_number = dict()
    while lockbox_offset >= 0:
        lockbox_name = fdt.get_name(lockbox_offset)
        lockbox_num = -1
        if lockbox_name == 'origin-lockbox':
            lockbox_num = 0
        else:
            tokens = lockbox_name.split('-')
            lockbox_num = int(tokens[1])
        offset_by_number[lockbox_num] = lockbox_offset
        lockbox_offset = fdt.next_subnode(lockbox_offset, QUIET_NOTFOUND)

    # Display the hash of the public key and the comment for each lockbox.
    # The origin key's hash is always displayed first.
    for num in sorted(offset_by_number):
        offset = offset_by_number[num]
        comment = fdt.getprop(offset, 'untrusted-comment').as_str()
        fingerprint_offset = fdt.subnode_offset(offset, 'pubkey-fingerprint')
        hash_str = fdt.getprop(fingerprint_offset, 'hash').hex()
        if num == 0:
            prefix = 'origin'
        else:
            prefix = 'recipient'
        print(prefix, hash_str, 'untrusted-comment', comment)

    dbg1('reading attachments')

    # Display the attachment and its comment
    parent_offset = fdt.path_offset('/file')
    file_offset = fdt.first_subnode(parent_offset, QUIET_NOTFOUND)
    while file_offset >= 0:
        comment = fdt.getprop(file_offset, 'untrusted-comment').as_str()
        name = fdt.get_name(file_offset)
        print('file', name, 'untrusted-comment', comment)
        file_offset = fdt.next_subnode(file_offset, QUIET_NOTFOUND)

def esm_generate(args):
    prompt1 = "Enter passphrase (empty for no passphrase):"
    prompt2 = "Enter same passphrase again:"

    if args.pubkey == args.seckey:
        err(1, 'pubkey and seckey cannot be the same: {}', args.pubkey)

    passphrase1 = read_passphrase(prompt1)
    passphrase2 = read_passphrase(prompt2)
    if passphrase1 != passphrase2:
        err(1, 'passphrases do not match')

    if passphrase1 == '':
        passphrase = None
    else:
        passphrase = passphrase1

    dbg1('making new key')

    seckey = RSA.generate(2048)
    pubkey = seckey.publickey()

    serialized_seckey = seckey.export_key(passphrase=passphrase)
    if serialized_seckey[-1] != b'\n':
        serialized_seckey += b'\n'
    serialized_pubkey = pubkey.export_key()
    if serialized_pubkey[-1] != b'\n':
        serialized_pubkey += b'\n'

    # Write the keys.
    if not dryrun:
        file_write(args.seckey, serialized_seckey)
        file_write(args.pubkey, serialized_pubkey)

def esm_make(args):
    make(args.blob, args.config)

def make(blob, config):
    config_contents = file_read(config)
    data_list = yaml.safe_load(config_contents)
    if not isinstance(data_list, list):
        err(1, '{}: invalid format', config)

    origin_list = list()
    recipient_list = list()
    digest_list = list()
    file_list = list()

    # Extract all the top-level dictionaries.
    for entry in data_list:
        if len(entry) != 1:
            err(1, '{}: entry ({}) invalid format {}', config, entry, len(entry))
        for key in entry:
            if key == 'origin':
                origin_list.append(entry[key])
            elif key == 'recipient':
                recipient_list.append(entry[key])
            elif key == 'digest':
                digest_list.append(entry[key])
            elif key == 'file':
                file_list.append(entry[key])
            else:
                err(1, '{}: unknown entry: {}', config, key)

    # There must be one origin entry.
    if len(origin_list) == 0:
        err(1, '{}: missing origin entry', config)
    if len(origin_list) > 1:
        err(1, '{}: multiple origin entries', config)
    origin = origin_list[0]

    # Legal origin keys.
    for key in origin:
        if key not in ['comment', 'pubkey', 'seckey']:
            err(1, '{}: origin entry: unexpected key: {}', config, key)
    # Mandatory origin keys.
    for key in ['pubkey', 'seckey']:
        if key not in origin:
            err(1, '{}: origin entry: missing key: {}', config, key)
    if 'comment' in origin:
        origin_comment = origin['comment']
    else:
        origin_comment = ''
    create(blob, origin['pubkey'], origin_comment)

    if len(recipient_list) == 0 and len(file_list) == 0:
        return 0

    prompt = "Enter passphrase for key '{}':".format(origin['seckey'])
    password = read_passphrase(prompt)

    # Validate each recipient entry and authorize each recipient in blob.
    for recipient in recipient_list:
        # Legal recipient keys.
        for key in recipient:
            if key not in ['comment', 'pubkey']:
                err(1, '{}: recipient entry: unexpected key: {}', config, key)
        # Mandatory recipient keys.
        for key in ['pubkey']:
            if key not in recipient:
                err(1, '{}: recipient entry: missing key: {}', config, key)
        if 'comment' in recipient:
            recipient_comment = recipient['comment']
        else:
            recipient_comment = ''
        authorize(blob, recipient['pubkey'], recipient_comment,
            origin['seckey'], password)

    # There must be one digest entry.
    if len(digest_list) == 0:
        err(1, '{}: missing digest entry', config)
    if len(digest_list) > 1:
        err(1, '{}: multiple digest entries', config)
    digest_entry = digest_list[0]

    # Legal digest keys.
    for key in digest_entry:
        if key not in ['comment', 'args', 'initramfs', 'kernel']:
            err(1, '{}: digest entry: unexpected key: {}', config, key)
    # Mandatory file keys.
    for key in ['args', 'initramfs', 'kernel']:
        if key not in digest_entry:
            err(1, '{}: digest entry: missing key: {}', config, key)
    if 'comment' in digest_entry:
        file_comment = digest_entry['comment']
    else:
        file_comment = ''

    digest(blob, file_comment, digest_entry['args'], digest_entry['initramfs'],
            digest_entry['kernel'], origin['seckey'], password)

    # Validate each file entry and affix each file to blob.
    for file in file_list:
        # Legal file keys.
        for key in file:
            if key not in ['comment', 'name', 'path']:
                err(1, '{}: file entry: unexpected key: {}', config, key)
        # Mandatory file keys.
        for key in ['path']:
            if key not in file:
                err(1, '{}: file entry: missing key: {}', config, key)
        if 'comment' in file:
            file_comment = file['comment']
        else:
            file_comment = ''
        if 'name' in file:
            file_name = file['name']
        else:
            file_name = ''
        attach(blob, file['path'], file_comment, file_name, origin['seckey'],
            password)

    return 0
