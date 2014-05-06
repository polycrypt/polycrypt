#!/usr/bin/env python

import hashlib
from Crypto.Hash import SHA


def get_pass_hash(pass_plain, salt):
    pass_hash = pass_plain + salt
    for _ in range(10000):
        m = hashlib.sha256()
        m.update(pass_hash)
        pass_hash = m.digest()
    pass_enc = ''
    for byte in pass_hash:
        val = hex(ord(byte))[2:]
        while len(val) < 2:
            val = '0' + val
        pass_enc += val
    return pass_enc

def myhash(txt):
    m = hashlib.sha256()
    m.update(txt)
    hashed_txt = m.digest()
    hex_str = ''
    for byte in hashed_txt:
        val = hex(ord(byte))[2:]
        while len(val) < 2:
            val = '0' + val
        hex_str += val
    return hex_str

print myhash('a\x00')

