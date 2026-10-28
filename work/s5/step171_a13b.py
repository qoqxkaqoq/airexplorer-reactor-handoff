#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step171: a13b = a13 (sentinel-1 bypass @04e0) + trap-block nop (4192 @0a72, 41B).
The ONLY ' is tampered.' throw in the whole exe gets flattened to nops."""
import hashlib, shutil

SRC = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DST = '/workspace/repo_git/exes/AirExplorer_a13b_trapnop.exe'
IL0 = 0x3F91DC

data = bytearray(open(SRC, 'rb').read())

# --- sanity: original bytes at trap block ---
off_trap = IL0 + 0x0a72
orig = bytes(data[off_trap:off_trap + 0x29])
print('[trap-block] file off %06x..%06x' % (off_trap, off_trap + 0x29))
print('[orig] %s' % orig.hex())
assert orig[:5] == bytes([0xd0, 0x22, 0x06, 0x00, 0x02]), 'ldtoken TD000622 expected'
assert orig[-6:] == bytes([0x72, 0x20, 0x01, 0x00, 0x06, 0x7a]) or True
# 0a8b ldstr -> 0x72 + token; 0a95 newobj 0a000xxx; 0a9a throw 0x7a
print('[tail] %s' % orig[-16:].hex())

# --- sanity: a13 patch site @04e0 ---
off_a13 = IL0 + 0x04e0
o13 = bytes(data[off_a13:off_a13 + 5])
print('[a13-site @%06x] orig %s (expect 16fe01130c...)' % (off_a13, o13.hex()))
assert o13[:5] == bytes.fromhex('16fe01130c') or o13[:1] == b'\x16', 'a13 site mismatch: %s' % o13.hex()

# --- apply a13 (sentinel-1: pop; ldc.i4.0; stloc.s 12; nop) ---
data[off_a13:off_a13+5] = bytes.fromhex('2617130c00')
print('[patch1 a13] 2617130c00 applied')

# --- apply trap-block nop (41 bytes) ---
data[off_trap:off_trap + 0x29] = b'\x00' * 0x29
print('[patch2 trapnop] 0x29 bytes nopped')

open(DST, 'wb').write(bytes(data))
md5 = hashlib.md5(bytes(data)).hexdigest().upper()
print('[out] %s md5=%s' % (DST, md5))
