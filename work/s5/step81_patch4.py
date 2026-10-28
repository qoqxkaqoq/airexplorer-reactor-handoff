#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step81: A4 = A3 + 06004528 -> bare ret via res0 DB delta.
06004528 (27546B, 74 throws) is the second-layer sentinel state machine,
called by 06004523 as void(arg0, var). It is stubbed in the file and lives
in the res0 DB -> patch = DB dword rewrite + cipher XOR delta."""
import struct, hashlib

A3 = '/workspace/repo_git/exes/AirExplorer_a3.exe'
DB0 = '/workspace/repo_git/work/s5/mem5/res0_plain_a1.bin'   # A3 leaves DB unchanged from A1
OUT = '/workspace/repo_git/exes/AirExplorer_a4.exe'
TOK = 0x06004528

exe = bytearray(open(A3, 'rb').read())
db = bytearray(open(DB0, 'rb').read())
db_old = bytes(db)

import dnfile
pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables
rva = md.MethodDef.rows[TOK - 0x06000001].Rva
print('[4528] rva=%#x' % rva)

off = 24
eo = None
while off < len(db):
    r, n = struct.unpack_from('<II', db, off)
    if r == rva:
        eo, nn = off, n
        break
    off += 8 + 4 * n
assert eo is not None, '06004528 not in DB'
old = bytes(db[eo + 8:eo + 8 + 4 * nn])
print('[4528] DB n=%d old_head=%s' % (nn, old[:12].hex()))
NEW = bytes([0x06, 0x2a]) + b'\x00' * (4 * nn - 2)
db[eo + 8:eo + 8 + 4 * nn] = NEW

base = pe.get_offset_from_rva(pe.net.struct.ResourcesRva)
cipher_off = None
for r in md.ManifestResource.rows:
    p = base + r.Offset
    ln = struct.unpack_from('<I', exe, p)[0]
    if ln == len(db):
        cipher_off = p + 4
delta = bytes(a ^ b for a, b in zip(db_old, db))
nz = [i for i, b in enumerate(delta) if b]
print('[delta] nonzero=%d at %s' % (len(nz), nz))
for i in nz:
    exe[cipher_off + i] ^= delta[i]

open(OUT, 'wb').write(bytes(exe))
open('/workspace/repo_git/work/s5/mem5/res0_plain_a4.bin', 'wb').write(bytes(db))
print('[a4] %s size=%d md5=%s' % (OUT, len(exe), hashlib.md5(bytes(exe)).hexdigest().upper()))
