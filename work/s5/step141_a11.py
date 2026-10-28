#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step141: a11/a12 = a9 variants + 4192@04e0 sentinel bypass (loc12 forced 0).

a11 = a9_p12 (DB-entry-only changes) + @04e0 -> tests DB changes under bypassed sentinel
a12 = a9_all  (P1+P2-only changes)  + @04e0 -> tests P1/P2 changes under bypassed sentinel

verdict (fields = R5.I):
  a11=6201 -> DB changes harmless (poison = P1/P2 plaintext bytes)
  a12=6201 -> P1/P2 harmless (poison = DB changes)
  both 5979-> both poison downstream (hash has no outlet; effects are data-derived)
  both 6201-> everything safe under bypass (contradicts a7g=5979 -> combo effect)
"""
import hashlib

A9P12 = '/workspace/repo_git/exes/AirExplorer_a9_p12.exe'
A9ALL = '/workspace/repo_git/exes/AirExplorer_a9_all.exe'
OUT = '/workspace/repo_git/exes/'

# 4192@04e0: file offset = IL0 + 0x4E0, IL0 = 0x3F91DC (4192 NOT-IN-DB, plaintext body)
OFF = 0x3F91DC + 0x4E0
OLD = bytes.fromhex('16FE01130C')            # ldc.i4.0; ceq; stloc.s 12
NEW = bytes.fromhex('2616130C00')            # pop; ldc.i4.0; stloc.s 12; nop

for src, name in ((A9P12, 'a11_dbonly'), (A9ALL, 'a12_p12only')):
    b = bytearray(open(src, 'rb').read())
    assert bytes(b[OFF:OFF+5]) == OLD, (name, bytes(b[OFF:OFF+5]).hex())
    b[OFF:OFF+5] = NEW
    data = bytes(b)
    open(OUT + 'AirExplorer_%s.exe' % name, 'wb').write(data)
    print('%s: md5=%s' % (name, hashlib.md5(data).hexdigest().upper()))
