#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step142: a13 = baseline + ONLY the @04e0 sentinel bypass (5 bytes in 4192 body, nothing else).

If fields=6201 -> the @04e0 patch itself is harmless; 5979 poison = data changes (DB or P1/P2),
i.e. ANY file change poisons the downstream lib-load chain (419C/428A) independently of 4192.
If fields=5979 -> the @04e0 5B change itself poisons the chain -> there is ANOTHER sentinel
(probably inside 419C/428A) watching 4192's body region -> multi-sentinel system.
"""
import hashlib

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
OUT = '/workspace/repo_git/exes/AirExplorer_a13_bypass_only.exe'

OFF = 0x3F91DC + 0x4E0
OLD = bytes.fromhex('16FE01130C')
NEW = bytes.fromhex('2616130C00')

b = bytearray(open(BASE, 'rb').read())
cur = bytes(b[OFF:OFF+5])
print('4192@04e0 current:', cur.hex(), '(baseline==OLD:', cur == OLD, ')')
b[OFF:OFF+5] = NEW
data = bytes(b)
open(OUT, 'wb').write(data)
print('a13_bypass_only: md5=%s' % hashlib.md5(data).hexdigest().upper())
