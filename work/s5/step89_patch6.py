#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step89: A6 = baseline + 06004192 ret ONLY (no 5-target patches).
Variable-separation experiment: if AG.cctor passes -> guard2 (4528) tests DATA
(hashtable sync is the right target). If it fails -> guard2 depends on guard1
side effects (different approach needed)."""
import hashlib

SRC = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
OUT = '/workspace/repo_git/exes/AirExplorer_a6.exe'

exe = bytearray(open(SRC, 'rb').read())
FO = 0x3f91d0
assert exe[FO:FO + 16].hex() == '1b3007000a230000270c001120957b53', exe[FO:FO + 16].hex()
exe[FO:FO + 2] = b'\x13\x30'
exe[FO + 4:FO + 8] = b'\x01\x00\x00\x00'
exe[FO + 12] = 0x2a
open(OUT, 'wb').write(bytes(exe))
print('[a6] %s size=%d md5=%s' % (OUT, len(exe), hashlib.md5(bytes(exe)).hexdigest().upper()))
print('[a6] patched head:', bytes(exe[FO:FO + 16]).hex())
