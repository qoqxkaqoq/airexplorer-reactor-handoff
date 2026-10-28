#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step79v2: A3 = A1 + 06004192 (per-method guard) -> immediate ret, via direct file patch.
The guard's own body sits in the file as full plaintext (not stubbed, not in res0 DB):
  fat hdr @0x3f91d0: 1b30 0700 0a230000 270c0011  (flags fat|initlocals|moresects, codesize 8970)
Patch 9 bytes: flags->0x3013 (drop moresects so JIT won't read the stale EH section),
codesize->1, first code byte->0x2a (ret). Layout/next-body position unchanged."""
import hashlib

SRC = '/workspace/repo_git/exes/AirExplorer_a1.exe'
OUT = '/workspace/repo_git/exes/AirExplorer_a3.exe'

exe = bytearray(open(SRC, 'rb').read())
FO = 0x3f91d0
assert exe[FO:FO + 16].hex() == '1b3007000a230000270c001120957b53', exe[FO:FO + 16].hex()
exe[FO:FO + 2] = b'\x13\x30'          # flags: 0x301b -> 0x3013 (fat, initlocals, no EH)
exe[FO + 4:FO + 8] = b'\x01\x00\x00\x00'  # codesize: 8970 -> 1
exe[FO + 12] = 0x2a                   # ret
open(OUT, 'wb').write(bytes(exe))
print('[a3] %s size=%d md5=%s' % (OUT, len(exe), hashlib.md5(bytes(exe)).hexdigest().upper()))
print('[a3] patched head:', bytes(exe[FO:FO + 16]).hex())
