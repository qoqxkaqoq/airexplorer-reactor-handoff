#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step107: a7c = baseline + ONLY the VerifyHash-shim(041EE) always-true patch.
Data untouched (res0 DB identical to baseline). Discriminates why 4528 fires:
  a7c ALIVE -> 4528 trips on the 3 patched res0 targets' behavior (or other res)
  a7c DEAD  -> 4528 hashes the shim region itself (file-integrity over 4192 body)"""
import hashlib

SRC = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
OUT = '/workspace/repo_git/exes/AirExplorer_a7c.exe'
FO = 0x405ac8
OLD = bytes.fromhex('5afe090000fe090100fe090200fe0903006f0c0a000a2a')
NEW = bytes([0x0A, 0x17, 0x2A]) + b'\x00' * 20

exe = bytearray(open(SRC, 'rb').read())
N0 = len(exe)
assert exe[FO:FO + 23] == OLD, exe[FO:FO + 24].hex()
exe[FO:FO + 23] = NEW
assert len(exe) == N0
open(OUT, 'wb').write(bytes(exe))
print('[a7c] %s md5=%s' % (OUT, hashlib.md5(bytes(exe)).hexdigest().upper()))
