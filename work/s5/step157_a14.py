#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step157: a14 = baseline + 4192 @04e0 force loc12=1 (mirror of a13 which forced 0 -> 5979).
Hypothesis (step151-156): baseline VerifyHash=false -> loc12=1 = OFFICIAL HEALTHY state.
a13/a7g forced 0 -> skipped healthy-path init side effects -> 5979 (67 business cctors dead).
a14 forces 1 -> simulate official state regardless of file hash -> expect fields=6201.
Patch 5B @IL0+0x4E0: 16 FE01 130C -> 26 17 130C 00  (pop; ldc.i4.1; stloc.s 12; nop)"""
import hashlib

SRC = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
OUT = '/workspace/repo_git/exes/AirExplorer_a14.exe'
IL0 = 0x3F91DC
OFF = IL0 + 0x4E0
OLD = bytes.fromhex('16FE01130C')
NEW = bytes.fromhex('2617130C00')

exe = bytearray(open(SRC, 'rb').read())
assert exe[OFF:OFF + 5] == OLD, 'mismatch @%x: %s' % (OFF, exe[OFF:OFF+5].hex())
exe[OFF:OFF + 5] = NEW
open(OUT, 'wb').write(bytes(exe))
print('[a14] md5=%s' % hashlib.md5(bytes(exe)).hexdigest().upper())
print('  patched @%x: %s -> %s (loc12 forced 1 = official healthy state)' % (OFF, OLD.hex(), NEW.hex()))
