#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step127: a7g = a1 + 4192 @04e0-04e4 force loc12=0 (post-VerifyHash ceq bypass).
  @04db call 060041EE   ; VerifyDynamicStrategy (real RSA VerifyHash runs, side effects kept)
  @04e0 ldc.i4.0        ; 16
  @04e1 ceq             ; FE 01
  @04e3 stloc.s 12      ; 13 0C
  @04e5 br 0x977
Patch 5B @04e0: 16 FE01 130C -> 26 16 130C 00  (pop; ldc.i4.0; stloc.s 12; nop)
Stack-neutral: call pushes 1, pop pops 1, ldc pushes 1, stloc pops 1. Equal length.
Result: 41EE executes normally, loc12 forced 0 -> @09f4 state selector takes the
baseline-healthy branch (42AC key statics initialized) and @00d3 guard reads 0.
Base = a1 (true delegate env, res0 intact)."""
import hashlib

SRC = '/workspace/repo_git/exes/AirExplorer_a1.exe'
OUT = '/workspace/repo_git/exes/AirExplorer_a7g.exe'
# 4192 body: RVA 0x3FAFD0 -> file off of IL0 = 0x3F91DC (delta 0x1DF4, from step112/113)
IL0 = 0x3F91DC
OFF = IL0 + 0x4E0
OLD = bytes.fromhex('16FE01130C')
NEW = bytes.fromhex('2616130C00')

exe = bytearray(open(SRC, 'rb').read())
assert exe[OFF:OFF + 5] == OLD, 'mismatch @%x: %s' % (OFF, exe[OFF:OFF+5].hex())
exe[OFF:OFF + 5] = NEW
open(OUT, 'wb').write(bytes(exe))
print('[a7g] %s md5=%s' % (OUT, hashlib.md5(bytes(exe)).hexdigest().upper()))
print('  patched @%x: %s -> %s' % (OFF, OLD.hex(), NEW.hex()))
