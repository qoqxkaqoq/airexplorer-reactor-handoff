#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step113: a7f = a1 + force the 'is tampered.' guard to always-continue.
a7e lesson: brfalse->br broke stack balance at merge 0x12 (br pops, br doesn't)
-> InvalidProgramException. Correct patch: @00d3 ldloc.s 12 (11 0C) ->
ldc.i4.0 + nop (16 00): push constant 0, brfalse @00f1 always taken -> dispatcher,
throw block @0a72 dead. Stack balanced; 41EE delegate still runs; loc12 (read by
state selector @09f4) untouched."""
import hashlib, struct

SRC = '/workspace/repo_git/exes/AirExplorer_a1.exe'
OUT = '/workspace/repo_git/exes/AirExplorer_a7f.exe'
BODY_RVA = 0x3FAFD0          # 06004192
PATCH_IL_OFF = 0xD3          # @00d3 ldloc.s 12
OLD = bytes.fromhex('110c')  # ldloc.s 12
NEW = bytes.fromhex('1600')  # ldc.i4.0 + nop

exe = bytearray(open(SRC, 'rb').read())
N0 = len(exe)
pe = struct.unpack_from('<I', exe, 0x3C)[0]
nsec = struct.unpack_from('<H', exe, pe + 6)[0]
opt_size = struct.unpack_from('<H', exe, pe + 20)[0]
sec0 = pe + 24 + opt_size
body = None
for i in range(nsec):
    o = sec0 + 40 * i
    va, vsz, raw, rsz = struct.unpack_from('<IIII', exe, o + 12)
    if va <= BODY_RVA < va + max(vsz, rsz):
        body = raw + (BODY_RVA - va)
        break
assert body is not None
hsize = (struct.unpack_from('<H', exe, body)[0] >> 12) * 4
off = body + hsize + PATCH_IL_OFF
assert exe[off:off + 2] == OLD, exe[off:off + 2].hex()
exe[off:off + 2] = NEW
assert len(exe) == N0
open(OUT, 'wb').write(bytes(exe))
print('[a7f] file off 0x%X: 110c->1600  md5=%s' % (off, hashlib.md5(bytes(exe)).hexdigest().upper()))
