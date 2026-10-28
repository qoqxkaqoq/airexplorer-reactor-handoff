#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step112: a7e = a1 + kill the 'is tampered.' throw guard in 4192.
Model (a7d verdict, run 40740983107): 41EE delegate returns FALSE in the rebuild
-> loc12 = !result = 1 -> guard @00d3 (ldloc.s 12; brfalse 0x12; br 0xa72) fires
the throw @0a72 (ldtoken 0x02000562 -> Assembly.Name + " is tampered.").
Patch: @00f1 brfalse(0x39) -> br(0x38), same operand (target 0x12, unchanged).
Throw block becomes dead code; the 41EE delegate still RUNS (side effects kept)."""
import hashlib, struct

SRC = '/workspace/repo_git/exes/AirExplorer_a1.exe'
OUT = '/workspace/repo_git/exes/AirExplorer_a7e.exe'
BODY_RVA = 0x3FAFD0          # 06004192
PATCH_IL_OFF = 0xF1          # @00f1 brfalse -> br
OLD = bytes.fromhex('391cffffff')
NEW = bytes.fromhex('381cffffff')

exe = bytearray(open(SRC, 'rb').read())
N0 = len(exe)
pe = struct.unpack_from('<I', exe, 0x3C)[0]
nsec = struct.unpack_from('<H', exe, pe + 6)[0]
opt_size = struct.unpack_from('<H', exe, pe + 20)[0]
sec0 = pe + 24 + opt_size
foff = None
for i in range(nsec):
    o = sec0 + 40 * i
    va, vsz, raw, rsz = struct.unpack_from('<IIII', exe, o + 12)
    if va <= BODY_RVA < va + max(vsz, rsz):
        body = raw + (BODY_RVA - va)
        break
assert body is not None
hsize = (struct.unpack_from('<H', exe, body)[0] >> 12) * 4
off = body + hsize + PATCH_IL_OFF
assert exe[off:off + 5] == OLD, exe[off:off + 5].hex()
exe[off:off + 5] = NEW
assert len(exe) == N0
open(OUT, 'wb').write(bytes(exe))
print('[a7e] file off 0x%X: 39->38  md5=%s' % (off, hashlib.md5(bytes(exe)).hexdigest().upper()))
