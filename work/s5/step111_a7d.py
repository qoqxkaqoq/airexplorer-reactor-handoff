#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step111: a7d = a1 + ONLY the VerifyHash(041EE) always-false shim.
Rationale (r5 probe diff, run 40739534976): healthy path requires VerifyHash()==false
(loc12=1) -> 4192 loads FactoryValidator blob (398794B) into DI._ExtractorVisitors.
a7c (always-true) silently SKIPS the load -> ~70 cctors die -> AG cctor throws at 4528.
a1's real 41EE is a forwarder whose runtime delegate misbehaves in the rebuild ->
bypass it with ldc.i4.0; ret (baseline-equivalent semantics)."""
import hashlib, struct

SRC = '/workspace/repo_git/exes/AirExplorer_a1.exe'
OUT = '/workspace/repo_git/exes/AirExplorer_a7d.exe'
RVA = 0x4078C8
OLD = bytes.fromhex('5afe090000fe090100fe090200fe0903006f0c0a000a2a')
NEW = bytes([0x0A, 0x16, 0x2A]) + b'\x00' * 20  # tiny hdr(2B body) + ldc.i4.0 + ret

exe = bytearray(open(SRC, 'rb').read())
N0 = len(exe)

# PE section table -> RVA to file offset
pe = struct.unpack_from('<I', exe, 0x3C)[0]
assert exe[pe:pe + 4] == b'PE\0\0'
nsec = struct.unpack_from('<H', exe, pe + 6)[0]
opt_size = struct.unpack_from('<H', exe, pe + 20)[0]
sec0 = pe + 24 + opt_size
foff = None
for i in range(nsec):
    o = sec0 + 40 * i
    va, vsz, raw, rsz = struct.unpack_from('<IIII', exe, o + 12)
    if va <= RVA < va + max(vsz, rsz):
        foff = raw + (RVA - va)
        name = exe[o:o + 8].rstrip(b'\0').decode()
        print('[a7d] section %s va=0x%X raw=0x%X -> file off 0x%X' % (name, va, raw, foff))
        break
assert foff is not None, 'RVA not in any section'

assert exe[foff:foff + 23] == OLD, exe[foff:foff + 24].hex()
exe[foff:foff + 23] = NEW
assert len(exe) == N0
open(OUT, 'wb').write(bytes(exe))
print('[a7d] %s md5=%s' % (OUT, hashlib.md5(bytes(exe)).hexdigest().upper()))
