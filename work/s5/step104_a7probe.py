#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step104: A7 probe = a1 + VerifyHash shim (060041EE) patched to always-true.
Rationale: res5 = AES-256-CBC(RSA-1024 pubkey XML) -> signature unforgeable ->
hash-table rewrite impossible. Instead neuter ONLY the verification shim:
4192 keeps all side effects (AES decrypt res5 -> FromXmlString -> statics),
4528's dependency preserved; only the tamper verdict flips.
Shim @ fileoff 0x405ac8, tiny hdr 0x5A (22B): [ldarg0..3][callvirt VerifyHash][ret][pad]
New: tiny hdr 0x0A (2B): [ldc.i4.1][ret]  + zero pad."""
import hashlib

SRC = '/workspace/repo_git/exes/AirExplorer_a1.exe'
OUT = '/workspace/repo_git/exes/AirExplorer_a7probe.exe'

FO = 0x405ac8
OLD_HDR = 0x5A
OLD_BODY = bytes.fromhex('fe090000fe090100fe090200fe0903006f0c0a000a2a')

exe = bytearray(open(SRC, 'rb').read())
assert exe[FO] == OLD_HDR and exe[FO + 1:FO + 1 + 22] == OLD_BODY, exe[FO:FO + 24].hex()
SRCLEN = len(exe)
# replace the full 23-byte body region in-place: hdr + 2B code + 20B zero pad
exe[FO:FO + 23] = bytes([0x0A, 0x17, 0x2A]) + b'\x00' * 20
assert len(exe) == SRCLEN, 'length changed! %d' % len(exe)
open(OUT, 'wb').write(bytes(exe))
print('[a7probe] %s size=%d md5=%s' % (OUT, len(exe), hashlib.md5(bytes(exe)).hexdigest().upper()))
print('[a7probe] patched head:', bytes(exe[FO:FO + 12]).hex())
