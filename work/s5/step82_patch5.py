#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step82: A5 = A1 + guard1 ret (keep from A3) + swallow 06004523's catch-rethrow.
06004528 must keep running (it does real init; a4 proved ret breaks <Module>{guid}.cctor
with ArgumentOutOfRange). Instead, 06004523's rethrow (ldloc.s; throw @IL 0x046d/0x046f)
is popped: pop leaves the catch handler normally, no state-machine loop (it's a plain handler).
06004523 is stubbed in file + DB-covered head -> deep code sits in file plaintext tail."""
import hashlib

A1 = '/workspace/repo_git/exes/AirExplorer_a1.exe'
OUT = '/workspace/repo_git/exes/AirExplorer_a5.exe'
TOK = 0x06004523
THROW_OFF = 0x046f

exe = bytearray(open(A1, 'rb').read())

# guard1 ret patch (same as A3)
FO1 = 0x3f91d0
assert exe[FO1:FO1 + 16].hex() == '1b3007000a230000270c001120957b53'
exe[FO1:FO1 + 2] = b'\x13\x30'
exe[FO1 + 4:FO1 + 8] = b'\x01\x00\x00\x00'
exe[FO1 + 12] = 0x2a

import dnfile
pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables
rva = md.MethodDef.rows[TOK - 0x06000001].Rva
fo = pe.get_offset_from_rva(rva)
# verify file head is the stub and code tail matches: file code byte k at fo+12+k
fpos = fo + 12 + THROW_OFF
print('[4523] rva=%#x fileoff=%#x throw@file=%#x cur=%#x (expect 0x7a)' % (rva, fo, fpos, exe[fpos]))
# sanity: byte before throw should be ldloc.s (0x11 xx)
print('[4523] ctx:', bytes(exe[fpos - 4:fpos + 2]).hex())
assert exe[fpos] == 0x7a, 'unexpected'
exe[fpos] = 0x26  # pop

open(OUT, 'wb').write(bytes(exe))
print('[a5] %s size=%d md5=%s' % (OUT, len(exe), hashlib.md5(bytes(exe)).hexdigest().upper()))
