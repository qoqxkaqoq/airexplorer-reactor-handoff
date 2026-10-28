#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step76: A2 = A1 + sentinel kill (06004192 throw->pop at file 0x3f9c76).
Sentinel = SHA1 integrity check over res5 hash table; failure throws
'AirExplorer is tampered.' from DispatcherInitializer.InstantiateGlobalCalculator.
pop instead of throw: newobj'd exception dropped, init chain continues."""
import hashlib

SRC = '/workspace/repo_git/exes/AirExplorer_a1.exe'
OUT = '/workspace/repo_git/exes/AirExplorer_a2.exe'
POS = 0x3f9c76

exe = bytearray(open(SRC, 'rb').read())
assert exe[POS] == 0x7a, 'unexpected byte %#x at %#x' % (exe[POS], POS)
exe[POS] = 0x26
open(OUT, 'wb').write(bytes(exe))
print('[a2] %s size=%d md5=%s' % (OUT, len(exe), hashlib.md5(bytes(exe)).hexdigest().upper()))
