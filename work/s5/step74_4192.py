#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step74: disassemble DispatcherInitializer::InstantiateGlobalCalculator (06004192)
from probe2 reflection dump; trace the 'AirExplorer is tampered.' throw path."""
import sys, os
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'

il = open(ALL, 'rb').read()
idx = {}
names = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        tok = int(p[0], 16)
        idx[tok] = (int(p[1]), int(p[4]))
        names[tok] = (p[2], p[3])

def body(tok):
    clen, pos = idx[tok]
    return il[pos:pos + clen]

TOK = 0x06004192
b = body(TOK)
print('[body] tok=%s len=%d hex_head=%s' % (hex(TOK), len(b), b[:16].hex()))
ins = parse(b)
for e in ins:
    print(e)
