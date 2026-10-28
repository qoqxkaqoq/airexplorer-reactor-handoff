#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step121: verify whether 0600000a ToString really calls 06004196 @001d."""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse
import dnfile

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'

il = open(ALL, 'rb').read()
bodies = {}
raw = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        tok = int(p[0], 16)
        bodies[tok] = (int(p[1]), int(p[4]))
        raw[tok] = p

pe = dnfile.dnPE(EXE)
md = pe.net.mdtables

print('[index rows for 0600000a]', raw[0x0600000a])
print('[index rows for 06004196]', raw[0x06004196])

clen, pos = bodies[0x0600000a]
ins = list(parse(il[pos:pos+clen]))
print('\n[0600000a ToString] size=%d ins=%d' % (clen, len(ins)))
for e in ins:
    off, name, k, op, plen = e
    print('   %04x %s %s' % (off, name, hex(op) if k in ('tok', 'str') else op))
