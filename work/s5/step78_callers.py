#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step78: find callers of 06004192 (byte pattern 28 92 41 00 06) in all bodies."""
import sys, struct
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
il = open(ALL, 'rb').read()
idx = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        idx[int(p[0], 16)] = (int(p[1]), int(p[4]))

PAT = struct.pack('<I', 0x06004192)
hits = []
for tok, (clen, pos) in idx.items():
    b = il[pos:pos + clen]
    j = b.find(b'\x28' + PAT)
    while j != -1:
        hits.append((tok, j))
        j = b.find(b'\x28' + PAT, j + 1)
print('[callers of 06004192]', [(hex(t), hex(o)) for t, o in hits])
for tok, off in hits:
    clen, pos = idx[tok]
    b = il[pos:pos + clen]
    ins = parse(b)
    seq = [e for e in ins]
    for k, e in enumerate(seq):
        if e[0] == off:
            for c in seq[max(0, k - 3):k + 4]:
                print('  %04x %s %s' % (c[0], c[1], hex(c[2]) if isinstance(c[2], int) and c[1] not in ('switch',) else c[2]))
            print('  ---')
