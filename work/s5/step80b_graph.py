#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step80b: map 06004524 call graph -> find the actual thrower."""
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

def body(tok):
    clen, pos = idx[tok]
    return il[pos:pos + clen]

def calls_of(tok):
    b = body(tok)
    out = []
    for e in parse(b):
        if e[1] in ('call', 'callvirt', 'newobj'):
            out.append((e[0], e[1], struct.unpack_from('<I', b, e[0] + 1)[0]))
    return out

def throwinfo(tok):
    b = body(tok)
    th = [e for e in parse(b) if e[1] in ('throw', 'rethrow')]
    return th

T = 0x06004524
seen = set()
frontier = [T]
depth = 0
while frontier and depth < 4:
    nxt = []
    for tok in frontier:
        if tok in seen:
            continue
        seen.add(tok)
        th = throwinfo(tok)
        cs = calls_of(tok)
        print('[%s] throws=%d calls=%s' % (hex(tok), len(th), ' '.join('%s@%04x' % (hex(t), o) for o, k, t in cs)))
        for o, k, t in cs:
            if (t & 0xFF000000) == 0x06000000 and t in idx and t not in seen:
                nxt.append(t)
    frontier = nxt
    depth += 1
    print('--- depth %d ---' % depth)
