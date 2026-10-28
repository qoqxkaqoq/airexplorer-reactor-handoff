#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step117b: compact metadata + callers of 0600418b."""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'

il = open(ALL, 'rb').read()
bodies = {}
names = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        tok = int(p[0], 16)
        bodies[tok] = (int(p[1]), int(p[4]))
        names[tok] = p[2] if len(p) > 2 else ''

TARGET_CALL = 0x0600418b
callers = []
for tok, (clen, pos) in bodies.items():
    try:
        ins = parse(il[pos:pos+clen])
    except Exception:
        continue
    for e in ins:
        if e[1] in ('call', 'callvirt', 'newobj', 'jmp') and e[2] == 'tok' and e[3] == TARGET_CALL:
            callers.append((tok, e[0], e[1]))
print('[callers of 0600418b GenerateAlphabeticVerifier] %d' % len(callers))
for tok, off, op in callers:
    print('   %08x %-40s %s @%04x' % (tok, names.get(tok, '?'), op, off))
