#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step77: inspect 06004192 around the pop site (0x0a9a) + signature of the method."""
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
b = il[idx[0x06004192][1]:idx[0x06004192][1] + idx[0x06004192][0]]
ins = parse(b)
for e in ins:
    if 0x0a60 <= e[0] <= 0x0b60:
        print('%04x  %s %s' % (e[0], e[1], e[2] if e[1] != 'ldc.i4' else hex(e[2]) if isinstance(e[2], int) else e[2]))

# who branches into 0x0a8b..0x0a9b (throw block) and where does 0x0a9b flow
print('--- br/brtrue/brfalse/switch targets hitting 0xa80-0xa9f ---')
for e in ins:
    t = e[2]
    if e[1] in ('br', 'brtrue', 'brfalse', 'brtrue.s', 'brfalse.s', 'br.s') and isinstance(t, int):
        # flat targets are absolute? in flat.py output above: brtrue 8969 / br 18 -> absolute offsets
        if 0xa80 <= t <= 0xa9f:
            print('%04x %s -> %04x' % (e[0], e[1], t))
    if e[1] == 'switch' and isinstance(t, list):
        for k, tgt in enumerate(t):
            if 0xa80 <= tgt <= 0xa9f:
                print('%04x switch[%d] -> %04x' % (e[0], k, tgt))

import dnfile
pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
for i, row in enumerate(pe.net.mdtables.MethodDef.rows):
    if 0x06000001 + i == 0x06004192:
        print('[sig] 06004192 impl=%s' % row.ImplFlags)
        try:
            print('[sig]', row.Signature.__dict__ if hasattr(row.Signature, '__dict__') else row.Signature)
        except Exception as ex:
            print('[sig] raw bytes?', ex)
