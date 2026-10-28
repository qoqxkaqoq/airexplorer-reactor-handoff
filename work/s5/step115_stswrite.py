#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step115: scan ALL method ILs for ldsfld/stsfld of _ExtractorVisitors (0x04001FD0)
and m_ExtendedSchemaTemplate (0x04001FCD). Output method tokens + offsets."""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse
import dnfile

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'

TARGETS = {0x04001FD0: '_ExtractorVisitors', 0x04001FCD: 'm_ExtendedSchemaTemplate'}

il = open(ALL, 'rb').read()
bodies = {}
names = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        tok = int(p[0], 16)
        bodies[tok] = (int(p[1]), int(p[4]))
        names[tok] = p[2] if len(p) > 2 else ''

pe = dnfile.dnPE(EXE)
md = pe.net.mdtables

print('[scan] %d methods' % len(bodies))
hits = {}  # field -> list of (mtok, off, op)
n = 0
for tok, (clen, pos) in bodies.items():
    n += 1
    try:
        ins = parse(il[pos:pos + clen])
    except Exception as e:
        print('  [parse-fail] %08x %s' % (tok, e))
        continue
    for e in ins:
        if e[1] in ('stsfld', 'ldsfld') and e[2] == 'tok' and e[3] in TARGETS:
            hits.setdefault(e[3], []).append((tok, e[0], e[1]))

for fld, lst in sorted(hits.items()):
    print('\n[%s] 0x%08x  %d refs' % (TARGETS[fld], fld, len(lst)))
    # summarize per method
    perm = {}
    for tok, off, op in lst:
        perm.setdefault(tok, []).append((op, off))
    for tok in sorted(perm):
        ops = perm[tok]
        w = [o for o in ops if o[0] == 'stsfld']
        print('   %08x %s  refs=%d W=%d  %s' % (
            tok, names.get(tok, '?'), len(ops), len(w),
            ' '.join('%s@%04x' % (o, x) for o, x in ops[:8])))
