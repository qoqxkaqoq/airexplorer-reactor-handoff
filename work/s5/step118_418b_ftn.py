#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step118: scan ldftn/ldvirtftn refs to 0600418b; also list the 41E0..41F5 method
family names to map the delegate-table neighborhood."""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse
import dnfile

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'

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

# (1) method family 41E0..41F5 names + attrs
print('[method family 060041E0..060041F5]')
for r in range(0x41E0, 0x41F6):
    m = md.MethodDef.rows[r - 1]
    print('   06:%06x %-40s static=%s virt=%s rva=%s' % (
        r, str(m.Name), m.Flags.mdStatic, m.Flags.mdVirtual, hex(m.Rva) if m.Rva else '0'))

# (2) ldftn/ldvirtftn to 0600418b anywhere
TARGET = 0x0600418b
hits = []
for tok, (clen, pos) in bodies.items():
    try:
        ins = parse(il[pos:pos+clen])
    except Exception:
        continue
    for e in ins:
        if e[1] in ('ldftn', 'ldvirtftn') and e[2] == 'tok' and e[3] == TARGET:
            hits.append((tok, e[0]))
print('\n[ldftn refs to 0600418b] %d' % len(hits))
for tok, off in hits:
    print('   %08x %s @%04x' % (tok, names.get(tok, '?'), off))
