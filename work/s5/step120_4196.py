#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step120: dump 06004196 (the ldsfld reader of _ExtractorVisitors) + metadata."""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse
import dnfile

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'

il = open(ALL, 'rb').read()
bodies = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        bodies[int(p[0], 16)] = (int(p[1]), int(p[4]))

pe = dnfile.dnPE(EXE)
md = pe.net.mdtables

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06: return '06:%06x:%s' % (r, md.MethodDef.rows[r-1].Name)
        if t == 0x0A:
            m = md.MemberRef.rows[r-1]
            cls = m.Class.row
            return '0A:%s::%s' % (getattr(cls, 'TypeName', '?'), m.Name)
        if t == 0x04: return 'fld:%06x:%s' % (r, md.Field.rows[r-1].Name)
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

m = md.MethodDef.rows[0x4196 - 1]
print('[06004196] Name=%r static=%s virt=%s rva=%s' % (
    str(m.Name), m.Flags.mdStatic, m.Flags.mdVirtual, hex(m.Rva) if m.Rva else '0'))

clen, pos = bodies[0x06004196]
ins = list(parse(il[pos:pos+clen]))
print('[body] size=%d ins=%d' % (clen, len(ins)))
with open('/tmp/step120_004196.txt', 'w') as f:
    for e in ins:
        off, name, k, op, plen = e
        ann = ''
        if k in ('tok', 'str'):
            ann = ' ' + mname(op)
        elif k in ('br4', 'br1'):
            ann = ' -> %04x' % op
        elif k == 'sw':
            ann = ' -> ' + ','.join('%04x' % t for t in op)
        elif k == 'var':
            ann = ' %s' % op
        f.write('%04x %s%s\n' % (off, name, ann))
print('-> /tmp/step120_004196.txt')

# callers of 4196
refs = []
for tok, (clen2, pos2) in bodies.items():
    try:
        ins2 = parse(il[pos2:pos2+clen2])
    except Exception:
        continue
    for e in ins2:
        if e[1] in ('call', 'callvirt', 'ldftn') and e[2] == 'tok' and e[3] == 0x06004196:
            refs.append((tok, e[0], e[1]))
print('[callers of 06004196] %d' % len(refs))
for tok, off, op in refs[:10]:
    print('   %08x %s @%04x (%s)' % (tok, mname(tok), off, op))
