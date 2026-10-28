#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step122: dump 06004195 SearchStrategy (real blob loader) + 06004282 DirectDefinition."""
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
        if t == 0x70: return 'str@%x' % (r)
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

for tok in (0x06004195, 0x06004282):
    m = md.MethodDef.rows[(tok & 0xFFFFFF) - 1]
    print('[%08x] %r static=%s rva=%s' % (tok & 0xFFFFFF, str(m.Name),
          m.Flags.mdStatic, hex(m.Rva) if m.Rva else '0'))
    clen, pos = bodies[tok]
    ins = list(parse(il[pos:pos+clen]))
    out = '/tmp/step122_%06x.txt' % (tok & 0xFFFFFF)
    with open(out, 'w') as f:
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
            elif k == 'b':
                ann = ' %d' % op
            f.write('%04x %s%s\n' % (off, name, ann))
    print('   size=%d ins=%d -> %s' % (clen, len(ins), out))
