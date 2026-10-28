#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step137d: tamper-block identity (02000622, 0A:000997, 0A:000252) + stub forward targets."""
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

def tinfo(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x02:
            td = md.TypeDef.rows[r-1]
            return '02:%06x %s.%s' % (r, td.TypeNamespace, td.TypeName)
        if t == 0x01:
            tr = md.TypeRef.rows[r-1]
            return '01:%06x %s.%s' % (r, tr.TypeNamespace, tr.TypeName)
    except Exception as e:
        return '%02x:%06x err' % (t, r)
    return '%02x:%06x' % (t, r)

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06: return '06:%06x:%s' % (r, md.MethodDef.rows[r-1].Name)
        if t == 0x0A:
            m = md.MemberRef.rows[r-1]
            cls = m.Class.row
            cn = getattr(cls, 'TypeName', getattr(cls, 'Name', '?'))
            ns = getattr(cls, 'TypeNamespace', '')
            return '0A:%06x %s%s::%s' % (r, ns + '.' if ns else '', cn, m.Name)
        if t == 0x04: return 'fld:%06x:%s' % (r, md.Field.rows[r-1].Name)
        if t == 0x2B:
            ms = md.MethodSpec.rows[r-1]
            mth = ms.Method.row
            return 'mspec:%06x -> %s' % (r, mname(getattr(mth, 'row_index', 0) or 0))
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

print('[tokens in tamper block]')
print('  ', tinfo(0x02000622))
print('   0A:000997 =', mname(0x0A000997))
print('   0A:000252 =', mname(0x0A000252))
print('   fld:001fbe =', mname(0x04001FBE))

def dump(tok, lo=None, hi=None, title=''):
    if tok not in bodies:
        print('[%s] 06:%06x NOT-IN-INDEX' % (title, tok & 0xFFFFFF)); return
    c, p = bodies[tok]
    print('[%s] 06:%06x clen=%d' % (title, tok & 0xFFFFFF, c))
    for off, name, k, op, plen in parse(il[p:p+c]):
        if lo is not None and not (lo <= off <= hi):
            continue
        ann = ''
        if k == 'tok': ann = ' ' + mname(op)
        elif k in ('br4', 'br1'): ann = ' -> %04x' % op
        elif k == 'var': ann = ' %s' % op
        elif k == 'b': ann = ' %d' % op
        print('   @%04x %s%s' % (off, name, ann))

for rid in (0x41cb, 0x41d0, 0x41cf, 0x41f0, 0x41f1, 0x41f2, 0x41d1, 0x41d2, 0x41d3, 0x41d4, 0x41d5):
    dump(0x06000000 | rid, title='stub')
    print()

# TypeDef 0x622 full row + its method list range
td = md.TypeDef.rows[0x622 - 1]
print('[02000622] %s.%s flags=%s methodlist=%d..%d' % (
    td.TypeNamespace, td.TypeName, td.Flags,
    td.MethodList.row_index if td.MethodList else 0,
    (md.TypeDef.rows[0x622].MethodList.row_index if 0x622 < len(md.TypeDef.rows) else '?')))
