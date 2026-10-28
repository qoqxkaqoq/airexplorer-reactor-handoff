#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step126: 4192 window @21e0..@22c0 (RSA instance creation @22ae) + stsfld full table."""
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
            cn = getattr(cls, 'TypeName', getattr(cls, 'Name', '?'))
            ns = getattr(cls, 'TypeNamespace', '')
            return '0A:%s%s::%s' % (ns + '.' if ns else '', cn, m.Name)
        if t == 0x04: return 'fld:%06x:%s' % (r, md.Field.rows[r-1].Name)
        if t == 0x01: return 'tspec:%06x' % r
        if t == 0x02: return 'tdef:%06x' % r
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

clen, pos = bodies[0x06004192]
ins = list(parse(il[pos:pos+clen]))

print('[4192] window @2200..22c8 (RSA creation):')
for e in ins:
    if 0x2200 <= e[0] <= 0x22c8:
        off, name, k, op, plen = e
        ann = ''
        if k in ('tok', 'str'): ann = ' ' + mname(op)
        elif k in ('br4', 'br1'): ann = ' -> %04x' % op
        elif k == 'var': ann = ' %s' % op
        elif k == 'b': ann = ' %d' % op
        print('   %04x %s%s' % (off, name, ann))

# also: which class does the VerifyHash MemberRef 0x0A000A0C belong to?
mr = md.MemberRef.rows[0x0A0C - 1]
cls = mr.Class.row
print('\n[0A000A0C] class=%s.%s name=%r' % (
    getattr(cls, 'TypeNamespace', ''), getattr(cls, 'TypeName', getattr(cls, 'Name', '?')),
    str(mr.Name)))

# stsfld full table of 4192 (rewrite step110 part quickly)
print('\n[4192] stsfld targets:')
seen = {}
for e in ins:
    if e[1] == 'stsfld' and e[2] == 'tok':
        seen.setdefault(e[3], []).append(e[0])
for t, offs in sorted(seen.items()):
    print('   %04x %s @%s' % (t & 0xFFFFFF, mname(t), ','.join('%04x' % x for x in offs)))
