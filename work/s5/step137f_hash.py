#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step137f: 4192 window @0400..0aa0 — SHA1 input construction (file? region?)."""
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

def clsname(cls):
    tn = getattr(cls, 'TypeName', None)
    if tn is not None:
        ns = str(getattr(cls, 'TypeNamespace', '') or '')
        return (ns + '.' if ns else '') + str(tn)
    nm = getattr(cls, 'Name', None)
    return str(nm) if nm is not None else '<cls?>'

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06:
            return '06:%06x:%s' % (r, str(md.MethodDef.rows[r-1].Name))
        if t == 0x0A:
            m = md.MemberRef.rows[r-1]
            return '%s::%s' % (clsname(m.Class.row), str(m.Name))
        if t == 0x04:
            return 'fld:%06x:%s' % (r, str(md.Field.rows[r-1].Name))
        if t == 0x2B:
            ms = md.MethodSpec.rows[r-1]
            mt = ms.Method.row
            try:
                return 'gspec<%s::%s>' % (clsname(mt.Class.row), str(mt.Name))
            except Exception:
                return 'mspec:%06x' % r
        if t == 0x01:
            tr = md.TypeRef.rows[r-1]
            return 'T:%s.%s' % (str(tr.TypeNamespace), str(tr.TypeName))
        if t == 0x02:
            td = md.TypeDef.rows[r-1]
            return 'T:%s.%s' % (str(td.TypeNamespace), str(td.TypeName))
        if t == 0x11:
            return 'sig:%06x' % r
        return '%02x:%06x' % (t, r)
    except Exception as e:
        return '%02x:%06x' % (t, r)

c, p = bodies[0x06004192]
print('[4192] @0400..0aa0 (%d ins total)' % len(list(parse(il[p:p+c]))))
for off, name, k, op, plen in parse(il[p:p+c]):
    if not (0x0400 <= off <= 0x0aa0):
        continue
    ann = ''
    if k == 'tok': ann = ' ' + mname(op)
    elif k == 'str': ann = ' STR'
    elif k in ('br4', 'br1'): ann = ' -> %04x' % op
    elif k == 'var': ann = ' %s' % op
    elif k == 'b': ann = ' %d' % op
    elif k == 'i': ann = ' %d' % op if isinstance(op, int) else ' %s' % op
    print('   @%04x %s%s' % (off, name, ann))
