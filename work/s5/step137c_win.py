#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step137c: 4192 windows around 'SHA1' (@0b01) and res5 name (@0be5) + stub bodies."""
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
us = pe.net.user_strings

def sval(tok):
    try:
        s = us.get(tok & 0xFFFFFF)
        return str(s.value) if s and s.value is not None else '?'
    except Exception:
        return '?'

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
        if t == 0x2B: return 'mspec:%06x' % r
        if t == 0x1B: return 'tsig:%06x' % r
        if t == 0x11: return 'stsig:%06x' % r
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def dump(tok, lo=None, hi=None, title=''):
    c, p = bodies[tok]
    print('[%s] 06:%06x clen=%d%s' % (title, tok & 0xFFFFFF, c,
          ' window @%04x..%04x' % (lo, hi) if lo is not None else ''))
    for off, name, k, op, plen in parse(il[p:p+c]):
        if lo is not None and not (lo <= off <= hi):
            continue
        ann = ''
        if k == 'tok': ann = ' ' + mname(op)
        elif k == 'str': ann = ' %r' % sval(op)[:60]
        elif k in ('br4', 'br1'): ann = ' -> %04x' % op
        elif k == 'var': ann = ' %s' % op
        elif k == 'b': ann = ' %d' % op
        print('   @%04x %s%s' % (off, name, ann))

# 1) window before/after 'SHA1' ldstr
dump(0x06004192, 0x0a40, 0x0c20, 'w1 SHA1 zone')
# 2) window around res5 name
dump(0x06004192, 0x0bb0, 0x0c60, 'w2 res5 zone')
# 3) stub bodies consuming strings: 41cb,41ce,41cf,41d0,41f0,41f1,41f2,41ca,41cc,41cd
for rid in (0x41ca, 0x41cb, 0x41cc, 0x41cd, 0x41ce, 0x41cf, 0x41d0, 0x41f0, 0x41f1, 0x41f2):
    dump(0x06000000 | rid, title='stub')
    print()
