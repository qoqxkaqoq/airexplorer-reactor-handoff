#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step152: dump 06004196 full (pool reinit path) + 428A-428F family + xref newobj 428D."""
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
        if t == 0x01:
            return 'T:%s' % str(md.TypeRef.rows[r-1].TypeName)
        if t == 0x02:
            return 'TD%06x:%s' % (r, str(md.TypeDef.rows[r-1].TypeName))
        if t == 0x2B:
            return 'gspec:%06x' % r
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def sval(tok):
    try:
        s = pe.net.user_strings.get(tok & 0xFFFFFF)
        return str(s.value) if s and s.value is not None else '?'
    except Exception:
        return '?'

def dump(tok):
    if tok not in bodies:
        print('\n[%06x] MISSING' % tok); return
    c, p = bodies[tok]
    ins = list(parse(il[p:p+c]))
    nm = '?'
    try: nm = str(md.MethodDef.rows[(tok & 0xFFFFFF)-1].Name)
    except Exception: pass
    print('\n===== %06x (%s) clen=%d ins=%d =====' % (tok, nm, c, len(ins)))
    for off, name, k, op, plen in ins:
        if k == 'tok':
            print('  @%04x %-12s %s' % (off, name, mname(op)))
        elif k == 'str':
            print('  @%04x %-12s %r' % (off, name, sval(op)[:90]))
        else:
            print('  @%04x %-12s %s' % (off, name, ('%x' % op) if op is not None else ''))

for t in (0x06004196, 0x06004195, 0x0600428A, 0x0600428B, 0x0600428C, 0x0600428D, 0x0600428E, 0x0600428F):
    dump(t)

# xref newobj/ldftn 428D (delegate ctor) -> registration site
print('\n[xref 0600428D newobj/ldftn]:')
for t, (c, p) in bodies.items():
    try:
        for off, name, k, op, plen in parse(il[p:p+c]):
            if k == 'tok' and op == 0x0600428D and name in ('newobj', 'ldftn', 'call'):
                print('   %08x @%04x %s' % (t, off, name))
    except Exception:
        pass
