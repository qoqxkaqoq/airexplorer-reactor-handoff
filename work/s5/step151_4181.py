#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step151: dump 06004181 DispatcherInitializer::cctor full IL — the last divergence point of a13(5979).
Also: xref ldftn/ldtoken 0600428B/0600428C (delegate registration) + all 0600428A call sites."""
import sys, re
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
            tr = md.TypeRef.rows[r-1]
            return 'T:%s' % str(tr.TypeName)
        if t == 0x02:
            td = md.TypeDef.rows[r-1]
            return 'TD%06x:%s' % (r, str(td.TypeName))
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

def dump(tok, label):
    if tok not in bodies:
        print('[%s] %x MISSING from il_index' % (label, tok)); return
    c, p = bodies[tok]
    ins = list(parse(il[p:p+c]))
    print('\n===== %s %x  clen=%d ins=%d =====' % (label, tok, c, len(ins)))
    for off, name, k, op, plen in ins:
        if k == 'tok':
            print('  @%04x %-12s %s' % (off, name, mname(op)))
        elif k == 'str':
            print('  @%04x %-12s %r' % (off, name, sval(op)[:90]))
        else:
            print('  @%04x %-12s %s' % (off, name, ('%x' % op) if op is not None else ''))

# ---- 1) 06004181 full dump
dump(0x06004181, '4181 DispatcherInitializer.cctor')

# ---- 2) global xref: ldftn/ldtoken 428B/428C + call/newobj 428A/428B/428C
TARGETS = {0x0600428B: '428B(ResourceResolve dlg)', 0x0600428C: '428C(AssemblyResolve dlg)',
           0x0600428A: '428A(WrapCommonSorter)', 0x06004181: '4181(DispatcherInit.cctor)',
           0x0600428F: '428F(.cctor default)'}
hits = {}
for t, (c, p) in bodies.items():
    try:
        for off, name, k, op, plen in parse(il[p:p+c]):
            if k == 'tok' and op in TARGETS and name in ('ldftn', 'ldtoken', 'ldvirtftn', 'call', 'callvirt', 'newobj'):
                hits.setdefault(op, []).append((t, off, name))
    except Exception:
        pass

for tok in sorted(TARGETS):
    lst = hits.get(tok, [])
    if not lst:
        print('\n[xref %s] NO REFERENCES' % TARGETS[tok]); continue
    print('\n[xref %s] %d sites:' % (TARGETS[tok], len(lst)))
    for t, off, name in lst[:40]:
        try:
            nm = str(md.MethodDef.rows[(t & 0xFFFFFF)-1].Name)
        except Exception:
            nm = '?'
        print('   %08x (%06x %s) @%04x %s' % (t, t & 0xFFFFFF, nm, off, name))
    if len(lst) > 40:
        print('   ... %d more' % (len(lst) - 40))
