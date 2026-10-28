#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step170: dump 41cb/41ee/41f0/41f1/41f2 — second sentinel's helper family."""
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
        bodies[int(p[0], 16)] = (int(p[1]), int(p[4]))
        names[int(p[0], 16)] = '%s::%s' % (p[2], p[3])

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
            m2 = md.MemberRef.rows[r-1]
            return '%s::%s' % (clsname(m2.Class.row), str(m2.Name))
        if t == 0x04:
            return 'fld:%06x:%s' % (r, str(md.Field.rows[r-1].Name))
        if t == 0x01:
            return 'T:%s' % str(md.TypeRef.rows[r-1].TypeName)
        if t == 0x02:
            return 'TD%06x:%s' % (r, str(md.TypeDef.rows[r-1].TypeName))
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def sval(tok):
    try:
        s = pe.net.user_strings.get(tok & 0xFFFFFF)
        return str(s.value) if s and s.value is not None else '?'
    except Exception:
        return '?'

for tok in [0x060041cb, 0x060041ee, 0x060041f0, 0x060041f1, 0x060041f2]:
    c, p = bodies[tok]
    ins = list(parse(il[p:p+c]))
    print('== %s (%dB, %d ins) ==' % (names[tok], c, len(ins)))
    for off, name, k, op, plen in ins:
        if k == 'tok': print('  @%04x %-10s %s' % (off, name, mname(op)))
        elif k == 'str': print('  @%04x %-10s %r' % (off, name, sval(op)[:70]))
        elif k == 'sw': print('  @%04x %-10s [%d tgts]' % (off, name, len(op)))
        else: print('  @%04x %-10s %s' % (off, name, ('%x' % op) if op is not None else ''))
    print()

# xref: who calls 41f0/41f1/41f2
print('== xref 41f0/41f1/41f2/41cb ==')
XS = {0x0041f0: [], 0x0041f1: [], 0x0041f2: [], 0x0041cb: []}
for tok in sorted(bodies):
    c, p = bodies[tok]
    try:
        ins = list(parse(il[p:p+c]))
    except Exception:
        continue
    for off, name, k, op, plen in ins:
        if k == 'tok' and name in ('call', 'callvirt') and (op >> 24) == 0x06:
            r = op & 0xFFFFFF
            if r in XS:
                XS[r].append('%s @%04x' % (names.get(tok, '%06x' % tok), off))
for r in sorted(XS):
    print('06:%06x x%d:' % (r, len(XS[r])))
    for x in XS[r][:12]:
        print('   ' + x)
