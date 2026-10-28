#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step169: (1) whole-exe ldstr 'tampered' census; (2) dump 4192 @0a00-0b60 window;
(3) dump GenerateLocalError full (path self-check)."""
import sys, re
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

print('== whole-exe ldstr containing tamper/AirExplorer ==')
TRE = re.compile(r'tamper|AirExplorer', re.I)
for tok in sorted(bodies):
    c, p = bodies[tok]
    try:
        ins = list(parse(il[p:p+c]))
    except Exception:
        continue
    for off, name, k, op, plen in ins:
        if k == 'str' and TRE.search(sval(op)):
            print('  %s @%04x %r' % (names[tok], off, sval(op)[:60]))

def dumpwin(tok, lo, hi, label):
    c, p = bodies[tok]
    ins = list(parse(il[p:p+c]))
    print('== %s @%04x-%04x ==' % (label, lo, hi))
    for off, name, k, op, plen in ins:
        if lo <= off <= hi:
            if k == 'tok': print('  @%04x %-10s %s' % (off, name, mname(op)))
            elif k == 'str': print('  @%04x %-10s %r' % (off, name, sval(op)[:70]))
            elif k == 'sw': print('  @%04x %-10s [%d tgts]' % (off, name, len(op)))
            else: print('  @%04x %-10s %s' % (off, name, ('%x' % op) if op is not None else ''))

dumpwin(0x06004192, 0x0a00, 0x0b60, '4192 window')

# GenerateLocalError full
tok = 0x0600419d
c, p = bodies[tok]
ins = list(parse(il[p:p+c]))
print('== 419d GenerateLocalError (%dB, %d ins) full ==' % (c, len(ins)))
for off, name, k, op, plen in ins:
    if k == 'tok': print('  @%04x %-10s %s' % (off, name, mname(op)))
    elif k == 'str': print('  @%04x %-10s %r' % (off, name, sval(op)[:70]))
    elif k == 'sw': print('  @%04x %-10s [%d tgts]' % (off, name, len(op)))
    else: print('  @%04x %-10s %s' % (off, name, ('%x' % op) if op is not None else ''))
