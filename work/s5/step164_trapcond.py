#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step164: (1) dump 4194/4282/453a/4650 bodies; (2) reverse-branch analysis of
68 newobj-448f trap sites in 4528 -> who branches INTO each trap."""
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

def fmt(x):
    off, name, k, op, plen = x
    if k == 'tok': return '@%04x %-10s %s' % (off, name, mname(op))
    if k == 'str': return '@%04x %-10s %r' % (off, name, sval(op)[:60])
    if k in ('sw',): return '@%04x %-10s [%d tgts]' % (off, name, len(op) if hasattr(op, '__len__') else 0)
    return '@%04x %-10s %s' % (off, name, ('%x' % op) if op is not None else '')

def dumpfull(tok, label):
    c, p = bodies[tok]
    ins = list(parse(il[p:p+c]))
    print('== %s (%06x, %dB, %d ins) ==' % (label, tok & 0xFFFFFF, c, len(ins)))
    for x in ins:
        print('  ' + fmt(x))
    return ins

for tok, lab in [(0x06004194, '4194 DefineActiveEvent'), (0x06004282, '4282 DirectDefinition'),
                 (0x0600453a, '453a GenerateCustomMonitor'), (0x06004650, '4650 ExecuteExplorer')]:
    dumpfull(tok, lab)
print()

# ---- reverse-branch analysis on 4528 ----
ins = list(parse(il[bodies[0x06004528][0] and 0 or 0:0])) if False else None
c, p = bodies[0x06004528]
ins = list(parse(il[p:p+c]))

BR = re.compile(r'^(br|br\.s|brtrue|brtrue\.s|brfalse|brfalse\.s|beq|beq\.s|bne\.un|bne\.un\.s|bge|bge\.s|bge\.un|bge\.un\.s|bgt|bgt\.s|bgt\.un|bgt\.un\.s|ble|ble\.s|ble\.un|ble\.un\.s|blt|blt\.s|blt\.un|blt\.un\.s)$')
# switch targets too
traps = [x[0] for x in ins if x[1] == 'newobj' and x[2] == 'tok' and (x[3] >> 24) == 0x06 and (x[3] & 0xFFFFFF) == 0x00448f]
print('== trap sites: %d ==' % len(traps))
trapset = set(traps)

# build: list of (idx, off, name, target)
incoming = {t: [] for t in traps}
sw_targets = {}
for i, (off, name, k, op, plen) in enumerate(ins):
    if k in ('br1', 'br4') and BR.match(name):
        if op in trapset:
            incoming[op].append((i, off, name, 'branch'))
    elif k == 'sw':
        for tg in op:
            if tg in trapset:
                incoming[tg].append((i, off, name, 'switch'))

for t in traps:
    inc = incoming[t]
    print('---- trap @%04x: %d incoming ----' % (t, len(inc)))
    for i, off, name, kind in inc:
        print('  via %s @%04x (idx %d):' % (kind, off, i))
        for j in range(max(0, i-10), min(len(ins), i+2)):
            mark = '>>' if j == i else '  '
            print('   %s %s' % (mark, fmt(ins[j])))
