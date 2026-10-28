#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step166: trace delegate-field init points (stsfld) for 4528's check delegates
(fld:00212e InterruptError, fld:002129 MatchRunner, fld:002066 m_ScheduledHandlerTemplate)
across the whole exe; dump 41ED; find owner types."""
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

# owner type of a field token
def fld_owner(fld_rid):
    try:
        f = md.Field.rows[fld_rid-1]
        # find via TypeDef field list — brute force
        for i, td in enumerate(md.TypeDef.rows):
            for fl in td.FieldList:
                if fl.row_index == fld_rid:
                    return '%s.%s' % (td.TypeNamespace, td.TypeName)
    except Exception:
        pass
    return '?'

TARGETS = {0x00212e: 'InterruptError', 0x002129: 'MatchRunner', 0x002066: 'm_ScheduledHandlerTemplate'}
for rid, nm in TARGETS.items():
    print('fld:%06x %s owner=%s' % (rid, nm, fld_owner(rid)))

print()
print('== whole-exe stsfld/ldsfld scan for targets ==')
HITS = {0x00212e: [], 0x002129: [], 0x002066: []}
for tok in sorted(bodies):
    c, p = bodies[tok]
    try:
        ins = list(parse(il[p:p+c]))
    except Exception:
        continue
    for off, name, k, op, plen in ins:
        if name in ('stsfld', 'ldsfld') and k == 'tok' and (op >> 24) == 0x04:
            rid = op & 0xFFFFFF
            if rid in HITS:
                HITS[rid].append('%s%s@%04x in %s' % (name[:3], ' 0x%06x' % tok, off, names.get(tok, '?')))
for rid, hits in HITS.items():
    print('-- fld:%06x (%s): %d refs' % (rid, TARGETS[rid], len(hits)))
    for h in hits[:40]:
        print('   ' + h)

print()
# dump 41ED
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
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def clsname(cls):
    tn = getattr(cls, 'TypeName', None)
    if tn is not None:
        ns = str(getattr(cls, 'TypeNamespace', '') or '')
        return (ns + '.' if ns else '') + str(tn)
    return str(getattr(cls, 'Name', '?') or '?')

def sval(tok):
    try:
        s = pe.net.user_strings.get(tok & 0xFFFFFF)
        return str(s.value) if s and s.value is not None else '?'
    except Exception:
        return '?'

if 0x060041ed in bodies:
    c, p = bodies[0x060041ed]
    ins = list(parse(il[p:p+c]))
    print('== 41ED (%dB, %d ins) ==' % (c, len(ins)))
    for off, name, k, op, plen in ins:
        if k == 'tok': print('  @%04x %-10s %s' % (off, name, mname(op)))
        elif k == 'str': print('  @%04x %-10s %r' % (off, name, sval(op)[:70]))
        elif k == 'sw': print('  @%04x %-10s [%d tgts]' % (off, name, len(op)))
        else: print('  @%04x %-10s %s' % (off, name, ('%x' % op) if op is not None else ''))
else:
    print('41ED not in index')
