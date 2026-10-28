#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step156: 4192 @0970-@0a90 — the loc12 consumption block (healthy vs poison path semantics)."""
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

c, p = bodies[0x06004192]
print('===== 4192 window @0970-@0aa0 (loc12 consumption) =====')
for off, name, k, op, plen in parse(il[p:p+c]):
    if 0x0970 <= off <= 0x0aa0:
        if k == 'tok':
            print('  @%04x %-12s %s' % (off, name, mname(op)))
        elif k == 'str':
            print('  @%04x %-12s %r' % (off, name, sval(op)[:80]))
        elif name == 'switch':
            print('  @%04x %-12s switch(%d) targets[:8]=%s' % (off, name, len(op), ['%x' % x for x in op[:8]]))
        else:
            print('  @%04x %-12s %s' % (off, name, ('%x' % op) if op is not None else ''))

# also: what happens right after @09f4 branch targets — trace @0a70-@0a80 throw block
print('\n===== 4192 loc13 (SHA1 inst, idx 13) & hash-bytes consumption in whole 4192 =====')
for off, name, k, op, plen in parse(il[p:p+c]):
    if name in ('stloc', 'ldloc', 'stloc.s', 'ldloc.s', 'ldloca', 'ldloca.s') and op == 13:
        print('  @%04x %s loc13' % (off, name))

# jump targets resolution for the two branches at @09f4: list instructions at 0x0a72/0x0a77 etc
print('\n===== 4192 window @0aa0-@0b40 (after consumption block) =====')
for off, name, k, op, plen in parse(il[p:p+c]):
    if 0x0aa0 <= off <= 0x0b40:
        if k == 'tok':
            print('  @%04x %-12s %s' % (off, name, mname(op)))
        elif k == 'str':
            print('  @%04x %-12s %r' % (off, name, sval(op)[:80]))
        elif name == 'switch':
            print('  @%04x %-12s switch(%d)' % (off, name, len(op)))
        else:
            print('  @%04x %-12s %s' % (off, name, ('%x' % op) if op is not None else ''))
