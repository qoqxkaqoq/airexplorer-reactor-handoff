#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step160: who calls 4528 + 42AC dispatch structure (feature 0x2c path) + 42B0 census."""
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
            m2 = md.MemberRef.rows[r-1]
            return '%s::%s' % (clsname(m2.Class.row), str(m2.Name))
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

# ---- 1) xref 4528
print('[xref 06004528]:')
for t, (c, p) in bodies.items():
    try:
        for off, name, k, op, plen in parse(il[p:p+c]):
            if k == 'tok' and op == 0x06004528:
                nm = '?'
                try: nm = str(md.MethodDef.rows[(t & 0xFFFFFF)-1].Name)
                except Exception: pass
                print('   %08x (%s) @%04x %s' % (t, nm, off, name))
    except Exception:
        pass

# ---- 2) 42AC head + branch census (feature dispatch)
c, p = bodies[0x060042AC]
ins = list(parse(il[p:p+c]))
print('\n[42AC] %d ins — head @0000-0050:' % len(ins))
for off, name, k, op, plen in ins:
    if off <= 0x50:
        if k == 'tok': print('  @%04x %-12s %s' % (off, name, mname(op)))
        elif k == 'str': print('  @%04x %-12s %r' % (off, name, sval(op)[:70]))
        elif name == 'switch': print('  @%04x %-12s switch(%d) t[:8]=%s' % (off, name, len(op), ['%x' % x for x in op[:8]]))
        else: print('  @%04x %-12s %s' % (off, name, ('%x' % op) if op is not None else ''))

# find where 0x2c feature leads: locate branch compares with 0x2c constant near ldarg.0
print('\n[42AC] ldc 0x2c sites context:')
for i, (off, name, k, op, plen) in enumerate(ins):
    if name in ('ldc.i4', 'ldc.i4.s') and op in (0x2c, 44):
        for j in range(max(0, i-2), min(len(ins), i+6)):
            o2, n2, k2, op2, pl2 = ins[j]
            if k2 == 'tok': print('  @%04x %-12s %s' % (o2, n2, mname(op2)))
            elif k2 == 'str': print('  @%04x %-12s %r' % (o2, n2, sval(op2)[:60]))
            elif n2 == 'switch': print('  @%04x %-12s switch(%d)' % (o2, n2, len(op2)))
            else: print('  @%04x %-12s %s' % (o2, n2, ('%x' % op2) if op2 is not None else ''))
        print('  ---')

# ---- 3) 42B0 census (reflection consumer)
c3, p3 = bodies[0x060042B0]
ins3 = list(parse(il[p3:p3+c3]))
print('\n[42B0] %d ins — all callees:' % len(ins3))
for off, name, k, op, plen in ins3:
    if k == 'tok' and name in ('call', 'callvirt', 'newobj'):
        print('  @%04x %-12s %s' % (off, name, mname(op)))
