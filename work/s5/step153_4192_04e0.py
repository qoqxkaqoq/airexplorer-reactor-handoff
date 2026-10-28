#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step153: 4192 body around @04e0 (a13 patch site semantics) + switch-safe dump 428B-428F."""
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

def pr(off, name, k, op, plen):
    if k == 'tok':
        print('  @%04x %-12s %s' % (off, name, mname(op)))
    elif k == 'str':
        print('  @%04x %-12s %r' % (off, name, sval(op)[:80]))
    elif name == 'switch':
        print('  @%04x %-12s switch(%d targets) first=%s' % (off, name, len(op), ['%x' % x for x in op[:6]]))
    else:
        print('  @%04x %-12s %s' % (off, name, ('%x' % op) if op is not None else ''))

# ---- 1) 4192 window @0400-@0600 (patch site context)
c, p = bodies[0x06004192]
print('===== 4192 window @0400-@0600 =====')
for off, name, k, op, plen in parse(il[p:p+c]):
    if 0x0400 <= off <= 0x0600:
        pr(off, name, k, op, plen)

# ---- 2) loc12 (index 12) ALL reads/writes in 4192
print('\n===== 4192 loc12 stloc/ldloc sites =====')
for off, name, k, op, plen in parse(il[p:p+c]):
    if name in ('stloc', 'ldloc', 'stloc.s', 'ldloc.s', 'ldloca.s', 'ldloca') and op == 12:
        print('  @%04x %s' % (off, name))
    if name in ('stloc', 'ldloc') and op == 12:
        print('  @%04x %s (long)' % (off, name))

# ---- 3) switch-safe dump 428B-428F
for tok in (0x0600428B, 0x0600428C, 0x0600428D, 0x0600428E, 0x0600428F):
    if tok not in bodies:
        print('\n[%06x] MISSING' % tok); continue
    c2, p2 = bodies[tok]
    ins = list(parse(il[p2:p2+c2]))
    nm = '?'
    try: nm = str(md.MethodDef.rows[(tok & 0xFFFFFF)-1].Name)
    except Exception: pass
    print('\n===== %06x (%s) clen=%d ins=%d =====' % (tok, nm, c2, len(ins)))
    for off, name, k, op, plen in ins:
        pr(off, name, k, op, plen)

# ---- 4) who references 428E/428D/428F (delegate wiring)
print('\n[xref 428D/428E/428F any-ref]:')
TARGETS = {0x0600428D, 0x0600428E, 0x0600428F, 0x0600428B}
for t, (c3, p3) in bodies.items():
    try:
        for off, name, k, op, plen in parse(il[p3:p3+c3]):
            if k == 'tok' and op in TARGETS:
                print('   %08x @%04x %s -> %06x' % (t, off, name, op))
    except Exception:
        pass
