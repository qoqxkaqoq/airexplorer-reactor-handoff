#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step155: global xref call 06004192 + 42AD full dump + 42AC/42AF/4290-429B census."""
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
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def sval(tok):
    try:
        s = pe.net.user_strings.get(tok & 0xFFFFFF)
        return str(s.value) if s and s.value is not None else '?'
    except Exception:
        return '?'

# ---- 1) global xref: any reference to 06004192 (call/ldtoken/ldftn)
print('===== global xref 06004192 (InstantiateGlobalCalculator) =====')
sites = []
for t, (c, p) in bodies.items():
    try:
        for off, name, k, op, plen in parse(il[p:p+c]):
            if k == 'tok' and op == 0x06004192:
                sites.append((t, off, name))
    except Exception:
        pass
for t, off, name in sorted(sites):
    nm = '?'
    try: nm = str(md.MethodDef.rows[(t & 0xFFFFFF)-1].Name)
    except Exception: pass
    print('   %08x (%06x %s) @%04x %s' % (t, t & 0xFFFFFF, nm, off, name))
print('   total=%d sites' % len(sites))

# ---- 2) 42AD full dump
for tok in (0x060042AD,):
    c2, p2 = bodies[tok]
    nm = '?'
    try: nm = str(md.MethodDef.rows[(tok & 0xFFFFFF)-1].Name)
    except Exception: pass
    print('\n===== %06x (%s) =====' % (tok, nm))
    for off, name, k, op, plen in parse(il[p2:p2+c2]):
        if k == 'tok':
            print('  @%04x %-12s %s' % (off, name, mname(op)))
        elif k == 'str':
            print('  @%04x %-12s %r' % (off, name, sval(op)[:80]))
        elif name == 'switch':
            print('  @%04x %-12s switch(%d)' % (off, name, len(op)))
        else:
            print('  @%04x %-12s %s' % (off, name, ('%x' % op) if op is not None else ''))

# ---- 3) census helper: MethodDef callees matching 419x/42Ax
import re as _re
def census(tok, tag):
    c3, p3 = bodies[tok]
    ins3 = list(parse(il[p3:p3+c3]))
    nm = '?'
    try: nm = str(md.MethodDef.rows[(tok & 0xFFFFFF)-1].Name)
    except Exception: pass
    cc = {}
    for off, name, k, op, plen in ins3:
        if k == 'tok' and name in ('call', 'callvirt', 'newobj') and (op >> 24) in (0x06, 0x0A):
            cc.setdefault(mname(op), []).append(off)
    hits = {n: v for n, v in cc.items() if _re.match(r'06:004(19|1a|1b|1c|1d|1e|1f|2a|2b)', n)}
    if hits:
        print('\n[%s %06x %s] %d ins, shell-family callees:' % (tag, tok, nm, len(ins3)))
        for n in sorted(hits):
            print('   %-56s @%s' % (n, ','.join('%04x' % x for x in hits[n][:6])))

for t in (0x060042AC, 0x060042AF, 0x06004290, 0x06004291, 0x06004292, 0x06004293,
          0x06004294, 0x06004295, 0x06004296, 0x06004297, 0x06004298, 0x06004299,
          0x0600429A, 0x0600429B, 0x06004264):
    if t in bodies:
        census(t, 'census')
