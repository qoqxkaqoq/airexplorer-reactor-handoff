#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step161: upstream of 4523 (who calls it, recursive) + _AdjustableTransformerElements writers + 42AC calc path."""
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
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def sval(tok):
    try:
        s = pe.net.user_strings.get(tok & 0xFFFFFF)
        return str(s.value) if s and s.value is not None else '?'
    except Exception:
        return '?'

# ---- 1) recursive upstream of 4523: who calls 06004523 (depth up to 3)
def xref_callers(tok):
    out = []
    for t, (c, p) in bodies.items():
        try:
            for off, name, k, op, plen in parse(il[p:p+c]):
                if k == 'tok' and op == tok and name in ('call', 'callvirt', 'newobj', 'ldftn', 'ldtoken'):
                    out.append((t, off, name))
        except Exception:
            pass
    return out

frontier = [0x06004523]
seen = set()
for depth in range(3):
    nxt = []
    for tok in frontier:
        if tok in seen: continue
        seen.add(tok)
        callers = xref_callers(tok)
        print('[depth%d] callers of %06x: %d' % (depth, tok, len(callers)))
        for t, off, name in callers[:15]:
            nm = '?'
            try: nm = str(md.MethodDef.rows[(t & 0xFFFFFF)-1].Name)
            except Exception: pass
            print('   %08x (%06x %s) @%04x %s' % (t, t & 0xFFFFFF, nm, off, name))
            nxt.append(t)
        if len(callers) > 15: print('   ... +%d' % (len(callers)-15))
    frontier = [x for x in nxt if x not in seen][:8]
    if not frontier: break

# ---- 2) _AdjustableTransformerElements fld:001feb all writers
print('\n[writers of fld:001feb _AdjustableTransformerElements]:')
FLD = 0x04001FEB
for t, (c, p) in bodies.items():
    try:
        for off, name, k, op, plen in parse(il[p:p+c]):
            if k == 'tok' and op == FLD and name in ('stsfld', 'ldsfld'):
                nm = '?'
                try: nm = str(md.MethodDef.rows[(t & 0xFFFFFF)-1].Name)
                except Exception: pass
                print('   %08x (%06x %s) @%04x %s' % (t, t & 0xFFFFFF, nm, off, name))
    except Exception:
        pass

# ---- 3) 42AC calc path @0048-0180
c, p = bodies[0x060042AC]
ins = list(parse(il[p:p+c]))
print('\n[42AC calc path @0048-0180]:')
for off, name, k, op, plen in ins:
    if 0x48 <= off <= 0x180:
        if k == 'tok': print('  @%04x %-12s %s' % (off, name, mname(op)))
        elif k == 'str': print('  @%04x %-12s %r' % (off, name, sval(op)[:70]))
        elif name == 'switch': print('  @%04x %-12s switch(%d)' % (off, name, len(op)))
        else: print('  @%04x %-12s %s' % (off, name, ('%x' % op) if op is not None else ''))
