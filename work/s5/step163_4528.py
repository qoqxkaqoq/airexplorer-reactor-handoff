#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step163: 4528 DefineSetSet (27546B) — full IL to file + trap-condition analysis.
Goals: (1) find newobj/call Exception sites & their guarding condition;
       (2) find message source (ldstr / pool-service calls with int idx);
       (3) ldsfld census (what state the checks read)."""
import sys, re
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse
import dnfile

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
OUT = '/workspace/repo_git/work/s5/out163_4528.il'

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

def dump(tok, label):
    c, p = bodies[tok]
    ins = list(parse(il[p:p+c]))
    with open(OUT if tok == 0x06004528 else OUT + '.' + '%06x' % (tok & 0xFFFF), 'w') as f:
        for off, name, k, op, plen in ins:
            if k == 'tok':
                f.write('@%04x %-12s %s\n' % (off, name, mname(op)))
            elif k == 'str':
                f.write('@%04x %-12s %r\n' % (off, name, sval(op)))
            elif k in ('switch', 'sw'):
                f.write('@%04x %-12s [%d targets]\n' % (off, name, len(op) if hasattr(op, '__len__') else 0))
            else:
                f.write('@%04x %-12s %s\n' % (off, name, ('%x' % op) if op is not None else ''))
    print('[%s] clen=%d ins=%d -> file written' % (label, c, len(ins)))
    return ins

ins4528 = dump(0x06004528, '4528')
ins4521 = dump(0x06004521, '4521')
ins448f = dump(0x0600448F, '448F')

# ---- 4521 full (86B, small) ----
print('== 4521 PlanRunner full ==')
for off, name, k, op, plen in ins4521:
    if k == 'tok': print('  @%04x %-10s %s' % (off, name, mname(op)))
    elif k == 'str': print('  @%04x %-10s %r' % (off, name, sval(op)[:60]))
    elif k in ('switch', 'sw'): print('  @%04x %-10s [%d targets]' % (off, name, len(op) if hasattr(op, '__len__') else 0))
    else: print('  @%04x %-10s %s' % (off, name, ('%x' % op) if op is not None else ''))

# ---- 448F full (22B) ----
print('== 448F .ctor full ==')
for off, name, k, op, plen in ins448f:
    if k == 'tok': print('  @%04x %-10s %s' % (off, name, mname(op)))
    elif k in ('switch', 'sw'): print('  @%04x %-10s [%d targets]' % (off, name, len(op) if hasattr(op, '__len__') else 0))
    else: print('  @%04x %-10s %s' % (off, name, ('%x' % op) if op is not None else ''))

# ---- 4528 analysis ----
print('== 4528: throw sites with 6-instr context ==')
idx = {i: x for i, x in enumerate(ins4528)}
for i, (off, name, k, op, plen) in enumerate(ins4528):
    if name in ('throw', 'rethrow'):
        for j in range(max(0, i-8), min(len(ins4528), i+1)):
            o, n, kk, oo, _ = ins4528[j]
            if kk == 'tok': print('  @%04x %-10s %s' % (o, n, mname(oo)))
            elif kk == 'str': print('  @%04x %-10s %r' % (o, n, sval(oo)[:60]))
            else: print('  @%04x %-10s %s' % (o, n, ('%x' % oo) if oo is not None else ''))
        print('  ---')

print('== 4528: ldstr census (all) ==')
for off, name, k, op, plen in ins4528:
    if k == 'str':
        v = sval(op)
        print('  @%04x %r' % (off, v[:80]))

print('== 4528: newobj sites ==')
for off, name, k, op, plen in ins4528:
    if name == 'newobj' and k == 'tok':
        print('  @%04x newobj %s' % (off, mname(op)))

print('== 4528: ldsfld census ==')
fs = {}
for off, name, k, op, plen in ins4528:
    if name in ('ldsfld', 'stsfld') and k == 'tok':
        fs.setdefault(mname(op), []).append((off, name))
for n in sorted(fs):
    print('  %-60s %s' % (n, ','.join('%s@%04x' % (x[1][:3], x[0]) for x in fs[n][:10])))

print('== 4528: pool-service call sites (41ex/42ax/419x targets with ldc.i4 imm before) ==')
POOLS = re.compile(r'06:00(41e|41f|419|42a|42b)', re.I)
for i, (off, name, k, op, plen) in enumerate(ins4528):
    if k == 'tok' and name in ('call', 'callvirt') and POOLS.search(mname(op)):
        # look back 2 instructions for int constant
        prev = ins4528[i-1] if i >= 1 else None
        pv = ''
        if prev and prev[1] in ('ldc.i4', 'ldc.i4.s', 'ldc.i4.1', 'ldc.i4.0'):
            pv = 'imm=%s' % (('%x' % prev[3]) if prev[3] is not None else prev[1])
        print('  @%04x call %s  %s' % (off, mname(op), pv))
