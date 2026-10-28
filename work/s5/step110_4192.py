#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step110: dump 06004192 InstantiateGlobalCalculator in full.
Hypothesis: baseline VerifyHash returns FALSE (res5 = pubkey only, sig has no
matching private key) -> ceq makes loc12 = 1 = "expected" state. a7c flipped
shim returns 1 -> loc12 = 0 = anomaly -> 4192 writes anomaly flag to a static
-> 4528 reads it -> throw. Verify: (1) loc12 consumption branches, (2) stsfld
set in 4192, (3) intersection with 4528's ldsfld set."""
import sys, struct
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
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

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06:
            return '06:%06x:%s' % (r, md.MethodDef.rows[r-1].Name)
        if t == 0x0A:
            m = md.MemberRef.rows[r-1]
            cls = m.Class.row
            cn = getattr(cls, 'TypeName', getattr(cls, 'Name', '?'))
            return '0A:%s::%s' % (cn, m.Name)
        if t == 0x04:
            return 'fld:%06x:%s' % (r, md.Field.rows[r-1].Name)
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def dump(tok, out):
    clen, pos = bodies[tok]
    ins = list(parse(il[pos:pos+clen]))
    print('[%06X] size=%d ins=%d' % (tok & 0xFFFFFF, clen, len(ins)))
    with open(out, 'w') as f:
        for i, e in enumerate(ins):
            f.write('%04x %s\n' % (e[0], e))
    return ins

ins = dump(0x06004192, '/tmp/step110_4192.txt')

# (1) stsfld set in 4192
sts = {}
for e in ins:
    if e[1] in ('stsfld', 'ldsfld') and e[2] == 'tok':
        sts.setdefault(e[3], []).append(e[0])
print('\n[4192] stsfld targets:')
for t, a in sorted(sts.items()):
    kind = 'W' if any(True for _ in a) else ''
    print('   %s (%s) @%s' % (mname(t), hex(t), ','.join('%04x' % x for x in a[:6])))

# (2) loc12 (local slot 12) consumption: find ldloc 12 after the ceq @04e3
# loc index: stloc.s 12 @04e3 -> find all 'ldloc' with operand 12
print('\n[4192] ldloc slot-12 sites:')
for i, e in enumerate(ins):
    if e[1].startswith('ldloc') and e[2] == 'n' and e[3] == 12:
        ctx = ' | '.join('%s %s' % (x[1], x[3] if x[2] == 'tok' else '') for x in ins[max(0,i-2):i+4])
        print('   @%04x  %s' % (e[0], ctx))

# (3) full window around the VerifyHash site @04db and state-var writes after
print('\n[4192] window @04b0..0560:')
for e in ins:
    if 0x04b0 <= e[0] <= 0x0560:
        op = e[3] if e[2] == 'tok' else (e[3] if e[2] in ('br', 'br4', 'brs') else '')
        print('   %04x %s %s' % (e[0], e[1], op))
