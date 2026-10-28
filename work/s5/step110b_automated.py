#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step110b: dump 0600419C / 06004196 / 06004181 (automatedError consumers)
+ who calls them + what they decide. This is the 4192 -> 4528 state channel."""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse
import dnfile

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'

il = open(ALL, 'rb').read()
# robust parse: find header line, col layout tok/offset/.../size
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
        if t == 0x06: return '06:%06x:%s' % (r, md.MethodDef.rows[r-1].Name)
        if t == 0x0A:
            m = md.MemberRef.rows[r-1]; cls = m.Class.row
            return '0A:%s::%s' % (getattr(cls, 'TypeName', '?'), m.Name)
        if t == 0x04: return 'fld:%06x:%s' % (r, md.Field.rows[r-1].Name)
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def dump(tok, out, maxins=10**9):
    if tok not in bodies:
        print('[%06X] NOT IN DUMP' % (tok & 0xFFFFFF)); return None
    clen, pos = bodies[tok]
    if clen > 1000000 or clen <= 0:
        print('[%06X] bad size %d -> scan il_index row again' % (tok & 0xFFFFFF, clen)); return None
    ins = list(parse(il[pos:pos+clen]))
    print('[%06X] size=%d ins=%d' % (tok & 0xFFFFFF, clen, len(ins)))
    with open(out, 'w') as f:
        for e in ins:
            f.write('%04x %s\n' % (e[0], e))
    return ins

for tk in (0x0600419C, 0x06004196, 0x06004181):
    ins = dump(tk, '/tmp/step110b_%04x.txt' % (tk & 0xFFFF))
    if ins is None:
        # try locate by searching index rows for the token
        continue
    # show all automatedError ops with context
    print('  --- automatedError sites ---')
    for i, e in enumerate(ins):
        if e[2] == 'tok' and (e[3] & 0xFFFFFF) == 0x001FBE:
            lo = max(0, i-4); hi = min(len(ins), i+6)
            for x in ins[lo:hi]:
                mark = '>>' if x[0] == e[0] else '  '
                op = x[3] if x[2] in ('tok', 'br', 'br4', 'i') else ''
                print('   %s %04x %s %s' % (mark, x[0], x[1], op))
            print('   ---')

# who calls these three?
print('\n=== callers of 419C/4196/4181 (scan all dump bodies) ===')
TARGETS = {0x0600419C: '419C', 0x06004196: '4196', 0x06004181: '4181'}
pos2tok = sorted((o, t) for t, (o, s) in bodies.items())
import bisect
starts = [o for o, _ in pos2tok]
found = 0
scan = 0
for off in range(0, len(il) - 4):
    # cheap: find call tokens 28 xx xx 00 06 / 6f xx xx 00 06 / 73 xx xx 00 06
    b0 = il[off]
    if b0 in (0x28, 0x6f, 0x73) and il[off+3] == 0x00 and il[off+4] == 0x06:
        tk = 0x06000000 | (il[off+1] | (il[off+2] << 8))
        if tk in TARGETS:
            j = bisect.bisect_right(starts, off) - 1
            owner = pos2tok[j][1] if j >= 0 and off < pos2tok[j][0] + bodies[pos2tok[j][1]][1] else None
            print('  call %s from %08X @il_off=0x%x' % (TARGETS[tk], owner or 0, off))
            found += 1
            scan += 1
print('total call sites:', found)
