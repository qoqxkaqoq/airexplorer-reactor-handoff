#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step119: sanity check the caller-scan: 41ED is known to be called by 4192 @04d2.
Also verify 0600418b is in the index, and dump its full disasm."""
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

print('[index] 0600418b in bodies:', 0x0600418b in bodies)
print('[index] 06004192 in bodies:', 0x06004192 in bodies)
print('[index] total:', len(bodies))

pe = dnfile.dnPE(EXE)
md = pe.net.mdtables

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06: return '06:%06x:%s' % (r, md.MethodDef.rows[r-1].Name)
        if t == 0x0A:
            m = md.MemberRef.rows[r-1]
            cls = m.Class.row
            return '0A:%s::%s' % (getattr(cls, 'TypeName', '?'), m.Name)
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

# sanity: who calls 41ED / 41EE across all IL
for TGT, nm in ((0x060041ED, 'VerifyVirtualMatcher'), (0x060041EE, 'VerifyDynamicStrategy')):
    refs = []
    for tok, (clen, pos) in bodies.items():
        try:
            ins = parse(il[pos:pos+clen])
        except Exception:
            continue
        for e in ins:
            if e[1] in ('call', 'callvirt', 'ldftn', 'ldvirtftn') and e[2] == 'tok' and e[3] == TGT:
                refs.append((tok, e[0], e[1]))
    print('\n[refs to 0600%04x %s] %d' % (TGT & 0xFFFF, nm, len(refs)))
    for tok, off, op in refs:
        print('   %08x %s @%04x (%s)' % (tok, mname(tok), off, op))

# dump 418b full body to /tmp for reading
clen, pos = bodies[0x0600418b]
ins = list(parse(il[pos:pos+clen]))
with open('/tmp/step119_00418b.txt', 'w') as f:
    for e in ins:
        off, name, k, op, plen = e
        ann = ''
        if k in ('tok', 'str'):
            ann = ' ' + mname(op)
        elif k in ('br4', 'br1'):
            ann = ' -> %04x' % op
        elif k == 'sw':
            ann = ' -> ' + ','.join('%04x' % t for t in op)
        elif k == 'var':
            ann = ' %s' % op
        elif k == 'b':
            ann = ' %d' % op
        f.write('%04x %s%s\n' % (off, name, ann))
print('\n[418b dump] size=%d ins=%d -> /tmp/step119_00418b.txt' % (clen, len(ins)))
