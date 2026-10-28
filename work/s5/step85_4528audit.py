#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step85: audit 06004528's 74 throws - what do its checks test?
Does it call 06004192-family (dead guard1)? What precedes each throw?"""
import sys, struct
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse

EXE = '/workspace/repo_git/exes/AirExplorer_a1.exe'
IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'

il = open(ALL, 'rb').read()
idx = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        idx[int(p[0], 16)] = (int(p[1]), int(p[4]))

import dnfile
pe = dnfile.dnPE(EXE)
md = pe.net.mdtables

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06:
            return str(md.MethodDef.rows[r - 1].Name)
        if t == 0x0A:
            row = md.MemberRef.rows[r - 1]
            cn = '?'
            try:
                c = row.Class
                r2 = c.row if hasattr(c, 'row') else c
                if hasattr(r2, 'TypeName'):
                    cn = (str(r2.TypeNamespace) + '.' if str(r2.TypeNamespace) else '') + str(r2.TypeName)
            except Exception:
                pass
            return cn + '::' + str(row.Name)
    except Exception:
        return '<err>'
    return hex(tok)

b = il[idx[0x06004528][1]:idx[0x06004528][1] + idx[0x06004528][0]]
ins = parse(b)
print('[4528] len=%d ins=%d' % (len(b), len(ins)))

# 1) does it call guard1 family?
fam = [0x06004192, 0x0600419C, 0x06004194, 0x06004523, 0x06004524, 0x060041FA]
for e in ins:
    if e[1] in ('call', 'callvirt'):
        t = struct.unpack_from('<I', b, e[0] + 1)[0]
        if t in fam:
            print('  CALLS-GUARD %04x %s' % (e[0], hex(t)))

# 2) throw contexts
throws = [i for i, e in enumerate(ins) if e[1] == 'throw']
print('[4528] throws=%d' % len(throws))
pats = {}
for k in throws:
    o = ins[k][0]
    pre = ins[max(0, k - 10):k]
    sig = tuple(c[1] for c in pre)
    pats[sig] = pats.get(sig, 0) + 1
for sig, n in sorted(pats.items(), key=lambda x: -x[1])[:8]:
    print('  pattern x%d: %s' % (n, ' '.join(sig)))

# 3) what tokens appear right before throws (calls + ldfld/ldsfld)
tokcnt = {}
for k in throws:
    for c in ins[max(0, k - 10):k]:
        if c[1] in ('call', 'callvirt', 'newobj'):
            t = struct.unpack_from('<I', b, c[0] + 1)[0]
            tokcnt.setdefault(mname(t), set()).add(c[1])
        if c[1].startswith('ld') and 'fld' in c[1]:
            tokcnt.setdefault('fld@' + hex(struct.unpack_from('<I', b, c[0] + 1)[0]), set()).add(c[1])
print('[4528] tokens near throws:')
for n, ks in sorted(tokcnt.items(), key=lambda x: -len(x[1])):
    print('  %-60s x%d' % (n[:60], len(ks)))

# 4) ldsfld/ldfld count overall - where does state come from
flds = {}
for e in ins:
    if e[1] in ('ldsfld', 'stsfld'):
        t = struct.unpack_from('<I', b, e[0] + 1)[0]
        flds[t] = flds.get(t, 0) + 1
print('[4528] static fields uniq=%d' % len(flds))
for t, n in sorted(flds.items(), key=lambda x: -x[1])[:12]:
    print('  %s x%d' % (hex(t), n))
