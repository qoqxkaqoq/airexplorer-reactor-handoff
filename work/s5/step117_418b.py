#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step117: full IL of 0600418b (blob loader) + who calls it + metadata."""
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

def fname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x04: return 'fld:%06x:%s' % (r, md.Field.rows[r-1].Name)
        return mname(tok)
    except Exception:
        return '%02x:%06x' % (t, r)

# metadata of 418b
m = md.MethodDef.rows[0x418b - 1]
print('[0600418b] Name=%r ImplFlags=%s Flags=%s RVA=%s' % (
    str(m.Name), m.ImplFlags, m.Flags, hex(m.Rva) if m.Rva else '0'))
print('  Sig=%s' % (m.Signature.__bytes__().hex() if hasattr(m.Signature, '__bytes__') else '?'))

# metadata of 4181 (cctor?)
m1 = md.MethodDef.rows[0x4181 - 1]
print('[06004181] Name=%r Flags=%s' % (str(m1.Name), m1.Flags))

# callers: scan all IL for call/callvirt/newobj/jmp 0600418b
TARGET_CALL = 0x0600418b
callers = []
for tok, (clen, pos) in bodies.items():
    try:
        ins = parse(il[pos:pos+clen])
    except Exception:
        continue
    for e in ins:
        if e[1] in ('call', 'callvirt', 'newobj', 'jmp') and e[2] == 'tok' and e[3] == TARGET_CALL:
            callers.append((tok, e[0]))
print('\n[callers of 0600418b] %d' % len(callers))
for tok, off in callers:
    print('   %08x %s @%04x' % (tok, mname(tok), off))
