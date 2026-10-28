#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step88: (1) name key fields of 4528; (2) RVA-like ldc.i4 constants inside
4528 (method-body hash walk evidence); (3) locate 06004409/4559 status."""
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

# --- 1) field names ---
def fname(tok):
    r = tok & 0xFFFFFF
    try:
        f = md.Field.rows[r - 1]
        return str(f.Name)
    except Exception:
        return '<err>'
for t in (0x4002012, 0x4002048, 0x4002074, 0x4002129, 0x4002d89, 0x4002185, 0x4002d83, 0x4002d9d):
    print('[fld] %s = %s' % (hex(t), fname(t)))

# --- 2) 4528 constants ---
b = il[idx[0x06004528][1]:idx[0x06004528][1] + idx[0x06004528][0]]
ins = parse(b)
# build RVA set from MethodDef
rvas = {}
for i, row in enumerate(md.MethodDef.rows):
    if row.Rva:
        rvas[row.Rva] = 0x06000001 + i
const = {}
for e in ins:
    if e[1] in ('ldc.i4', 'ldc.i4.s'):
        v = struct.unpack_from('<I', b, e[0] + 1)[0] if e[1] == 'ldc.i4' else b[e[0] + 1]
        if isinstance(v, int) and v >= 0x1000:
            const[v] = const.get(v, 0) + 1
big = {v: n for v, n in const.items() if v >= 0x100000}
rva_hits = {v: n for v, n in const.items() if v in rvas}
print('[4528] const>=0x100000: %d uniq; RVA-matching consts: %d' % (len(big), len(rva_hits)))
for v, n in sorted(rva_hits.items())[:40]:
    print('  rva=%#x tok=%s x%d' % (v, hex(rvas[v]), n))

# --- 3) 06004409/06004559 status ---
for t in (0x06004409, 0x06004559, 0x0600457F, 0x06004580, 0x06004581):
    r = t & 0xFFFFFF
    row = md.MethodDef.rows[r - 1]
    inidx = t in idx
    print('[m] %s name=%s rva=%#x in_dump=%s' % (hex(t), row.Name, row.Rva, inidx))
    if inidx:
        cl, pos = idx[t]
        print('     dump len=%d' % cl)

# --- 4) whose type are 4523/4524/4528 (name it properly) ---
rid28 = 0x06004528 - 0x06000001
for td in md.TypeDef.rows:
    ml = [m.row if hasattr(m, 'row') else m for m in td.MethodList]
    toks = set()
    for m in ml:
        try:
            toks.add(0x06000001 + md.MethodDef.rows.index(m))
        except Exception:
            pass
    if 0x06004528 in toks:
        print('[type of 4528] %s.%s methods=%d' % (td.TypeNamespace, td.TypeName, len(toks)))
