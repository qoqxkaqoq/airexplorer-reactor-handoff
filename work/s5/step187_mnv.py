#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step187: 反查 m_RemoteNodeVal FieldDef token + 全库扫 stsfld/ldsfld 引用者。
目的: 找到写入者方法, 判定其是否落在可补丁面(4192/4196 原位真体)。"""
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

# 1) 找 m_RemoteNodeVal 字段 rid + 声明类型
target_rids = []
for i, f in enumerate(md.Field.rows, 1):
    if str(f.Name) == 'm_RemoteNodeVal':
        target_rids.append(i)
print('== Field "m_RemoteNodeVal" rids: %s ==' % [hex(r) for r in target_rids])

# 2) 声明类型归属（扫 TypeDef FieldList）
for r in target_rids:
    for ti, td in enumerate(md.TypeDef.rows, 1):
        try:
            for fl in td.FieldList:
                if fl.row_index == r:
                    print('  04:%06x declared by 02:%06x %s.%s' % (r, ti, td.TypeNamespace, td.TypeName))
                    break
        except Exception:
            continue

# 3) 全库扫引用 (stsfld/ldsfld/ldsflda + initobj 不可能)
if not target_rids:
    print('NO FIELD FOUND — abort'); sys.exit(1)
tokset = {0x04000000 | r for r in target_rids}
hits = []
for tok, (c, p) in bodies.items():
    try:
        ins = list(parse(il[p:p + c]))
    except Exception:
        continue
    for x in ins:
        off, name, k, op, plen = x
        if k == 'tok' and op in tokset and name in ('stsfld', 'ldsfld', 'ldsflda'):
            hits.append((tok, name, off))

print('== refs: %d ==' % len(hits))
mdef = md.MethodDef.rows
for tok, name, off in hits:
    r = tok & 0xFFFFFF
    try:
        mn = str(mdef[r - 1].Name)
        rva = mdef[r - 1].Rva
    except Exception:
        mn, rva = '?', 0
    print('  %s 06:%06x %s rva=%x @%04x' % (name, r, mn, rva, off))
