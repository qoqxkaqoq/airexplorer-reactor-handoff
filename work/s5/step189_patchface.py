#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step189: 修正版文件级补丁面判定 — 文件 fat 头后的 code 与 dump IL 对齐比较。"""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
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
d = pe.__data__

def file_code(rva, want):
    off = pe.get_offset_from_rva(rva)
    b = bytes(d[off:off + 16 + want])
    if b[0] & 3 == 2:
        return b[1:1 + want], 1, (b[0] >> 2) & 0x3F
    flags = b[0] | (b[1] << 8)
    hs = (flags >> 12) * 4
    csize = int.from_bytes(b[4:8], 'little')
    return b[hs:hs + want], hs, csize

for tok in (0x06004181, 0x0600419c, 0x06004192, 0x06004196, 0x06004528, 0x0600423c):
    r = tok & 0xFFFFFF
    rva = md.MethodDef.rows[r - 1].Rva
    if tok not in bodies:
        print('06:%06x NOT IN DUMP' % r); continue
    csize, p = bodies[tok]
    fc, hs, fcs = file_code(rva, min(csize, 32))
    dc = il[p:p + min(csize, 32)]
    ndiff = sum(1 for a, b in zip(fc, dc) if a != b)
    print('06:%06x csize=%d fileCodeSize=%d headDiff=%d/32  file=%s dump=%s' % (
        r, csize, fcs, ndiff, fc[:16].hex(), dc[:16].hex()))
