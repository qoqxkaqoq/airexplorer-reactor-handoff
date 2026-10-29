#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step186: 判定 4528/4523/4521/42AC/4555 在文件里是原位真体还是桩（文件级补丁可行性）。"""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
import dnfile

EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'

il = open(ALL, 'rb').read()
bodies = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        bodies[int(p[0], 16)] = (int(p[1]), int(p[4]))

pe = dnfile.dnPE(EXE)
data = pe.__data__
md = pe.net.mdtables

for rid in (0x4192, 0x4528, 0x4523, 0x4521, 0x42ac, 0x4555, 0x4581, 0x4196):
    tok = 0x06000000 | rid
    row = md.MethodDef.rows[rid - 1]
    rva = row.Rva
    name = str(row.Name)
    if rva == 0:
        print('06:%06x %s rva=0 (abstract/pinvoke?)' % (rid, name))
        continue
    off = pe.get_offset_from_rva(rva)
    hdr = data[off]
    if (hdr & 3) == 2:
        csize = hdr >> 2
        code_off = off + 1
        fat = False
    else:
        flags = int.from_bytes(data[off:off + 2], 'little')
        hsize = (flags >> 12) * 4
        csize = int.from_bytes(data[off + 4:off + 8], 'little')
        code_off = off + hsize
        fat = True
    fbody = bytes(data[code_off:code_off + 16])
    if tok in bodies:
        c, p = bodies[tok]
        dbody = il[p:p + 16]
        match = fbody == dbody and c >= 16
        print('06:%06x %-28s file: fat=%s csize=%-6d | dump len=%-6d | head-match=%s' % (rid, name, fat, csize, c, match))
        if csize <= 8:
            print('     file stub bytes: %s' % bytes(data[code_off:code_off + 8]).hex())
    else:
        print('06:%06x %-28s file: fat=%s csize=%-6d | NOT IN DUMP' % (rid, name, fat, csize))
