#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step188: m_RemoteNodeVal 两处写入点上下文解剖 + 4181/419c 文件级补丁面判定。"""
import sys, struct
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

def tname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x02:
            row = md.TypeDef.rows[r - 1]
            return '02:%06x:%s.%s' % (r, row.TypeNamespace, row.TypeName)
        if t == 0x01:
            row = md.TypeRef.rows[r - 1]
            return '01:%06x:%s.%s' % (r, row.TypeNamespace, row.TypeName)
        if t == 0x06:
            return '06:%06x:%s' % (r, md.MethodDef.rows[r - 1].Name)
        if t == 0x0A:
            m2 = md.MemberRef.rows[r - 1]
            cn = m2.Class.row
            nm = getattr(cn, 'TypeName', None) or getattr(cn, 'Name', '?')
            ns = str(getattr(cn, 'TypeNamespace', '') or '')
            return '0A:%06x:%s%s%s::%s' % (r, ns, '.' if ns else '', nm, m2.Name)
        if t == 0x04:
            return '04:%06x:%s' % (r, md.Field.rows[r - 1].Name)
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

TARGET = 0x04001fbd

def ctx(tok, at, back=18, fwd=10, label=''):
    c, p = bodies[tok]
    ins = list(parse(il[p:p + c]))
    idx = next(i for i, x in enumerate(ins) if x[0] == at)
    print('== %s 06:%06x @%04x (csize=%d, ins=%d) ==' % (label, tok & 0xFFFFFF, at, c, len(ins)))
    for y in ins[max(0, idx - back):idx + fwd]:
        yo, yn, yk, yop, ypl = y
        mark = ' >>>' if yo == at else '    '
        s = '%s %s' % (yn, (' ' + tname(yop)) if yk == 'tok' else '')
        if yk == 'i':
            s += ' 0x%08x' % (yop & 0xFFFFFFFF)
        elif yk == 'i8':
            s += ' 0x%016x' % (yop & 0xFFFFFFFFFFFFFFFF)
        elif yk == 'b':
            s += ' %d' % (yop if yop < 128 else yop - 256)
        elif yk == 'br1':
            s += ' -> %04x' % yop
        elif yk == 'br4':
            s += ' -> %04x' % yop
        elif yk == 'str':
            s += ' 0x%08x' % (yop & 0xFFFFFFFF)
        print('%s @%04x %s' % (mark, yo, s))

ctx(0x06004181, 0x00d2, back=20, fwd=6, label='cctor initial write')
ctx(0x0600419c, 0x3daf, back=24, fwd=8, label='DefineEfficientProfiler overwrite')
print()
print('== readers ctx 419c @1993 / @22fb ==')
ctx(0x0600419c, 0x1993, back=8, fwd=6, label='read1')
ctx(0x0600419c, 0x22fb, back=8, fwd=6, label='read2')

# 文件级补丁面判定: 原位 IL vs dump 头匹配 (同 step186)
def method_bytes_at_rva(rva, n=12):
    off = pe.get_offset_from_rva(rva)
    d = pe.__data__
    return bytes(d[off:off + n])

def dump_head(tok):
    c, p = bodies[tok]
    return il[p:p + min(c, 12)], c

print()
print('== 文件级补丁面判定 (head 12B match) ==')
for tok, label in [(0x06004181, '4181 cctor'), (0x0600419c, '419c DefEffProfiler'), (0x06004192, '4192 InstantiateGlobalCalc'), (0x06004196, '4196')]:
    rva = md.MethodDef.rows[(tok & 0xFFFFFF) - 1].Rva
    fb = method_bytes_at_rva(rva)
    dh, csize = dump_head(tok)
    # fat 头: 12B 头后是 code; tiny: 1B
    def code_start(b):
        if b[0] & 3 == 2:
            return b[1:12], 1
        hs = ((b[0] >> 12) & 0xF) * 4
        return b[hs:hs + 11], hs
    fc, _ = code_start(fb)
    dc, _ = code_start(dh)
    match = fc == dc
    print('  %s rva=%x csize=%d file-head=%s dump-head=%s match=%s' % (
        label, rva, csize, fc.hex()[:22], dc.hex()[:22], match))
