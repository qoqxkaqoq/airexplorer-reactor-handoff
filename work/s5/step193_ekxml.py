#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step193: 4192 内 XML key 来源解剖——FromXmlString(@2250) 前后数据流。"""
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
        if t == 0x1B:
            return '1B:%06x:TypeSpec' % r
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

tok = 0x06004192
c, p = bodies[tok]
ins = list(parse(il[p:p + c]))
print('4192: %d ins csize=%d' % (len(ins), c))
byoff = {x[0]: x for x in ins}
offs = [x[0] for x in ins]

# FromXmlString @2250 前后各 40 条
import bisect
i0 = offs.index(0x2250)
lo, hi = max(0, i0 - 45), min(len(ins), i0 + 20)
print('== window around 2250 ==')
for x in ins[lo:hi]:
    off, name, k, op, plen = x
    s = '%04x: %s' % (off, name)
    if k == 'tok':
        s += ' ' + tname(op)
    elif op is not None:
        s += ' %s' % (op,)
    print('  ' + s)

# stsfld 001fcd @22ae 前后
i1 = offs.index(0x22ae)
print('== window around 22ae ==')
for x in ins[max(0, i1 - 8):i1 + 4]:
    off, name, k, op, plen = x
    s = '%04x: %s' % (off, name)
    if k == 'tok':
        s += ' ' + tname(op)
    elif op is not None:
        s += ' %s' % (op,)
    print('  ' + s)

# 4192 里所有 ldstr / ldtoken / 对字符串池的调用
print('== 4192 ldstr/ldtoken/ldsflda pool refs ==')
for x in ins:
    off, name, k, op, plen = x
    if name in ('ldstr', 'ldtoken'):
        print('  @%04x %s %s %s' % (off, name, k, tname(op) if k == 'tok' else hex(op)))
