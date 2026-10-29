#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step185: 解剖 06:004555 HandleAutomatableConnection（池异常提供者）+
4528 @3538 throw 块的分支前驱（补丁点）+ 全库 xref。"""
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
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def dump_body(tok, lo=None, hi=None, label=''):
    if tok not in bodies:
        print('== %s %s: NOT IN DUMP ==' % (tok, label))
        return None
    c, p = bodies[tok]
    ins = list(parse(il[p:p + c]))
    print('== %s %s: %d ins ==' % (label, tname(tok), len(ins)))
    for off, name, k, op, plen in ins:
        if lo is not None and not (lo <= off <= hi):
            continue
        if k == 'tok':
            print('  @%04x %-10s %s' % (off, name, tname(op)))
        elif k == 'str':
            print('  @%04x %-10s ldstr' % (off, name))
        elif k == 'sw':
            print('  @%04x %-10s switch(%d)' % (off, name, len(op)))
        elif k == 'i':
            print('  @%04x %-10s %d (0x%x)' % (off, name, op, op & 0xFFFFFFFF))
        elif k == 'b':
            print('  @%04x %-10s %d' % (off, name, op))
        elif k == 'br1' or k == 'br4':
            print('  @%04x %-10s -> %04x' % (off, name, op))
        else:
            print('  @%04x %-10s' % (off, name))
    return ins

# 1) 06:004555 全体
ins555 = dump_body(0x06004555, label='HandleAutomatableConnection')

# 2) 全库 xref 4555（call/callvirt/ldftn）
print('== xref 06004555 ==')
for tok in sorted(bodies):
    c2, p2 = bodies[tok]
    try:
        ins2 = list(parse(il[p2:p2 + c2]))
    except Exception:
        continue
    for off, name, k, op, plen in ins2:
        if k == 'tok' and op == 0x06004555 and name in ('call', 'callvirt', 'ldftn', 'jmp'):
            print('  %s @%s @%04x' % (tname(tok), name, off))

# 3) 4528 @3538 块字节与分支前驱
c3, p3 = bodies[0x06004528]
ins3 = list(parse(il[p3:p3 + c3]))
print('== 4528 @34e0-3560 window ==')
for off, name, k, op, plen in ins3:
    if 0x34e0 <= off <= 0x3560:
        if k == 'tok':
            print('  @%04x %-10s %s' % (off, name, tname(op)))
        elif k in ('br1', 'br4'):
            print('  @%04x %-10s -> %04x' % (off, name, op))
        else:
            print('  @%04x %-10s' % (off, name))
print('== 4528 branches targeting 0x3538 ==')
for off, name, k, op, plen in ins3:
    if k in ('br1', 'br4') and op == 0x3538:
        print('  @%04x %s -> 3538' % (off, name))
    if k == 'sw':
        for t2 in op:
            if t2 == 0x3538:
                print('  @%04x switch -> 3538' % off)
