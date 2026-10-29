#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step177: ① 4192 全 switch/branch 臂 -> 0x0a72 路由点 (flat.py op 为十进制 rel)
② 检查函数族 41ce/41cf/41d0/41e9 + 4523 全 call 清单 -> 'AirExplorer ' (name+' ') 构造点"""
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
        if t == 0x06: return '0600%04x:%s' % (r, str(md.MethodDef.rows[r-1].Name))
        if t == 0x0A:
            m2 = md.MemberRef.rows[r-1]
            cn = m2.Class.row
            nm = getattr(cn, 'TypeName', None)
            full = (str(getattr(cn, 'TypeNamespace', '') or '') + '.' if nm else '') + str(nm or getattr(cn, 'Name', '?'))
            return '%s::%s' % (full, str(m2.Name))
        if t == 0x04: return 'fld:%06x:%s' % (r, str(md.Field.rows[r-1].Name))
        if t == 0x01: return 'td:%06x:%s' % (r, str(md.TypeDef.rows[r-1].TypeName))
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

c, p = bodies[0x06004192]
ins = list(parse(il[p:p+c]))

# ① all branch/switch targets
print('== 4192 edges -> 0x0a72 ==')
hits = 0
for off2, name, k, op, plen in ins:
    if k == 'br' and isinstance(op, int):
        tgt = off2 + plen + op
        if tgt == 0x0a72:
            print('  @%04x %s -> 0a72' % (off2, name)); hits += 1
    elif k in ('switch', 'sw') and hasattr(op, '__len__'):
        for rel in op:
            tgt = off2 + plen + rel
            if tgt == 0x0a72:
                print('  @%04x switch[%d] -> 0a72' % (off2, rel)); hits += 1
print('  hits=%d' % hits)
# sanity: list a few switch abs-target ranges
for off2, name, k, op, plen in ins:
    if k in ('switch', 'sw') and hasattr(op, '__len__') and off2 < 0x200:
        tgts = [off2 + plen + r for r in op]
        print('  [sanity] @%04x switch n=%d abs[min=%04x max=%04x] (csize=230a)' % (off2, len(op), min(tgts), max(tgts)))
        break

# ② dump check-family methods
def dump_meth(tok, tag=''):
    if tok not in bodies:
        print('== %06x %s: NOT IN DUMP ==' % (tok & 0xFFFFFF, tag)); return
    cc, pp = bodies[tok]
    print('== %06x %s %s: %d ins ==' % (tok & 0xFFFFFF, mname(tok), tag, cc))
    for off2, name, k, op, plen in parse(il[pp:pp+cc]):
        if k == 'tok': print('  @%04x %-10s %s' % (off2, name, mname(op)))
        elif k == 'str': print('  @%04x %-10s %r' % (off2, name, op))
        else: print('  @%04x %-10s %s' % (off2, name, ('%x' % op) if (op is not None and not hasattr(op, '__len__')) else ''))

for t in (0x41ce, 0x41cf, 0x41d0, 0x41e9):
    dump_meth(0x06000000 | t)

# ③ 4523 all calls
c2, p2 = bodies[0x06004523]
print('== 4523 all calls (%d ins) ==' % c2)
for off2, name, k, op, plen in parse(il[p2:p2+c2]):
    if k == 'tok' and (op >> 24) in (0x06, 0x0A, 0x2B, 0x2C):
        print('  @%04x %-10s %s' % (off2, name, mname(op)))
