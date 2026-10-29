#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step175: a13d 判定后的两个问题。
① 4523 (GenerateAdaptableExtractor) 全 dump——'AirExplorer ' 新消息的构造点
   (a13: 'AirExplorer is tampered.' → a13d: 'AirExplorer ', 尾巴消失 = 消息由陷阱块区域参与构造)
② 4192 内跳向 0x0a72 (陷阱块入口) 的全部分支——第二哨兵的路由点 = 豁免补丁目标"""
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

# ---------- ① 4523 full dump ----------
for tok in (0x06004523, 0x06004521):
    if tok not in bodies:
        print('!! %06x not in dump' % (tok & 0xFFFFFF)); continue
    c, p = bodies[tok]
    ins = list(parse(il[p:p+c]))
    print('== %06x %s: %d ins ==' % (tok & 0xFFFFFF, mname(tok), len(ins)))
    thrown = 0
    for off2, name, k, op, plen in ins:
        if name in ('throw', 'rethrow') or (k == 'tok' and (op >> 24) == 0x0A and 'Exception' in mname(op)) or name == 'ldstr' or (name.startswith('br') and name != 'brtrue.s'):
            if name in ('throw', 'rethrow'): thrown += 1
            if name == 'ldstr':
                # resolve string from #US via token? flat.py str kind resolves op as offset
                print('  @%04x %-10s op=%r' % (off2, name, op if not hasattr(op, '__len__') else op))
            elif k == 'tok':
                print('  @%04x %-10s %s' % (off2, name, mname(op)))
            else:
                print('  @%04x %-10s %s' % (off2, name, ('%x' % op) if op is not None else ''))
    print('  (throws=%d)' % thrown)

# ---------- ② 4192 incoming branches -> 0x0a72 ----------
c, p = bodies[0x06004192]
ins = list(parse(il[p:p+c]))
print('== 4192 branches targeting 0x0a72 (trap entry) ==')
for off2, name, k, op, plen in ins:
    if not (name.startswith('br') or name.startswith('b') and name not in ('ldarg',)): continue
    if k == 'br' and op is not None and not hasattr(op, '__len__'):
        if off2 + plen + op == 0x0a72:
            print('  @%04x %s -> 0a72' % (off2, name))
    elif k == 'sw' and hasattr(op, '__len__'):
        for tgt in op:
            if off2 + plen + tgt == 0x0a72:
                print('  @%04x switch[] -> 0a72' % off2)

# also: any flow falling through INTO 0x0a72 (previous instruction ends at 0a72)
prev = None
for off2, name, k, op, plen in ins:
    if prev is not None and prev[0] + prev[4] == 0x0a72:
        print('  fall-through into 0a72: @%04x %s' % (prev[0], prev[1]))
    prev = (off2, name, k, op, plen)

# and check around 0af0 (ValidateGlobalParser branch per earlier note)
print('== 4192 @0ad0-0b60 window ==')
for off2, name, k, op, plen in ins:
    if 0x0ad0 <= off2 <= 0x0b60:
        if k == 'tok': print('  @%04x %-10s %s' % (off2, name, mname(op)))
        elif name == 'ldstr': print('  @%04x %-10s %r' % (off2, name, op))
        else: print('  @%04x %-10s %s' % (off2, name, ('%x' % op) if (op is not None and not hasattr(op, '__len__')) else ''))
