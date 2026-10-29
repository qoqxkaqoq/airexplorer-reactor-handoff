#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step183: 'AirExplorer ' 守卫追击。
① 135 个 Exception 构造点紧凑清单（方法名+ctor 签名）
② 0A:00010e / 0A:000252 签名 blob 解码
③ 42AC @05c8/@06bc 宽窗（找消息推送者）
④ 02:000660 (.ydb9FG3vNekLADseUvw) 结构体 + ToString 覆写检查"""
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

# ② ctor 签名按栈形定案：0A:000252 = .ctor(string)（4194 'Debugger Detected' 用法）；
#    0A:00010e = .ctor() 无参（42AC blt 后直接 newobj，无字符串入栈）

# ① 紧凑清单
exc_refs = set()
for i, m2 in enumerate(md.MemberRef.rows, 1):
    try:
        cn = m2.Class.row
        if str(getattr(cn, 'TypeName', '')) == 'Exception' and str(getattr(cn, 'TypeNamespace', '')) == 'System':
            exc_refs.add(0x0A000000 | i)
    except Exception:
        pass

hits = []
for tok in sorted(bodies):
    c, p = bodies[tok]
    try:
        ins = list(parse(il[p:p + c]))
    except Exception:
        continue
    for i, x in enumerate(ins):
        if x[1] == 'newobj' and (x[3] in exc_refs or (x[3] >> 24) == 0x06):
            # 0x06 子类 ctor 略过：仅列直连 MemberRef
            if x[3] in exc_refs:
                hits.append((tok, x[0], x[3]))
print('== compact: %d direct Exception-ctor newobj ==' % len(hits))
for tok, off, op in hits:
    print('HIT %s @%04x newobj %s' % (tname(tok), off, tname(op)))

# ③ 42AC 宽窗
for lo_w, hi_w, tag in ((0x0560, 0x0610, 'A'), (0x0650, 0x0710, 'B')):
    print('== 42AC window %s [%04x,%04x) ==' % (tag, lo_w, hi_w))
    c, p = bodies[0x060042ac]
    ins = list(parse(il[p:p + c]))
    for off, name, k, op, plen in ins:
        if lo_w <= off <= hi_w:
            if k == 'tok':
                print('  @%04x %-10s %s' % (off, name, tname(op)))
            elif k == 'str':
                print('  @%04x %-10s ldstr' % (off, name))
            elif k == 'i':
                print('  @%04x %-10s %d (0x%x)' % (off, name, op, op & 0xFFFFFFFF))
            elif k == 'b':
                print('  @%04x %-10s %d' % (off, name, op))
            else:
                print('  @%04x %-10s' % (off, name))

# ④ 02:000660 类型解剖
td = md.TypeDef.rows[0x660 - 1]
print('== 02:000660 %s.%s ==' % (td.TypeNamespace, td.TypeName))
try:
    for m in td.MethodList:
        r = m.row_index
        mr = md.MethodDef.rows[r - 1]
        print('  method 06:%06x %s rva=%x' % (r, mr.Name, mr.Rva))
except Exception as e:
    print('  methodlist err %s' % e)
# ToString 真体（若有 rva 且在 dump 中）
try:
    for m in td.MethodList:
        r = m.row_index
        if str(md.MethodDef.rows[r - 1].Name) == 'ToString' and 0x06000000 | r in bodies:
            c, p = bodies[0x06000000 | r]
            ins = list(parse(il[p:p + c]))
            print('  -- ToString body (%d ins) --' % len(ins))
            for off, name, k, op, plen in ins[:40]:
                if k == 'tok':
                    print('    @%04x %-10s %s' % (off, name, tname(op)))
                elif k == 'str':
                    print('    @%04x %-10s ldstr' % (off, name))
                else:
                    print('    @%04x %-10s' % (off, name))
except Exception as e:
    print('  tostring err %s' % e)
