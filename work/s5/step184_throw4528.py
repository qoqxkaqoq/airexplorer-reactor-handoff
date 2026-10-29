#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step184: 4528 throw 站点进料分类 + 448F 类型解剖 + 4528 被调清单。
FCE 实锤: 裸 System.Exception("AirExplorer ") 的 throw 指令在 4528 体内。"""
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

# 1) 4528 全 throw 站点 + 进料
c, p = bodies[0x06004528]
ins = list(parse(il[p:p + c]))
print('== 4528 DefineSetSet: %d ins ==' % len(ins))
newobj_hist = {}
throws = []
for i, x in enumerate(ins):
    off, name, k, op, plen = x
    if name == 'newobj':
        newobj_hist[tname(op)] = newobj_hist.get(tname(op), 0) + 1
    if name == 'throw':
        throws.append((i, off))
print('newobj histogram:')
for t2, n in sorted(newobj_hist.items(), key=lambda kv: -kv[1]):
    print('  %d x %s' % (n, t2))
print('throw sites: %d' % len(throws))
for i, off in throws:
    lo = max(0, i - 4)
    feed = []
    for y in ins[lo:i]:
        yo, yn, yk, yo_op, ypl = y
        feed.append('%s%s' % (yn, (' ' + tname(yo_op)) if yk == 'tok' else ''))
    print('  @%04x <- %s' % (off, ' ; '.join(feed)))

# 2) 4528 被调清单（去重）
calls = set()
for x in ins:
    off, name, k, op, plen = x
    if name in ('call', 'callvirt', 'jmp', 'ldftn', 'newobj') and k == 'tok':
        calls.add((name, op))
print('== 4528 distinct callees (%d) ==' % len(calls))
for name, op in sorted(calls, key=lambda t: (t[1] >> 24, t[1] & 0xFFFFFF)):
    print('  %-9s %s' % (name, tname(op)))

# 3) 448F 声明类型解剖
mr = None
# 448F 是 MethodDef (0600448F)
row = md.MethodDef.rows[0x448F - 1]
print('== 448F method: %s rva=%x ==' % (row.Name, row.Rva))
# 找它的 TypeDef: 扫 TypeDef MethodList
for ti2, td in enumerate(md.TypeDef.rows, 1):
    try:
        for m in td.MethodList:
            if m.row_index == 0x448F:
                bt = td.BaseType.row
                btn = '%s.%s' % (getattr(bt, 'TypeNamespace', '?'), getattr(bt, 'TypeName', '?'))
                print('  declaring TypeDef 02:%06x %s.%s  BaseType=%s' % (ti2, td.TypeNamespace, td.TypeName, btn))
                for m2 in td.MethodList:
                    r2 = m2.row_index
                    mr2 = md.MethodDef.rows[r2 - 1]
                    print('    method 06:%06x %s rva=%x' % (r2, mr2.Name, mr2.Rva))
                # BaseType 是 TypeRef 时进一步看
                raise StopIteration
    except StopIteration:
        break
    except Exception:
        continue
