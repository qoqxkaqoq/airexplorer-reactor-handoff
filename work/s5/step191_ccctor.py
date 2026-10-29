#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step191: ① cctor 注入模式确认(06000002 头部); ② 419c 内 IntPtr local(slot 修正)全写入者;
③ 419c 全部 cctor 调用者计数; ④ ToInt64 局部的写点数据流。"""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse
from collections import Counter
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

# ① 06000002 .cctor 头部
c2, p2 = bodies[0x06000002]
ins2 = list(parse(il[p2:p2 + c2]))
print('== 06000002 .cctor csize=%d ins=%d ==' % (c2, len(ins2)))
for x in ins2[:10]:
    off, name, k, op, plen = x
    print('  @%04x %s%s' % (off, name, (' ' + tname(op)) if k == 'tok' else (' v%d' % op if k in ('var1', 'var2') else '')))

# ② 419c: ldloca.s @3da8 → slot; 该 slot 写入者
c, p = bodies[0x0600419c]
ins = list(parse(il[p:p + c]))
i3daf = next(i for i, x in enumerate(ins) if x[0] == 0x3daf)
ldi = i3daf - 2
assert ins[ldi][1] == 'ldloca.s', (ins[ldi], ins[i3daf-1])
slot = ins[ldi][3]
print('== 419c ldloca.s @%04x slot=%d ==' % (ins[ldi][0], slot))

uses = [(i, x[0], x[1]) for i, x in enumerate(ins) if x[2] == 'var' and x[3] == slot]
print('== local %d uses: %d, ops=%s ==' % (slot, len(uses), dict(Counter(u[2] for u in uses))))
shown = 0
for i, off, name in uses:
    if name.startswith('stloc') and shown < 16:
        shown += 1
        seq = []
        for y in ins[max(0, i - 7):i + 1]:
            yo, yn, yk, yop, ypl = y
            s = yn
            if yk == 'tok':
                s += ' ' + tname(yop)
            elif yk == 'i':
                s += ' 0x%08x' % (yop & 0xFFFFFFFF)
            elif yk == 'i8':
                s += ' 0x%016x' % (yop & 0xFFFFFFFFFFFFFFFF)
            elif yk == 'var1':
                s += ' v%d' % yop
            seq.append(s)
        print('  WR@%04x <- %s' % (off, ' ; '.join(seq)))

# ldloca.s 该 slot 的其他位置(取地址传入点)
for i, off, name in uses:
    if name == 'ldloca.s' and off != ins[ldi][0] and shown < 40:
        shown += 1
        seq = []
        for y in ins[i:i + 4]:
            yo, yn, yk, yop, ypl = y
            s = yn
            if yk == 'tok':
                s += ' ' + tname(yop)
            seq.append(s)
        print('  LDA@%04x -> %s' % (off, ' ; '.join(seq)))

# ③ 全部 419c 调用者计数
cnt = 0
for tok, (cc, pp) in bodies.items():
    try:
        insx = list(parse(il[pp:pp + cc]))
    except Exception:
        continue
    if any(x[2] == 'tok' and x[3] == 0x0600419c and x[1] in ('call', 'callvirt', 'jmp') for x in insx):
        cnt += 1
print('== methods calling 419c: %d ==' % cnt)
