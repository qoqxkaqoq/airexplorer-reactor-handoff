#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step190: 419c DefineEfficientProfiler 内 m_RemoteNodeVal 数据流。
① @3da8 ldloca.s 的 local 槽号; ② 该 local 全部写入者; ③ 419c 的调用者 xref;
④ 4224 ValidateConfigurableProxyThread 签名栈形。"""
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
            return '1B:%06x(typespec)' % r
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

c, p = bodies[0x0600419c]
ins = list(parse(il[p:p + c]))

# ① @3da8 ldloca.s 槽号
i3daf = next(i for i, x in enumerate(ins) if x[0] == 0x3daf)
slot = ins[i3daf - 1][3]  # ldloca.s operand
print('== @%04x %s slot=%d ==' % (ins[i3daf-1][0], ins[i3daf-1][1], slot))

# locals 签名里该槽类型
row = md.MethodDef.rows[0x419c - 1]
sig = row.Signature
try:
    blob = sig.__bytes__() if hasattr(sig, '__bytes__') else bytes(sig.value)
except Exception:
    blob = None
# ② 该 local 全部出现点 (ldloca/stloc/ldloc)
uses = []
for i, x in enumerate(ins):
    off, name, k, op, plen = x
    if k in ('var1', 'var2') and op == slot:
        uses.append((i, off, name))
print('== local %d uses: %d ==' % (slot, len(uses)))
from collections import Counter
print(' op histogram:', dict(Counter(u[2] for u in uses)))
# stloc 写入点前 6 条上下文 (每个写入点打印一次)
shown = 0
for i, off, name in uses:
    if name.startswith('stloc') and shown < 12:
        shown += 1
        seq = []
        for y in ins[max(0, i - 6):i + 1]:
            yo, yn, yk, yop, ypl = y
            s = '%s' % yn
            if yk == 'tok':
                s += ' ' + tname(yop)
            elif yk == 'i':
                s += ' 0x%08x' % (yop & 0xFFFFFFFF)
            elif yk == 'var1':
                s += ' v%d' % yop
            seq.append(s)
        print('  WR @%04x <- %s' % (off, ' ; '.join(seq)))

# ③ 419c 调用者
print('== 419c callers ==')
for tok, (c2, p2) in bodies.items():
    try:
        ins2 = list(parse(il[p2:p2 + c2]))
    except Exception:
        continue
    for x in ins2:
        if x[2] == 'tok' and x[3] == 0x0600419c and x[1] in ('call', 'callvirt', 'jmp'):
            r = tok & 0xFFFFFF
            try:
                nm = str(md.MethodDef.rows[r - 1].Name)
            except Exception:
                nm = '?'
            print('  %s from 06:%06x %s @%04x' % (x[1], r, nm, x[0]))

# ④ 4224 栈形 (读 reader @1993 的 6-10 条)
print('== 4224 method ==')
r24 = md.MethodDef.rows[0x4224 - 1]
print('  name=%s rva=%x' % (r24.Name, r24.Rva))
