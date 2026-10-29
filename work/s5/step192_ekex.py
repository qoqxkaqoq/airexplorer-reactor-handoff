#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step192: A2 公钥替换前置解剖。
① m_ExtendedSchemaTemplate(04:001fcd) 全库引用(读/写) → 初始化点
② 060041ED / 060041EE / 060041DF 真身反汇编
③ 全库 ldstr 清单(找 RSA XML blob 明文)"""
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

FIELD = 0x04001FCD  # m_ExtendedSchemaTemplate

# 1) 全库引用扫描
refs = []  # (mdef, off, insn_name, mode)
for tok, (c, p) in bodies.items():
    try:
        ins = list(parse(il[p:p + c]))
    except Exception:
        continue
    for x in ins:
        off, name, k, op, plen = x
        if k == 'tok' and op == FIELD and name in ('stsfld', 'ldsfld', 'ldsflda'):
            refs.append((tok, off, name))

print('== 04:001fcd refs: %d ==' % len(refs))
writers = [r for r in refs if r[2] == 'stsfld']
print('writers(stsfld): %d' % len(writers))
for tok, off, nm in writers:
    print('  06:%06x @%04x' % (tok & 0xFFFFFF, off))

# 2) 关键方法反汇编
def disasm(tok, label, ctx=0):
    if tok not in bodies:
        print('== %s 06:%06x: NOT IN DUMP ==' % (label, tok & 0xFFFFFF))
        return
    c, p = bodies[tok]
    ins = list(parse(il[p:p + c]))
    print('== %s 06:%06x: %d ins, csize=%d ==' % (label, tok & 0xFFFFFF, len(ins), c))
    for x in ins:
        off, name, k, op, plen = x
        s = '%04x: %s' % (off, name)
        if k == 'tok':
            s += ' ' + tname(op)
        elif k == 'str':
            s += ' tok=%s' % tname(op)
        elif op is not None and k not in ('tok', 'str'):
            s += ' %s' % (op,)
        print('  ' + s)

disasm(0x060041ED, '41ed(verify-core?)')
disasm(0x060041EE, '41ee(VerifyDynamicStrategy)')
disasm(0x060041DF, '41df(FromXmlString?)')

# 3) 41df 调用者
callers = []
for tok, (c, p) in bodies.items():
    try:
        ins = list(parse(il[p:p + c]))
    except Exception:
        continue
    for x in ins:
        off, name, k, op, plen = x
        if k == 'tok' and op == 0x060041DF and name in ('call', 'callvirt'):
            callers.append((tok, off, name))
print('== 41df callers: %d ==' % len(callers))
for tok, off, nm in callers:
    print('  06:%06x @%04x %s' % (tok & 0xFFFFFF, off, nm))

# 4) 全库 ldstr 清单
print('== all ldstr in dump ==')
for tok, (c, p) in bodies.items():
    try:
        ins = list(parse(il[p:p + c]))
    except Exception:
        continue
    for x in ins:
        off, name, k, op, plen = x
        if name == 'ldstr':
            print('  06:%06x @%04x tok=%08x' % (tok & 0xFFFFFF, off, op))
