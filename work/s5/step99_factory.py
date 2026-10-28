#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step99: dissect 060041D6 InstantiateAdjustableAuditor + 060041D9
GenerateInterruptibleHandler (SymmetricAlgorithm factories in 4192's family),
plus 041CF-041DA full family for completeness. Resolve all tokens via dnfile."""
import sys, struct
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse

EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'

il = open(ALL, 'rb').read()
idx = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        idx[int(p[0], 16)] = (int(p[1]), int(p[4]))

import dnfile
pe = dnfile.dnPE(EXE)
md = pe.net.mdtables
us = bytes(pe.net.metadata.streams[b'#US'].__data__)

def usdec(t):
    p = t & 0xFFFFFF
    b0 = us[p]
    if b0 & 0x80 == 0:
        ln, p = b0, p + 1
    elif b0 & 0xC0 == 0x80:
        ln = ((b0 & 0x3F) << 8) | us[p + 1]; p += 2
    else:
        ln = ((b0 & 0x1F) << 24) | (us[p + 1] << 16) | (us[p + 2] << 8) | us[p + 3]; p += 4
    return us[p:p + max(0, ln - 1)].decode('utf-16-le', 'replace')

def clsname(coded):
    """resolve TypeDefOrRef coded token to full name"""
    t, r = coded >> 24, coded & 0xFFFFFF
    try:
        if t == 0x02 and 1 <= r <= len(md.TypeDef.rows):
            td = md.TypeDef.rows[r - 1]
            return (str(td.TypeNamespace) + '.' if str(td.TypeNamespace) else '') + str(td.TypeName)
        if t == 0x01 and 1 <= r <= len(md.TypeRef.rows):
            tr = md.TypeRef.rows[r - 1]
            return (str(tr.TypeNamespace) + '.' if str(tr.TypeNamespace) else '') + str(tr.TypeName)
        if t == 0x1B and 1 <= r <= len(md.TypeSpec.rows):
            return 'TypeSpec@%06x' % r
    except Exception:
        pass
    return '%02x:%06x' % (t, r)

def mref(tok):
    """resolve MethodDef(06)/MemberRef(0A)/TypeRef(01) token to name"""
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06:
            m = md.MethodDef.rows[r - 1]
            return '06:' + str(m.Name)
        if t == 0x0A:
            row = md.MemberRef.rows[r - 1]
            c = row.Class
            r2 = c.row if hasattr(c, 'row') else c
            cn = '?'
            if hasattr(r2, 'TypeName'):
                cn = (str(r2.TypeNamespace) + '.' if str(r2.TypeNamespace) else '') + str(r2.TypeName)
            elif hasattr(r2, 'Name'):
                cn = str(r2.Name)
            return '0A:' + cn + '::' + str(row.Name)
        if t == 0x04:
            f = md.Field.rows[r - 1]
            return '04:fld:' + str(f.Name)
        if t == 0x01:
            return '01:type:' + clsname(tok)
        if t == 0x04 or (t == 0x00 and r):
            pass
    except Exception:
        pass
    return hex(tok)

def fldname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x04 and 1 <= r <= len(md.Field.rows):
            return 'fld:' + str(md.Field.rows[r - 1].Name)
    except Exception:
        pass
    return hex(tok)

TARGETS = [0x060041CF, 0x060041D0, 0x060041D1, 0x060041D2, 0x060041D3,
           0x060041D4, 0x060041D5, 0x060041D6, 0x060041D7, 0x060041D8,
           0x060041D9, 0x060041DA]

for tok in TARGETS:
    if tok not in idx:
        print('=== %s: NOT IN IL INDEX' % hex(tok))
        continue
    cl, pos = idx[tok]
    b = il[pos:pos + cl]
    ins = parse(b)
    print('=== %s len=%d ins=%d' % (hex(tok), cl, len(ins)))
    for e in ins:
        o, nm, k, op = e[0], e[1], e[2], e[3]
        line = '  %04x %s' % (o, nm)
        if nm in ('call', 'callvirt', 'newobj', 'ldtoken', 'newarr', 'ldsfld', 'stsfld', 'ldfld', 'stfld', 'box', 'unbox.any', 'castclass', 'isinst', 'ldobj', 'stobj', 'initobj', 'cpobj', 'sizeof', 'ldftn', 'ldvirtftn'):
            line += ' ' + (mref(op) if nm in ('call', 'callvirt', 'newobj', 'ldftn', 'ldvirtftn') else fldname(op) if nm in ('ldsfld', 'stsfld', 'ldfld', 'stfld') else clsname(op) if nm not in ('ldtoken',) or (op >> 24) != 0x06 else mref(op))
        elif nm == 'ldstr':
            line += ' %r' % usdec(op)
        elif nm in ('ldc.i4', 'ldc.i4.s'):
            line += ' %d' % (op if op is not None else 0)
        elif nm in ('ldarg', 'ldarg.s', 'starg', 'starg.s', 'ldloc', 'ldloc.s', 'stloc', 'stloc.s'):
            line += ' %d' % (op or 0)
        elif nm in ('br', 'br.s', 'brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'leave', 'leave.s'):
            line += ' -> %04x' % (op or 0)
        print(line)
    print()
