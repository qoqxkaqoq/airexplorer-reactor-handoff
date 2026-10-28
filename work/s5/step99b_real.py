#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step99b: resolve real tokens behind shims 041D6/041D9/041D5/041D2, then
dissect the real bodies (SymmetricAlgorithm factory: type ctor, Mode, Key/IV)."""
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
    t, r = coded >> 24, coded & 0xFFFFFF
    try:
        if t == 0x02 and 1 <= r <= len(md.TypeDef.rows):
            td = md.TypeDef.rows[r - 1]
            return (str(td.TypeNamespace) + '.' if str(td.TypeNamespace) else '') + str(td.TypeName)
        if t == 0x01 and 1 <= r <= len(md.TypeRef.rows):
            tr = md.TypeRef.rows[r - 1]
            return (str(tr.TypeNamespace) + '.' if str(tr.TypeNamespace) else '') + str(tr.TypeName)
        if t == 0x1B:
            return 'TypeSpec@%06x' % r
    except Exception:
        pass
    return '%02x:%06x' % (t, r)

def mref(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06:
            m = md.MethodDef.rows[r - 1]
            return '06:%06x:%s' % (r, str(m.Name))
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
        if t == 0x2B:
            return '2B:methodspec@%06x' % r
    except Exception:
        pass
    return hex(tok)

def fldname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x04 and 1 <= r <= len(md.Field.rows):
            return 'fld:%06x:%s' % (r, str(md.Field.rows[r - 1].Name))
    except Exception:
        pass
    return hex(tok)

# 1) raw call tokens of the shims
print('=== shim raw call tokens ===')
SHIMS = [0x060041CF, 0x060041D0, 0x060041D2, 0x060041D5, 0x060041D6, 0x060041D9]
targets = {}
for tok in SHIMS:
    cl, pos = idx[tok]
    b = il[pos:pos + cl]
    ins = parse(b)
    for e in ins:
        if e[1] in ('call', 'callvirt'):
            raw = struct.unpack_from('<I', b, e[0] + 1)[0]
            print('  %s @%04x -> %s (%s)' % (hex(tok), e[0], hex(raw), mref(raw)))
            if (raw >> 24) == 0x06:
                targets[raw] = hex(tok)

# 2) also find ALL MethodDefs named *AdjustableAuditor* / *InterruptibleHandler*
print('\n=== same-name MethodDefs ===')
NAMES = ('InstantiateAdjustableAuditor', 'GenerateInterruptibleHandler')
for i, m in enumerate(md.MethodDef.rows):
    n = str(m.Name)
    if n in NAMES:
        print('  06:%06x %s rva=%#x' % (i + 1, n, m.Rva))

# 3) dissect real bodies
def dissect(tok, label):
    if tok not in idx:
        # maybe needs il_new_index
        print('  %s NOT IN il_index' % hex(tok))
        return
    cl, pos = idx[tok]
    b = il[pos:pos + cl]
    ins = parse(b)
    print('\n=== %s (%s) len=%d ins=%d' % (hex(tok), label, cl, len(ins)))
    for e in ins:
        o, nm, k, op = e[0], e[1], e[2], e[3]
        line = '  %04x %s' % (o, nm)
        if nm in ('call', 'callvirt', 'newobj', 'ldftn', 'ldvirtftn'):
            raw = struct.unpack_from('<I', b, o + 1)[0]
            line += ' ' + mref(raw)
        elif nm in ('ldsfld', 'stsfld', 'ldfld', 'stfld'):
            raw = struct.unpack_from('<I', b, o + 1)[0]
            line += ' ' + fldname(raw)
        elif nm in ('newarr', 'box', 'unbox.any', 'castclass', 'isinst', 'ldobj', 'stobj', 'initobj', 'sizeof'):
            raw = struct.unpack_from('<I', b, o + 1)[0]
            line += ' ' + clsname(raw)
        elif nm == 'ldstr':
            raw = struct.unpack_from('<I', b, o + 1)[0]
            line += ' %r' % usdec(raw)
        elif nm in ('ldc.i4', 'ldc.i4.s'):
            line += ' %d' % (op if op is not None else 0)
        elif nm in ('ldarg', 'ldarg.s', 'starg', 'starg.s', 'ldloc', 'ldloc.s', 'stloc', 'stloc.s'):
            line += ' %d' % (op or 0)
        elif nm in ('br', 'br.s', 'brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'leave', 'leave.s'):
            line += ' -> %04x' % (op or 0)
        print(line)

for tok, src in sorted(targets.items()):
    dissect(tok, 'target of ' + src)
