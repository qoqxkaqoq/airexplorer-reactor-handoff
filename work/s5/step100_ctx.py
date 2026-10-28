#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step100: in 06004192's body, find call sites of the crypto shims
(041CF..041DA, 0418C, 041A8) and print +/-20 instruction context with
resolved tokens -> reveals AES Mode value, Key/IV source, res5 consumer chain."""
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
            return '06:%06x:%s' % (r, str(md.MethodDef.rows[r - 1].Name))
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

TOK = 0x06004192
cl, pos = idx[TOK]
b = il[pos:pos + cl]
ins = parse(b)
N = len(ins)

SHIMS = {0x060041cf: 'MapNameToOID', 0x060041d0: 'FileExists', 0x060041d1: 'GetManifestRes',
         0x060041d2: 'BR-BaseStream', 0x060041d5: 'BR-ReadBytes', 0x060041d3: 'set_Position',
         0x060041d4: 'get_Length', 0x060041d6: 'AES-factory', 0x060041d7: 'set_Mode',
         0x060041d8: 'CreateDecryptor', 0x060041d9: 'new-MemStream', 0x060041da: 'Stream-Write',
         0x0600418c: 'AES-factory-real', 0x060041a8: 'new-MemStream-real'}

def fmt(e):
    o, nm, k, op = e[0], e[1], e[2], e[3]
    s = '%04x %s' % (o, nm)
    try:
        if nm in ('call', 'callvirt', 'newobj', 'ldftn'):
            raw = struct.unpack_from('<I', b, o + 1)[0]
            tag = SHIMS.get(raw)
            s += ' ' + mref(raw) + (' <%s>' % tag if tag else '')
        elif nm in ('ldsfld', 'stsfld', 'ldfld', 'stfld'):
            s += ' ' + fldname(struct.unpack_from('<I', b, o + 1)[0])
        elif nm in ('newarr', 'box', 'unbox.any', 'castclass', 'isinst', 'ldobj', 'stobj', 'initobj'):
            s += ' ' + clsname(struct.unpack_from('<I', b, o + 1)[0])
        elif nm == 'ldstr':
            s += ' %r' % usdec(struct.unpack_from('<I', b, o + 1)[0])
        elif nm == 'ldtoken':
            raw = struct.unpack_from('<I', b, o + 1)[0]
            s += ' ' + hex(raw)
        elif nm in ('ldc.i4', 'ldc.i4.s'):
            s += ' %d' % (op if op is not None else 0)
        elif nm in ('ldarg', 'ldarg.s', 'starg', 'starg.s', 'ldloc', 'ldloc.s', 'stloc', 'stloc.s'):
            s += ' %d' % (op or 0)
        elif nm in ('br', 'br.s', 'brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'leave', 'leave.s'):
            s += ' -> %04x' % (op or 0)
    except Exception as ex:
        s += ' <%s>' % ex
    return s

# find call sites of shims
sites = []
for i, e in enumerate(ins):
    if e[1] in ('call', 'callvirt', 'newobj'):
        raw = struct.unpack_from('<I', b, e[0] + 1)[0]
        if raw in SHIMS:
            sites.append((i, raw))

print('[4192] total ins=%d, shim call sites=%d' % (N, len(sites)))
for i, raw in sites:
    print('\n' + '=' * 70)
    print('>>> %s call site @%04x (ins#%d)' % (SHIMS[raw], ins[i][0], i))
    lo, hi = max(0, i - 14), min(N, i + 15)
    for j in range(lo, hi):
        mark = '>>' if j == i else '  '
        print('%s %s' % (mark, fmt(ins[j])))
