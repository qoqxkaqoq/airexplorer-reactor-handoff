#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step94: dump 4192 CryptoStream/RSA region (0x2100-0x2450) and FileStream region
(0x0140-0x0220) with full member resolution."""
import sys, struct
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse

EXE = '/workspace/repo_git/exes/AirExplorer_a1.exe'
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

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06:
            return '06:' + str(md.MethodDef.rows[r - 1].Name)
        if t == 0x0A:
            row = md.MemberRef.rows[r - 1]
            cn = '?'
            try:
                c = row.Class
                r2 = c.row if hasattr(c, 'row') else c
                if hasattr(r2, 'TypeName'):
                    cn = (str(r2.TypeNamespace) + '.' if str(r2.TypeNamespace) else '') + str(r2.TypeName)
                elif hasattr(r2, 'Name'):
                    cn = str(r2.Name)
            except Exception:
                pass
            return '0A:' + cn + '::' + str(row.Name)
    except Exception:
        return hex(tok)
    return hex(tok)

cl, pos = idx[0x06004192]
b = il[pos:pos + cl]
ins = parse(b)

def dump(lo, hi, title):
    print('=== %s (0x%04x-0x%04x) ===' % (title, lo, hi))
    for e in ins:
        if e[0] < lo or e[0] > hi:
            continue
        line = '  %04x %s' % (e[0], e[1])
        if e[1] in ('call', 'callvirt', 'newobj', 'ldstr', 'ldsfld', 'stsfld', 'ldfld', 'ldtoken', 'stind.i1', 'ldelem.u1', 'ldelem.i1'):
            t = struct.unpack_from('<I', b, e[0] + 1)[0]
            line += ' ' + hex(t)
            if e[1] == 'ldstr':
                line += ' %r' % usdec(t)
            elif e[1] in ('ldsfld', 'stsfld', 'ldfld'):
                try:
                    line += ' fld:' + str(md.Field.rows[(t & 0xFFFFFF) - 1].Name)
                except Exception:
                    pass
            else:
                line += ' ' + mname(t)
        if e[1] in ('ldc.i4', 'ldc.i8'):
            fmt = '<I' if e[1] == 'ldc.i4' else '<q'
            v = struct.unpack_from(fmt, b, e[0] + 1)[0]
            if abs(v) > 0x100:
                line += ' %#x' % (v & 0xFFFFFFFFFFFFFFFF)
        print(line)

dump(0x2100, 0x2360, 'CryptoStream/RSA region')
dump(0x0140, 0x0200, 'FileStream region')
dump(0x05f0, 0x0680, 'BinaryReader region')
