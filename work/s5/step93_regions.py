#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step93: 4192 - locate all ctor/verify sites (FileStream/BinaryReader/CryptoStream/RSA/
SHA1-create) and dump the SHA1+resource region fully."""
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
byoff = {e[0]: i for i, e in enumerate(ins)}

# 1) locate key memberref sites
KEYS = {0xA000518: 'FileStream.ctor', 0xA00029F: 'BinaryReader.ctor', 0xA00033A: 'CryptoStream.ctor',
        0xA0009A5: 'RSA.ctor', 0xA0009A3: 'Stream.set_Position', 0xA000997: 'Type.get_Assembly'}
print('[4192] key memberref sites:')
for e in ins:
    if e[1] in ('call', 'callvirt', 'newobj'):
        t = struct.unpack_from('<I', b, e[0] + 1)[0]
        if t in KEYS:
            print('  @%04x %s %s' % (e[0], e[1], KEYS[t]))

# 2) dump region 0x0aeb..0x0e00 (SHA1 create + EmitterReporter)
print('=== region 0x0aeb-0x0e00 ===')
for e in ins:
    if e[0] < 0x0aeb or e[0] > 0x0e00:
        continue
    line = '  %04x %s' % (e[0], e[1])
    if e[1] in ('call', 'callvirt', 'newobj', 'ldstr', 'ldsfld', 'stsfld', 'ldfld', 'ldtoken'):
        t = struct.unpack_from('<I', b, e[0] + 1)[0]
        line += ' ' + hex(t)
        if e[1] == 'ldstr':
            line += ' %r' % usdec(t)
        elif e[1] in ('ldsfld', 'stsfld', 'ldfld'):
            try:
                line += ' fld:' + str(md.Field.rows[(t & 0xFFFFFF) - 1].Name)
            except Exception:
                pass
        elif e[1] in ('call', 'callvirt', 'newobj'):
            line += ' ' + mname(t)
    if e[1] == 'ldc.i4':
        v = struct.unpack_from('<I', b, e[0] + 1)[0]
        if abs(v) > 0x1000:
            line += ' %#x' % v
    print(line)
