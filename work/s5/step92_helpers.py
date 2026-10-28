#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step92: dissect 4192's key helper methods - FillResolver / ValidateSortedDispatcher /
CheckExpandableParameter / 06004264 ctor / ValidateSequentialSpec. Find where the
resource stream is opened and hashed."""
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
        if t == 0x02:
            return '02:typedef' + hex(r)
    except Exception:
        return hex(tok)
    return hex(tok)

# what type is 0x2000622
try:
    tdr = md.TypeDef.rows[0x622 - 1]
    print('[type 0x2000622] %s.%s' % (tdr.TypeNamespace, tdr.TypeName))
except Exception as e:
    print('[type 0x2000622] err', e)

for tok in (0x060041F0, 0x060041F1, 0x060041F2, 0x06004264, 0x060041D3):
    if tok not in idx:
        print('%s NOT-IN-IDX' % hex(tok)); continue
    cl, pos = idx[tok]
    b = il[pos:pos + cl]
    ins = parse(b)
    print('=== %s %s len=%d ins=%d' % (hex(tok), mname(tok), cl, len(ins)))
    for e in ins:
        line = '  %04x %s' % (e[0], e[1])
        if e[1] in ('call', 'callvirt', 'newobj', 'ldstr', 'ldsfld', 'stsfld', 'ldfld', 'ldtoken'):
            t = struct.unpack_from('<I', b, e[0] + 1)[0]
            line += ' ' + hex(t)
            if e[1] == 'ldstr':
                line += ' %r' % usdec(t)
            elif e[1].startswith('ldtoken'):
                line += ' ' + mname(t)
        if e[1] == 'ldc.i4':
            v = struct.unpack_from('<I', b, e[0] + 1)[0]
            if abs(v) > 0x1000:
                line += ' %#x' % v
        print(line)
