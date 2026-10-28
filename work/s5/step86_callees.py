#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step86: dissect 4528's callees (FilterStream/CloneSharer/Decryptor family)
and the state-machine entry - what does guard2 actually test?"""
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
            except Exception:
                pass
            return '0A:' + cn + '::' + str(row.Name)
    except Exception:
        return hex(tok)
    return hex(tok)

def body(tok):
    cl, pos = idx[tok]
    return il[pos:pos + cl]

def brief(tok, label):
    if tok not in idx:
        print('%s %s NOT-IN-IDX' % (label, hex(tok)))
        return
    b = body(tok)
    ins = parse(b)
    calls = {}
    strs = []
    for e in ins:
        if e[1] in ('call', 'callvirt', 'newobj'):
            t = struct.unpack_from('<I', b, e[0] + 1)[0]
            calls[mname(t)] = calls.get(mname(t), 0) + 1
        elif e[1] == 'ldstr':
            strs.append(usdec(struct.unpack_from('<I', b, e[0] + 1)[0]))
    print('%s tok=%s len=%d ins=%d throws=%d' % (label, hex(tok), len(b), len(ins),
          sum(1 for e in ins if e[1] == 'throw')))
    for s, n in sorted(calls.items(), key=lambda x: -x[1]):
        print('    call %-64s x%d' % (s[:64], n))
    for s in strs[:10]:
        print('    ldstr %r' % s)

# key callees
brief(0x06004385, 'FilterStream       ')
brief(0x060043F4, 'AddVisualDecryptor ')
brief(0x0600441E, 'InstantiateSharer  ')
brief(0x0600454C, 'CloneSharer        ')
brief(0x060077A4, 'ExecuteExplorer#1  ')
brief(0x0600780C, 'ExecuteExplorer#2  ')

# does 4528 call 0600428A family (res0 reader)?
b = body(0x06004528)
ins = parse(b)
c28 = {}
for e in ins:
    if e[1] in ('call', 'callvirt', 'newobj'):
        t = struct.unpack_from('<I', b, e[0] + 1)[0]
        c28[t] = c28.get(t, 0) + 1
print('[4528] all 0600 42xx/43xx/44xx calls:')
for t in sorted(c28):
    if (t >> 24) == 0x06 and 0x06004200 <= t <= 0x060044FF:
        print('  %s x%d %s' % (hex(t), c28[t], mname(t)))

# state machine entry: first 70 ins
print('[4528] ENTRY (first 70 ins):')
for e in ins[:70]:
    line = '  %04x %s' % (e[0], e[1])
    if e[1] in ('call', 'callvirt', 'newobj', 'ldstr', 'ldsfld', 'stsfld', 'ldfld'):
        line += ' ' + hex(struct.unpack_from('<I', b, e[0] + 1)[0])
        if e[1] == 'ldstr':
            line += ' %r' % usdec(struct.unpack_from('<I', b, e[0] + 1)[0])
    print(line)
