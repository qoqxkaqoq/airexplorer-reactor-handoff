#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step75: manual token extraction for 06004192 + #US string decode + throw->pop plan."""
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

b = il[idx[0x06004192][1]:idx[0x06004192][1] + idx[0x06004192][0]]
ins = parse(b)

# --- manual tokens ---
calls = {}
ldstrs = []
for e in ins:
    o, name = e[0], e[1]
    if name in ('call', 'callvirt', 'newobj'):
        tok = struct.unpack_from('<I', b, o + 1)[0]
        calls[tok] = calls.get(tok, 0) + 1
    elif name == 'ldstr':
        tok = struct.unpack_from('<I', b, o + 1)[0]
        ldstrs.append((o, tok))
print('[4192] calls uniq=%d' % len(calls))
print('  ', ' '.join('%s:x%d' % (hex(k), v) for k, v in sorted(calls.items())))
print('[4192] ldstr:', [(hex(o), hex(t)) for o, t in ldstrs])

# --- #US decode ---
import dnfile
pe = dnfile.dnPE(EXE)
us = pe.net.metadata.streams.get(b'#US') or pe.net.metadata.streams.get('#US')
data = us.__data__ if hasattr(us, '__data__') else us.get_data_at_offset(0, len(us.struct)) if False else None
raw = bytes(us.__data__)
for o, t in ldstrs:
    off = t & 0xFFFFFF
    # US heap: [compressed len][utf16][flag byte]
    p = off
    b0 = raw[p]
    if b0 & 0x80 == 0:
        ln, p = b0, p + 1
    elif b0 & 0xC0 == 0x80:
        ln = ((b0 & 0x3F) << 8) | raw[p + 1]; p += 2
    else:
        ln = ((b0 & 0x1F) << 24) | (raw[p+1] << 16) | (raw[p+2] << 8) | raw[p+3]; p += 4
    s = raw[p:p + ln - 1].decode('utf-16-le', 'replace')
    print('[US@%s] %r' % (hex(o), s))

# --- throw patch offset ---
th = [e for e in ins if e[1] == 'throw'][0]
print('[throw] iloff=%#x ilbyte=%#x' % (th[0], b[th[0]]))
for i, row in enumerate(pe.net.mdtables.MethodDef.rows):
    if 0x06000001 + i == 0x06004192:
        rva = row.Rva
fo = pe.get_offset_from_rva(rva)
fpos = fo + 12 + th[0]
print('[patch-plan] 06004192 rva=%#x fileoff=%#x cur=%#x -> 0x26 (pop)' % (rva, fpos, bytes(open(EXE,'rb').read())[fpos]))
