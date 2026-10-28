#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step80: dissect TemplateThread.GenerateAdaptableExtractor (second-layer sentinel).
Find token, check DB membership, disassemble throw sites + ldstr strings."""
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
tds = md.TypeDef.rows
tok = None
for td in tds:
    for mi in td.MethodList:
        m = mi.row if hasattr(mi, 'row') else mi
        if str(m.Name) == 'GenerateAdaptableExtractor':
            rid = md.MethodDef.rows.index(m) + 1
            dt = str(td.TypeName)
            print('cand tok=%s decl=%s' % (hex(0x06000001 + rid), dt))
            if dt == 'TemplateThread':
                tok = 0x06000001 + rid
print('[pick]', hex(tok) if tok else None)
if tok is None:
    raise SystemExit(1)

# DB membership
db = open('/workspace/repo_git/work/s5/mem5/res0_plain_s1_47.bin', 'rb').read()
off = 24
in_db = False
ent_off = ent_n = None
while off < len(db):
    r, n = struct.unpack_from('<II', db, off)
    row = md.MethodDef.rows[tok - 0x06000001]
    if r == row.Rva:
        in_db = True
        ent_off, ent_n = off, n
    off += 8 + 4 * n
print('[db] member=%s' % in_db)

clen, pos = idx[tok]
b = il[pos:pos + clen]
ins = parse(b)
throws = [e for e in ins if e[1] == 'throw']
print('[body] len=%d ins=%d throws=%d' % (clen, len(ins), len(throws)))
for t in throws:
    k = ins.index(t)
    print('  THROW@%04x:' % t[0], ' | '.join('%s' % c[1] for c in ins[max(0, k - 7):k + 1]))
    # tokens of nearby calls/newobj/ldstr
    for c in ins[max(0, k - 7):k + 1]:
        if c[1] in ('call', 'callvirt', 'newobj'):
            print('    %04x %s tok=%s' % (c[0], c[1], hex(struct.unpack_from('<I', b, c[0] + 1)[0])))
        if c[1] == 'ldstr':
            print('    %04x ldstr tok=%s' % (c[0], hex(struct.unpack_from('<I', b, c[0] + 1)[0])))
# all ldstrs
us = bytes(pe.net.metadata.streams[b'#US'].__data__)
for e in ins:
    if e[1] == 'ldstr':
        t = struct.unpack_from('<I', b, e[0] + 1)[0]
        p0 = t & 0xFFFFFF
        b0 = us[p0]
        if b0 & 0x80 == 0:
            ln, q = b0, p0 + 1
        elif b0 & 0xC0 == 0x80:
            ln = ((b0 & 0x3F) << 8) | us[p0 + 1]; q = p0 + 2
        else:
            ln = ((b0 & 0x1F) << 24) | (us[p0+1] << 16) | (us[p0+2] << 8) | us[p0+3]; q = p0 + 4
        s = us[q:q + max(0, ln - 1)].decode('utf-16-le', 'replace')
        print('  LDSTR@%04x %r' % (e[0], s))
# file state at RVA
fo = pe.get_offset_from_rva(md.MethodDef.rows[tok - 0x06000001].Rva)
exe = open(EXE, 'rb').read()
print('[file] head16=%s true_head16=%s full_match=%s' % (
    exe[fo:fo + 16].hex(), b[:16].hex(), exe[fo:fo + 12 + clen] == exe[fo:fo + 12] + b))
