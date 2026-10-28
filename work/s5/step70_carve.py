#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step70: carve m_<tok>.bin (24B header) for all il_index tokens not in dump_official_16598.zip.
Also import dump-missing family (06003909/06002BD1/...) which C-line forcedump missed but reflection reads."""
import struct, os, zipfile, sys

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
OUT = '/workspace/repo_git/work/s5/mem5/carve'
os.makedirs(OUT, exist_ok=True)

dump = set()
Z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
for n in Z.namelist():
    if n.startswith('m_') and n.endswith('.bin'):
        dump.add(int(n[2:10], 16))

rows = []
for ln in open(IDX):
    p = ln.rstrip('\n').split('\t')
    if len(p) >= 5:
        rows.append((int(p[0], 16), int(p[1]), p[2], p[3], int(p[4])))
data = open(ALL, 'rb').read()

n_new = 0
for tok, ln, ty, nm, pos in rows:
    if tok in dump:
        continue
    il = data[pos:pos + ln]
    assert len(il) == ln, (hex(tok), ln, len(il))
    with open(os.path.join(OUT, 'm_%08X.bin' % tok), 'wb') as f:
        f.write(struct.pack('<IIIIII', tok, ln, 8, 0, 0, 0))
        f.write(il)
    n_new += 1
print('carved new bodies:', n_new, '->', OUT)

# key tokens report
KEY = [0x06003909, 0x06002BD1, 0x060041A3, 0x06004264, 0x0600419E]
for tok in KEY:
    p = os.path.join(OUT, 'm_%08X.bin' % tok)
    print(hex(tok), 'len=' + str(os.path.getsize(p) - 24) if os.path.exists(p) else 'NOT-IN-MEM')
