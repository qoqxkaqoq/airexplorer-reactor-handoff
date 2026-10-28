#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step72b: end-to-end rebuild verification on the PATCHED exe (AirExplorer_a1.exe).
Expect: all 14252 rebuild-OK except the 5 patch targets, which must rebuild to
the patched bodies (P1/P2 deep byte flipped; P3/P4/P5 -> ldc.i4.1; ret).
"""
import struct, sys

EXE = '/workspace/repo_git/exes/AirExplorer_a1.exe'
DBF = '/workspace/repo_git/work/s5/mem5/res0_plain_a1.bin'
IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'

db = open(DBF, 'rb').read()
off = 24
entries = []
while off < len(db):
    rva, n = struct.unpack_from('<II', db, off)
    off += 8
    dw = list(struct.unpack_from('<%dI' % n, db, off))
    off += 4 * n
    entries.append((rva, dw))

il = open(ALL, 'rb').read()
bodies = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        bodies[int(p[0], 16)] = (int(p[1]), int(p[4]))

import dnfile
pe = dnfile.dnPE(EXE)
md = pe.net.mdtables
rva2tok = {}
for i, row in enumerate(md.MethodDef.rows):
    if row.Rva:
        rva2tok[row.Rva] = 0x06000001 + i
exe = open(EXE, 'rb').read()

TARGET = {0x0600212A, 0x06002157, 0x06002127, 0x06002133, 0x06002145}
ok = fail = notok = 0
targ_ok = 0
problems = []
for rva, dw in entries:
    tok = rva2tok.get(rva)
    if tok is None or tok not in bodies:
        notok += 1
        continue
    clen, pos = bodies[tok]
    code = il[pos:pos + clen]
    dbytes = b''.join(struct.pack('<I', d) for d in dw)
    b0 = dbytes[0]
    if (b0 & 3) == 2 and b0 not in (0x0A,):
        true_full = bytes([(clen << 2) | 2]) + code
    else:
        flags = struct.unpack_from('<H', dbytes, 0)[0]
        headsize = (flags >> 12) * 4
        true_full = dbytes[:12] + code
        if tok in TARGET and (b0 & 3) == 2:
            # patched tiny body: DB holds whole new body
            true_full = dbytes[:len(dbytes)]
    L = len(true_full)
    fo = pe.get_offset_from_rva(rva)
    buf = bytearray(exe[fo:fo + L + 8])
    for i, d in enumerate(dw):
        if i * 4 >= L:
            break
        if d != 0:
            buf[i * 4:i * 4 + 4] = struct.pack('<I', d)
    rebuilt = bytes(buf[:L])
    if tok in TARGET:
        # patched expectations
        if tok in (0x0600212A, 0x06002157, 0x06002127):
            good = rebuilt[:3] == b'\x0a\x17\x2a'
        else:
            iloff = 0x290 if tok == 0x06002133 else 0x120
            headsize = 12 if (b0 & 3) != 2 else 1
            good = rebuilt[headsize + iloff] == 0x17 and \
                   rebuilt[headsize + iloff + 1:] == true_full[headsize + iloff + 1:] and \
                   rebuilt[:headsize + iloff] == true_full[:headsize + iloff]
        if good:
            targ_ok += 1
        else:
            problems.append(('TARGET-BAD', hex(tok), rebuilt[:32].hex()))
        continue
    if rebuilt == true_full:
        ok += 1
    else:
        fail += 1
        if len(problems) < 8:
            d0 = next((k for k in range(min(L, len(rebuilt))) if rebuilt[k] != true_full[k]), -1)
            problems.append((hex(tok), hex(rva), 'diff@%d' % d0,
                             rebuilt[max(0, d0 - 4):d0 + 4].hex(), true_full[max(0, d0 - 4):d0 + 4].hex()))
print('[a1-rebuild] ok=%d fail=%d notok=%d targets_ok=%d/5' % (ok, fail, notok, targ_ok))
for p in problems:
    print('  ', p)
