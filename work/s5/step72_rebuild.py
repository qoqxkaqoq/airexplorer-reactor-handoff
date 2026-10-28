#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step72: full-library rebuild verification of the backfill hypothesis.

Hypothesis:
  - file body at RVA = stub-overwritten head + plaintext tail (residue)
  - DB (res0 plaintext) = the overwritten head part, as dwords
  - runtime backfill = copy DB dwords back over RVA (0x00000000 dword = keep file bytes)
  => rebuild(file_bytes, db_dwords) must equal the known true body (header+code)

Verify over ALL DB entries vs known true bodies from probe2 reflection dump.
"""
import struct, sys

EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DBF = '/workspace/repo_git/work/s5/mem5/res0_plain_s1_47.bin'
if len(sys.argv) > 2:
    EXE = sys.argv[2]
    DBF = sys.argv[3]
IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'

# ---- 1. parse DB: 24B header + entries [RVA u32][n u32][n x u32] ----
db = open(DBF, 'rb').read()
print('[db] size=%d head=%s' % (len(db), db[:24].hex()))
off = 24
entries = []
while off < len(db):
    rva, n = struct.unpack_from('<II', db, off)
    off += 8
    dw = list(struct.unpack_from('<%dI' % n, db, off))
    off += 4 * n
    entries.append((rva, dw))
print('[db] entries=%d consumed=%d/%d' % (len(entries), off, len(db)))

# ---- 2. known true bodies (code only) ----
il = open(ALL, 'rb').read()
bodies = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) < 5:
        continue
    try:
        tok = int(p[0], 16)
        bodies[tok] = (int(p[1]), int(p[4]))
    except ValueError:
        pass
print('[bodies] known=%d' % len(bodies))

# ---- 3. RVA -> token and RVA -> fileoff ----
import dnfile
pe = dnfile.dnPE(EXE)
md = pe.net.mdtables
rva2tok = {}
for i, row in enumerate(md.MethodDef.rows):
    if row.Rva:
        rva2tok[row.Rva] = 0x06000001 + i
exe = open(EXE, 'rb').read()

def foff(rva):
    return pe.get_offset_from_rva(rva)

# ---- 4. verify ----
MODE = sys.argv[1] if len(sys.argv) > 1 else 'skip0'   # skip0 | writeall
ok = fail = notok = zerow = 0
fails = []
tiny_ok = fat_ok = 0
for rva, dw in entries:
    tok = rva2tok.get(rva)
    if tok is None or tok not in bodies:
        notok += 1
        continue
    clen, pos = bodies[tok]
    code = il[pos:pos + clen]
    dbytes = b''.join(struct.pack('<I', d) for d in dw)
    b0 = dbytes[0]
    if (b0 & 3) == 2:
        hdr = bytes([(clen << 2) | 2])
        true_full = hdr + code
    else:
        flags = struct.unpack_from('<H', dbytes, 0)[0]
        headsize = (flags >> 12) * 4
        codesize = struct.unpack_from('<I', dbytes, 4)[0]
        if codesize != clen:
            pass  # header codesize mismatch counted via compare below
        true_full = dbytes[:12] + code
        # NOTE: EH (moresects) tail not modeled; if flags bit3 set and mismatch -> inspect
    L = len(true_full)
    fo = foff(rva)
    buf = bytearray(exe[fo:fo + L])
    if len(buf) < L:
        fail += 1
        fails.append((tok, rva, 'short-read'))
        continue
    zero_in_file = 0
    for i, d in enumerate(dw):
        if i * 4 >= L:
            break
        if d != 0 or MODE == 'writeall':
            if d == 0:
                zero_in_file += 1
            buf[i * 4:i * 4 + 4] = struct.pack('<I', d)
    rebuilt = bytes(buf[:L])  # compare only true-body length; dword pad tail is 4B-alignment filler
    if rebuilt == true_full:
        ok += 1
        if (b0 & 3) == 2:
            tiny_ok += 1
        else:
            fat_ok += 1
    else:
        fail += 1
        if len(fails) < 25:
            d0 = next((k for k in range(min(L, len(buf))) if bytes(buf)[k] != true_full[k]), -1)
            fails.append((hex(tok), hex(rva), 'L=%d n=%d' % (L, len(dw) * 4),
                          'db=' + dbytes.hex(),
                          'reb=' + bytes(buf).hex(),
                          'tru=' + true_full.hex(),
                          'file=' + exe[fo:fo + max(L, len(dw) * 4)].hex(),
                          'diff@%d' % d0))
print('[MODE=%s] ok=%d (tiny=%d fat=%d) fail=%d notok=%d zero_kept=%d' % (MODE, ok, tiny_ok, fat_ok, fail, notok, zerow))
for f in fails[:25]:
    print('  FAIL', f)
