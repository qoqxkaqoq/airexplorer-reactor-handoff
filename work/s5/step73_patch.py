#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step73: keystream recovery + A1 five-patch -> AirExplorer_a1.exe

Facts (step72 verified, 14252/14252):
  - res0 plaintext = method-body DB: 24B head + entries [RVA u32][n u32][n x u32]
  - file body at RVA = stub + plaintext tail; DB dwords written back to RVA = true body
Patch plan:
  P1 06002133 IL+0x290 : 0x16 -> 0x17   (file direct, deep in plaintext tail)
  P2 06002145 IL+0x120 : 0x16 -> 0x17   (file direct)
  P3 0600212A body -> ldc.i4.1; ret    (DB dword rewrite -> cipher delta)
  P4 06002157 body -> ldc.i4.1; ret    (DB dword rewrite -> cipher delta)
  P5 06002127 body -> ldc.i4.1; ret    (DB dword rewrite -> cipher delta)
  cipher' = cipher ^ (plain ^ plain')  ==  cipher ^ delta   (byte-aligned XOR stream)
"""
import struct

EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DBF = '/workspace/repo_git/work/s5/mem5/res0_plain_s1_47.bin'
IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
OUT = '/workspace/repo_git/exes/AirExplorer_a1.exe'

exe = bytearray(open(EXE, 'rb').read())
db = bytearray(open(DBF, 'rb').read())

# ---- A. locate res0 cipher resource in file ----
import dnfile
pe = dnfile.dnPE(EXE)
md = pe.net.mdtables
base = pe.get_offset_from_rva(pe.net.struct.ResourcesRva)
cipher_off = None
for r in md.ManifestResource.rows:
    p = base + r.Offset
    ln = struct.unpack_from('<I', exe, p)[0]
    nm = str(r.Name)
    if ln == len(db):
        print('[res] %s offset=%#x len=%d  <-- res0 cipher' % (nm, p + 4, ln))
        cipher_off = p + 4
if cipher_off is None:
    raise SystemExit('res0 cipher resource not found')

# ---- B. keystream = cipher ^ plain ----
cipher = bytes(exe[cipher_off:cipher_off + len(db)])
ks = bytes(a ^ b for a, b in zip(cipher, db))
print('[ks] head32=%s' % ks[:32].hex())
print('[ks] tail32=%s' % ks[-32:].hex())
# periodicity check on first 4096 bytes
seg = ks[:4096]
for P in (16, 32, 64, 128, 256, 512, 1024, 2048):
    if seg[:P] == seg[P:2 * P]:
        print('[ks] PERIODIC period=%d' % P)
        break
else:
    print('[ks] no simple period up to 2048 (stream/AES-CTR-like) -> delta patch is position-static, still valid')

# ---- C. parse DB entries & index targets ----
off = 24
ent = []  # (rva, eoff, n)
while off < len(db):
    rva, n = struct.unpack_from('<II', db, off)
    ent.append((rva, off, n))
    off += 8 + 4 * n
rva2e = {r: (o, n) for r, o, n in ent}
print('[db] entries=%d' % len(ent))

TOK = {0x0600212A: 'P3', 0x06002157: 'P4', 0x06002127: 'P5',
       0x06002133: 'P1', 0x06002145: 'P2'}
rva2tok = {}
for i, row in enumerate(md.MethodDef.rows):
    if row.Rva:
        rva2tok[row.Rva] = 0x06000001 + i

# known bodies for sanity
bodies = {}
il = open(ALL, 'rb').read()
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        bodies[int(p[0], 16)] = (int(p[1]), int(p[4]))

NEWBODY = bytes([0x17, 0x2A])          # ldc.i4.1 ; ret
NEWFULL = bytes([(len(NEWBODY) << 2) | 2]) + NEWBODY   # tiny hdr 0x0A

patches_res = []  # (name, rva, old_hex, new_hex)
for tok, tag in TOK.items():
    rva = None
    for i, row in enumerate(md.MethodDef.rows):
        if 0x06000001 + i == tok:
            rva = row.Rva
    if rva is None or rva not in rva2e:
        raise SystemExit('%s %s RVA %#x not in DB' % (tag, hex(tok), rva or 0))
    eo, n = rva2e[rva]
    old = bytes(db[eo + 8:eo + 8 + 4 * n])
    if tag in ('P3', 'P4', 'P5'):
        new = bytearray(old)
        new[0:len(NEWFULL)] = NEWFULL
        new[len(NEWFULL):] = b'\x00' * (len(new) - len(NEWFULL))
        db[eo + 8:eo + 8 + 4 * n] = new
        patches_res.append((tag, rva, n, old.hex(), bytes(new).hex()))
    else:
        clen, pos = bodies[tok]
        code = il[pos:pos + clen]
        iloff = 0x290 if tag == 'P1' else 0x120
        fo = pe.get_offset_from_rva(rva)
        fpos = fo + 12 + iloff  # fat head 12B sits in DB zone; file keeps code from +12
        cur = exe[fpos]
        print('[%s] tok=%s rva=%#x fileoff=%#x cur=%#x expect 0x16, code[%#x]=%#x' %
              (tag, hex(tok), rva, fpos, cur, iloff, code[iloff]))
        assert cur == 0x16 and code[iloff] == 0x16, '%s mismatch file=%#x plain=%#x' % (tag, cur, code[iloff])
        exe[fpos] = 0x17
        patches_res.append((tag, rva, n, 'file@%#x=0x16' % fpos, '0x17'))

# ---- D. cipher delta patch (P3/P4/P5) ----
db_old = open(DBF, 'rb').read()
delta = bytes(a ^ b for a, b in zip(db_old, db))
nz = [i for i, b in enumerate(delta) if b]
print('[delta] nonzero=%d bytes at %s' % (len(nz), nz[:32]))
for i in nz:
    exe[cipher_off + i] ^= delta[i]

# ---- E. self-test: patched cipher ^ ks == patched plain ----
cipher2 = bytes(exe[cipher_off:cipher_off + len(db)])
ok = all((cipher2[i] ^ ks[i]) == db[i] for i in range(len(db)))
print('[selftest] cipher2 ^ ks == plain2 : %s' % ok)
if not ok:
    raise SystemExit('selftest FAILED')

open(OUT, 'wb').write(bytes(exe))
open('/workspace/repo_git/work/s5/mem5/res0_plain_a1.bin', 'wb').write(bytes(db))
print('[out] %s size=%d' % (OUT, len(exe)))
import hashlib
print('[out] md5=%s' % hashlib.md5(bytes(exe)).hexdigest().upper())
for t, r, n, o, w in patches_res:
    print('  %s rva=%#x n=%d  %s -> %s' % (t, r, n, o, w))
