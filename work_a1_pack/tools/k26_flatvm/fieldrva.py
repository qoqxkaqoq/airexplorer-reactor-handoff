#!/usr/bin/env python3
# fieldrva.py — dump all FieldRVA rows + pointed-to data (si=4, gi=2, bi=4 verified via mdrva logic)
import struct, sys, binascii

EXE = r'airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe'
d = open(EXE, 'rb').read()
e = struct.unpack_from('<I', d, 0x3C)[0]
coff = e + 4
nsec, = struct.unpack_from('<H', d, coff + 2)
optsz, = struct.unpack_from('<H', d, coff + 16)
opt = coff + 20
magic, = struct.unpack_from('<H', d, opt)
ddoff = opt + (0x60 if magic == 0x10B else 0x70)
clr_rva, = struct.unpack_from('<I', d, ddoff + 14 * 8)
sec0 = opt + optsz
secs = []
for i in range(nsec):
    o = sec0 + i * 40
    va = struct.unpack_from('<I', d, o + 12)[0]; vsz = struct.unpack_from('<I', d, o + 8)[0]
    raw = struct.unpack_from('<I', d, o + 20)[0]; rawsz = struct.unpack_from('<I', d, o + 16)[0]
    secs.append((va, vsz, raw, rawsz))

def rva2off(rva):
    for va, vsz, raw, rawsz in secs:
        if va <= rva < va + max(vsz, rawsz):
            return raw + (rva - va)
    return None

cor = rva2off(clr_rva)
md_rva, md_sz = struct.unpack_from('<II', d, cor + 8)
mo = rva2off(md_rva)
vlen, = struct.unpack_from('<I', d, mo + 12)
p = mo + 16 + vlen
nstr, = struct.unpack_from('<H', d, p + 2); p += 4
streams = {}
for i in range(nstr):
    so, ssz = struct.unpack_from('<II', d, p)
    nm = d[p + 8:d.index(b'\0', p + 8)].decode()
    streams[nm] = (mo + so, ssz); p += 8 + len(nm) + 1; p = (p + 3) & ~3

tto, tsz = streams['#~']
hs = d[tto + 6]
si = 4 if hs & 1 else 2
gi = 4 if hs & 2 else 2
bi = 4 if hs & 4 else 2
print('HeapSizes flags=0x%02X si=%d gi=%d bi=%d' % (hs, si, gi, bi))
valid, = struct.unpack_from('<Q', d, tto + 8)
rows = {}
q = tto + 24
for b in range(64):
    if valid & (1 << b):
        rows[b], = struct.unpack_from('<I', d, q); q += 4
rowstart = q  # first table row starts here (after Valid 8 + Sorted 8)

def ci_size(tables):
    return 4 if any(rows.get(t, 0) > 0xFFFF for t in tables) else 2

RS = ci_size([0x00, 0x1A, 0x23, 0x01])
TDOR = ci_size([0x02, 0x01, 0x1B])
sz = {
    0x00: 2 + si + 3 * gi,
    0x01: RS + si + si,
    0x02: 4 + si + si + TDOR + ci_size([0x04]) + ci_size([0x06]),
    0x03: ci_size([0x04]),
    0x04: 2 + si + bi,
    0x05: ci_size([0x06]),
    0x06: 4 + 2 + 2 + si + bi + ci_size([0x08]),
    0x07: ci_size([0x06]),
    0x08: 2 + 2 + si,
    0x09: 2 + TDOR,
    0x0A: ci_size([0x02, 0x01, 0x1B, 0x1B, 0x06]) if False else 2 + si + bi,  # MemberRef: Class+Name+Sig
    0x0B: 2 + ci_size([0x04, 0x08, 0x17]) + bi,
    0x0C: 2 + 2 + bi,
    0x0D: 2 + bi,
    0x0E: 2 + 2 + bi,
    0x0F: 2 + 4 + 2,
    0x10: 4 + 2,
    0x11: bi,
    0x12: 2 + 2,
    0x13: 2,
    0x14: 2 + si + TDOR,
    0x15: 2 + 2,
    0x16: 2,
    0x17: 2 + si + bi,
    0x18: 2 + ci_size([0x06, 0x0A]) + ci_size([0x14, 0x17]),
    0x19: 2 + ci_size([0x06, 0x0A]) + ci_size([0x06, 0x0A]),
    0x1A: si,
    0x1B: bi,
    0x1C: 2 + ci_size([0x04, 0x06]) + si + ci_size([0x1A]),
}
off = rowstart
for b in sorted(sz):
    if b >= 0x1D:
        break
    if b in rows:
        off += sz[b] * rows[b]
nfr = rows.get(0x1D, 0)
fsz_fld = ci_size([0x04])
print('FieldRVA rows:', nfr)
out = {}
for r in range(nfr):
    ro = off + r * (4 + fsz_fld)
    if fsz_fld == 2:
        rva, fld = struct.unpack_from('<IH', d, ro)
    else:
        rva, fld = struct.unpack_from('<II', d, ro)
    fo = rva2off(rva)
    print('  field 0x%04X rva=0x%08X fileoff=0x%08X data64=%s' % (fld, rva, fo, d[fo:fo+64].hex() if fo else '??'))
    out[fld] = (rva, fo)

import json
json.dump({hex(k): [v[0], v[1]] for k, v in out.items()}, open('work_a1/k26/fieldrva.json', 'w'), indent=1)

# dump 256B for every field (candidates for the UInt32[64] table)
for fld, (rva, fo) in out.items():
    blk = d[fo:fo+256]
    dw = struct.unpack('<%dI' % min(64, len(blk)//4), blk[:256])
    nz = sum(1 for x in dw if x)
    print('field 0x%04X first256 nonzero-dwords %d/%d' % (fld, nz, len(dw)))
