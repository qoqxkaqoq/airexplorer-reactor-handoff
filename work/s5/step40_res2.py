# -*- coding: utf-8 -*-
"""step40: parse res[2] 'ValidatorAllocator.ValidatorProc' (47915B, low entropy) — candidate method-body index."""
import struct, dnfile

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
data = open(BASE, 'rb').read()
pe = dnfile.dnPE(BASE)
cor20 = pe.net.struct
base = pe.get_offset_from_rva(cor20.ResourcesRva)

# res[2] at off=0x570F0, 4-byte size prefix
doff = base + 0x570F0
size = struct.unpack_from('<I', data, doff)[0]
blob = data[doff+4:doff+4+size]
print('res[2] size=%d' % size)
print('head 96B:', blob[:96].hex())

# byte histogram of first byte of every 6-byte group (alignment probe)
import collections
for stride in (6, 8):
    c0 = collections.Counter(blob[i] for i in range(0, len(blob) - stride, stride))
    print('stride=%d first-byte top: %s' % (stride, c0.most_common(6)))

# try: u16 triplets
vals = struct.unpack('<%dH' % (len(blob)//2), blob[:len(blob)//2*2])
print('first 40 u16:', [hex(v) for v in vals[:40]])

# hypothesis: [u16 a][u32 off] or [u32 tok-related][u16 size]
u32s = struct.unpack('<%dI' % (len(blob)//4), blob[:len(blob)//4*4])
print('first 24 u32:', [hex(v) for v in u32s[:24]])

# cumulative-sum check for u16 pairs as (size,?) — do sizes sum to payload size?
h16 = vals
# try interpret as repeated [count][sizes...] blocks?
# entropy per 256B chunk to find header/tail boundary
import math
for o in range(0, 512, 64):
    c = collections.Counter(blob[o:o+64])
    e = -sum((n/64)*math.log2(n/64) for n in c.values())
    print('chunk @%04X ent=%.2f %s' % (o, e, blob[o:o+16].hex()))
print('...')
for o in (len(blob)//2, len(blob)-256, len(blob)-64):
    c = collections.Counter(blob[o:o+64])
    e = -sum((n/64)*math.log2(n/64) for n in c.values())
    print('chunk @%06X ent=%.2f %s' % (o, e, blob[o:o+16].hex()))
