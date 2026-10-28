#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step68: locate the 5 patch-target ciphertexts in the payload region via
known-plaintext x fixed-keystream double search.
cipher_w[p] = plain_w[i] ^ ks[k+i]  -> find (p, k) per body."""
import sys, struct, zipfile
sys.path.insert(0, '/workspace/repo_git/work')
from decrypt_prng import keystream
import dnfile

EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DUMPS = '/workspace/repo_git/work/dump_official_16598.zip'
TARGETS = ['06002133', '06002145', '0600212A', '06002157', '06002127']

pe = dnfile.dnPE(EXE)
data = pe.__data__
# map RVA 0x620000..0x920000 to file offsets
sec = None
for s in pe.sections:
    if s.VirtualAddress <= 0x620000 < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
        sec = s
        break
print('section:', sec.Name, 'VA=%06X' % sec.VirtualAddress, 'raw=%06X' % sec.PointerToRawData)
rva2off = lambda rva: sec.PointerToRawData + (rva - sec.VirtualAddress)
o0, o1 = rva2off(0x620000), rva2off(0x920000)
print('payload file offsets: %06X..%06X (%d bytes)' % (o0, o1, o1 - o0))

payload = bytes(data[o0:o1])
nw = len(payload) // 4
pw = struct.unpack_from('<%dI' % nw, payload, 0)

NK = 900000
print('generating %d keystream words...' % NK)
ks = keystream(NK)

# dict: 4-word (16B) window of payload -> position
print('building payload window dict (%d entries)...' % (nw - 3))
W = {}
for p in range(nw - 3):
    key = struct.pack('<4I', pw[p], pw[p+1], pw[p+2], pw[p+3])
    W[key] = p
print('dict built:', len(W))

Z = zipfile.ZipFile(DUMPS)
for t in TARGETS:
    d = Z.read('m_%s.bin' % t)
    ilSize = struct.unpack_from('<i', d, 4)[0]
    plain = d[24:24 + ilSize]
    n = min(4, ilSize // 4)
    plw = struct.unpack('<%dI' % n, plain[:n * 4])
    hits = []
    for k in range(NK - n):
        key = struct.pack('<4I', plw[0] ^ ks[k], plw[1] ^ ks[k+1], plw[2] ^ ks[k+2], plw[3] ^ ks[k+3])
        p = W.get(key)
        if p is not None:
            # verify 4 more words
            ok = 0
            for j in range(4, min(n if n > 4 else min(8, ilSize // 4), 8)):
                if p + j < nw and k + j < NK and pw[p + j] == (struct.unpack('<I', plain[j*4:j*4+4])[0] ^ ks[k + j]):
                    ok += 1
            hits.append((p, k, ok))
    print('%s ilSize=%d hits=%s' % (t, ilSize, hits[:8] if hits else 'NONE'))
