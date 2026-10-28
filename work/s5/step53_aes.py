# -*- coding: utf-8 -*-
"""step53: AES-CBC test with recovered key/IV candidates against res[0]/res[5]."""
import struct, json, itertools, dnfile
from Crypto.Cipher import AES

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
pe = dnfile.dnPE(BASE)
cor20 = pe.net.struct
rbase = pe.get_offset_from_rva(cor20.ResourcesRva)
data = open(BASE, 'rb').read()
RES = [(0x0, 356328), (0x56FEC, 256), (0x570F0, 47915), (0x62C1F, 26128), (0x69233, 2337031), (0x2A3B3E, 398794)]
res = {}
for idx, (off, sz) in enumerate(RES):
    res[idx] = data[rbase+off+4:rbase+off+4+sz]

maj = json.load(open('/workspace/repo_git/work/s5/out_419c_majority.json'))
cand = json.load(open('/workspace/repo_git/work/s5/out_419c_cand.json'))

arr32 = bytes(maj['32'])  # loc 0x20 (printed as '32')
arr16 = bytes(maj['16'])
print('key32:', arr32.hex())
print('iv16 :', arr16.hex())

def looks_ok(pt):
    printable = sum(1 for b in pt if 32 <= b < 127 or b in (0,))
    return printable / len(pt) > 0.7

for name, blob in (('res0', res[0]), ('res5', res[5])):
    for klen, key in ((32, arr32), (16, arr16)):
        for ivname, iv in (('iv16', arr16), ('iv32head', arr32[:16]), ('zero', b'\0'*16)):
            c = AES.new(key[:klen], AES.MODE_CBC, iv)
            pt = c.decrypt(blob[:256])
            score = sum(1 for b in pt[:64] if 32 <= b < 127 or b == 0) / 64
            tag = '  <<< HIT' if looks_ok(pt[:64]) else ''
            print('%s key%d %s: %s %s%s' % (name, klen, ivname, pt[:32].hex(), '%.2f' % score, tag))

# combos from candidate sets for loc32 idx0 conflicts
c32 = cand['32']
c16 = cand['16']
v0_32 = [v for v, c in c32.get('0', [])]
print('loc32 idx0 candidates:', [hex(v) for v in v0_32])
v0_16 = [v for v, c in c16.get('0', [])]
print('loc16 idx0 candidates:', [hex(v) for v in v0_16])
