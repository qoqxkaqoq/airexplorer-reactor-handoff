#!/usr/bin/env python3
# Scan all 6 resources for the seed-0 PRNG keystream hypothesis:
#   if payload = plain XOR keystream(seed=0) from byte 0 (word-aligned),
#   then for each word position i: plain[i] = ct[i] ^ ks[i].
# Known plaintext from TTD run 40125259583 (backfill write events):
#   0600212A: 1e027b3d 0c00042a 1e027b3b 0c00042a  (2 tiny getters)
#   06003909: 1b300700 9d080000 e80a0011 28944100  (fat hdr + code)
#   06002BD1: 1b300600 31030000 7d080011 28944100
import struct, sys
sys.path.insert(0, '/workspace/airexplorer-reactor-handoff/work')
from decrypt_prng import keystream

KNOWNS = [
    ("0600212A", [0x3d7b021e, 0x2a04000c, 0x3b7b021e, 0x2a04000c]),
    ("06003909", [0x0007301b, 0x0008009d, 0x11000ae8, 0x00419428]),
    ("06002BD1", [0x0006301b, 0x00080331, 0x1100087d, 0x00419428]),
]

RES = '/workspace/airexplorer-reactor-handoff/work'
import os
cands = sorted(f for f in os.listdir(RES) if f.startswith('res_') and f.endswith('.bin'))

def words(data, nw):
    # LE uint32 array of first nw words
    return list(struct.unpack_from('<%dI' % nw, data, 0))

for f in cands:
    path = os.path.join(RES, f)
    data = open(path, 'rb').read()
    nw = len(data) // 4
    ks = keystream(nw)   # seed 0
    c = words(data, nw)
    for tok, plains in KNOWNS:
        p0 = plains[0]
        hits = []
        for i in range(nw - 3):
            if (c[i] ^ ks[i]) == p0:
                if (c[i+1] ^ ks[i+1]) == plains[1] and \
                   (c[i+2] ^ ks[i+2]) == plains[2] and \
                   (c[i+3] ^ ks[i+3]) == plains[3]:
                    hits.append(i)
        print(f, tok, 'hits:', [hex(h*4) for h in hits])
print('done')
