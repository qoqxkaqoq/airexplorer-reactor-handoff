#!/usr/bin/env python3
# Try: payload stores per-method records [tok, ilSize, maxStack, eh, preExtra, localsTok] + IL.
# Known first word = 0x0600212A. Scan all resources with full cycle keystream (36818 words).
import struct, sys
sys.path.insert(0, '/workspace/airexplorer-reactor-handoff/work')
from decrypt_prng import prng_round

# build full cycle from seed 0
CY = 1 << 20
ks = []
v9 = 0
seen = {}
start = None
for j in range(CY):
    if v9 in seen:
        start = seen[v9]
        break
    seen[v9] = j
    ks.append(v9)
    v9 = prng_round(v9)
print('cycle: first repeat at j=%d (start=%d) unique=%d' % (j, start, len(ks)), flush=True)

KNOWNS = [
    ("body 0600212A", 0x3d7b021e, 0x2a04000c, 0x3b7b021e, 0x2a04000c),
    ("body 06003909", 0x0007301b, 0x0008009d, 0x11000ae8, 0x00419428),
    ("body 06002BD1", 0x0006301b, 0x00080331, 0x1100087d, 0x00419428),
    ("hdr  0600212A", 0x0600212A, 0x10, None, None),
    ("hdr  06003909", 0x06003909, None, None, None),
    ("hdr  06002BD1", 0x06002BD1, None, None, None),
    ("hdr  0600418B", 0x0600418B, None, None, None),
]

import os
RES = '/workspace/airexplorer-reactor-handoff/work'
n = len(ks)
for f in sorted(x for x in os.listdir(RES) if x.startswith('res_') and x.endswith('.bin')):
    data = open(os.path.join(RES, f), 'rb').read()
    nw = len(data) // 4
    ct = struct.unpack('<%dI' % nw, data[:nw * 4])
    out = []
    for name, p0, p1, p2, p3 in KNOWNS:
        hits = 0
        for i in range(nw - 3):
            j = seen.get(ct[i] ^ p0)
            if j is None: continue
            if p1 is None:
                hits += 1
                if hits <= 3: out.append('%s @res+%x ks=%d' % (name, i * 4, j))
            else:
                if (ct[i+1] ^ ks[(j+1) % n]) == p1 and (ct[i+2] ^ ks[(j+2) % n]) == p2 and (ct[i+3] ^ ks[(j+3) % n]) == p3:
                    hits += 1
                    if hits <= 3: out.append('%s @res+%x ks=%d' % (name, i * 4, j))
        if hits: out.append('%s total=%d' % (name, hits))
    print(f, '->', out if out else 'no hits', flush=True)
print('done')
