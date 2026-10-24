#!/usr/bin/env python3
# Hypothesis: payload ct word i decrypts with keystream word j (j independent of i,
# e.g. j = method sequence index). Scan (i, j) pairs via dict lookup:
#   plain[i] = ct[i] ^ ks[j]  ->  ks[j] = ct[i] ^ plain0, need 4 consecutive matches.
import struct, sys
sys.path.insert(0, '/workspace/airexplorer-reactor-handoff/work')
from decrypt_prng import keystream, prng_round

KS_RANGE = 1 << 22   # 4M words of keystream to pre-index

KNOWNS = [
    ("0600212A", [0x3d7b021e, 0x2a04000c, 0x3b7b021e, 0x2a04000c]),
    ("06003909", [0x0007301b, 0x0008009d, 0x11000ae8, 0x00419428]),
    ("06002BD1", [0x0006301b, 0x00080331, 0x1100087d, 0x00419428]),
]

path = '/workspace/airexplorer-reactor-handoff/work/res_ValidatorGenerator.DefinitionError.bin'
data = open(path, 'rb').read()
nw = len(data) // 4
ct = struct.unpack('<%dI' % nw, data[:nw * 4])

print('building ks dict %d words...' % KS_RANGE, flush=True)
ks = [0] * KS_RANGE
ksmap = {}
v9 = 0
for j in range(KS_RANGE):
    v9 = prng_round(v9)
    ks[j] = v9
    if v9 not in ksmap:
        ksmap[v9] = j
print('ks dict done, %d entries' % len(ksmap), flush=True)

for tok, plains in KNOWNS:
    hits = []
    p0, p1, p2, p3 = plains
    for i in range(nw - 3):
        j = ksmap.get(ct[i] ^ p0)
        if j is None: continue
        if j + 3 >= KS_RANGE: continue
        if (ct[i+1] ^ ks[j+1]) == p1 and (ct[i+2] ^ ks[j+2]) == p2 and (ct[i+3] ^ ks[j+3]) == p3:
            hits.append((i, j))
    print(tok, 'hits:', [(hex(a), hex(b)) for a, b in hits], flush=True)
print('done')
