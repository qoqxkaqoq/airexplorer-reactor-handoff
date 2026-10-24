#!/usr/bin/env python3
# Brute force k0 (first key word of 0600418B chain) under kw=1 hypothesis.
# s0 = k0 (v4=0); out0 = prng_round(s0); plain0 = ct0 ^ out0 = [len,0,0,0], len<1024.
# Validation: plain1 = ct1 ^ prng_round(s1), s1 = v4_1 + k0, v4_1 = s0 + out0; plain1 also [len,0,0,0].
import numpy as np, struct, sys, time
sys.path.insert(0, '/workspace/airexplorer-reactor-handoff/work')
from decrypt_prng import prng_round, u32

M = np.uint64(0xFFFFFFFF)
U64 = np.uint64((1 << 64) - 1)
K1 = np.uint64(506503628); K1B = np.uint64(u32(1610158714 + 1328951073 - 1267867220))
K2 = np.uint64(1959015338); K3 = np.uint64(854276594); K4 = np.uint64(41684485)

def prng_round_vec(v9):
    v9 = v9 & M
    v43 = ((K1 * v9) & M)
    v43 = np.where(v43 == np.uint64(0), U64, v43)
    v40 = (((K3 * K3) & M) % v43) & M
    rot = (K2 >> np.uint64(9)) | ((K2 << np.uint64(23)) & M)
    v45 = (rot + v9) & M
    v39 = (((v45 & np.uint64(0xAAAAAAAA)) >> np.uint64(1)) |
           ((v45 & np.uint64(0x55555555)) << np.uint64(1)))
    v41x = np.where(v9 == np.uint64(0), np.uint64(0xFFFFFFFF), v9)
    v44 = ((v40 // v41x) + v41x) & M
    v41 = (((v40 + v40) - v44) + v40) & M
    rot4 = ((K4 << np.uint64(10)) & M) | (K4 >> np.uint64(22))
    v45b = (rot4 + v40) & M
    v42 = (((v45b >> np.uint64(8)) & np.uint64(0x00FF00FF)) |
           ((v45b << np.uint64(8)) & np.uint64(0xFF00FF00)))
    v41 = v41 ^ (v41 >> np.uint64(3))
    v41 = (v41 + K1B) & M
    v41 = v41 ^ ((v41 << np.uint64(7)) & M)
    v41 = (v41 + v41) & M
    v41 = v41 ^ (v41 >> np.uint64(29))
    v41 = (v41 + v42) & M
    v41 = (v41 + ((((v39 << np.uint64(4)) & M) - v40) ^ K1B)) & M
    return (v9 + v41) & M

# self test vs scalar
for tv in (0, 1, 0xDEADBEEF, 0xFFFFFFFF):
    assert int(prng_round_vec(np.array([tv], dtype=np.uint64))[0]) == prng_round(tv), tv
print('vec self-test OK')

ct = open('/workspace/airexplorer-reactor-handoff/work/res_GlobalValidator.FactoryValidator.bin', 'rb').read()
ct0 = u32(ct[0] | (ct[1] << 8) | (ct[2] << 16) | (ct[3] << 24))
ct1 = u32(ct[4] | (ct[5] << 8) | (ct[6] << 16) | (ct[7] << 24))
print(f'ct0={ct0:08x} ct1={ct1:08x}')

t0 = time.time()
survivors = []
CH = 1 << 23
for base in range(0, 1 << 32, CH):
    cand = np.arange(base, base + CH, dtype=np.uint64)
    out0 = prng_round_vec(cand)
    plain0 = (out0 ^ np.uint64(ct0)) & np.uint64(0xFFFFFFFF)
    mask = (plain0 & np.uint64(0xFFFFFF00)) == np.uint64(0)   # [len,0,0,0]
    idx = np.nonzero(mask)[0]
    for ix in idx:
        k0 = base + int(ix)
        # deeper check with block1
        s0 = k0 & M32 if False else u32(k0)
        o0 = int(out0[ix]) & 0xFFFFFFFF
        p0 = u32(o0 ^ ct0)
        if not (0 < p0 < 1024): continue
        v4_1 = u32(s0 + o0)
        s1 = u32(v4_1 + s0)  # k0 == s0 under kw=1
        o1 = prng_round(s1)
        p1 = u32(int(o1) ^ ct1)
        if (p1 & 0xFFFFFF00) == 0 and 0 < p1 < 1024:
            survivors.append((k0, p0, p1))
            print(f'SURVIVOR k0={k0:#010x} len0={p0} len1={p1}')
    if (base >> 26) % 8 == 0:
        print(f'{base >> 26}/64 chunks {time.time()-t0:.0f}s', flush=True)
print(f'DONE {time.time()-t0:.0f}s survivors={len(survivors)}')
