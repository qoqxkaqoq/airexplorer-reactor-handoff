#!/usr/bin/env python3
# probe_prng_al.py — PRNG-chain probe with BYTE-GRANULAR alignment (ProbeB only tried 4B-aligned).
# For every byte offset o in payload: ks0 = u32le(pay[o:o+4]) ^ P[0:4],
# ks1 = u32le(pay[o+4:o+8]) ^ P[4:8]; test prng_round(ks0) == ks1 (seed-free).
# Fully vectorized in numpy (prng_round is elementwise). Hit -> verify 32B exactly.
import struct, sys
import numpy as np

EXE = '/workspace/airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe'
DUMPDIR = '/tmp/dumps'
M = np.uint64(0xFFFFFFFF)
U64 = np.uint64((1 << 64) - 1)
K1 = 506503628
K1B = (1610158714 + 1328951073 - 1267867220) & 0xFFFFFFFF
K2 = 1959015338
K3 = 854276594
K4 = 41684485
K3K3 = (K3 * K3) & 0xFFFFFFFF

def prng_round_vec(v9):
    """vectorized prng_round over uint64 numpy array (values < 2^32)"""
    v9 = v9 & M
    v43 = ((np.uint64(K1) * v9) & M)
    v43 = np.where(v43 == 0, U64, v43)
    v40 = ((np.uint64(K3K3) % v43) & M)
    rot = (np.uint64(K2) >> np.uint64(9)) | ((np.uint64(K2) << np.uint64(23)) & M)
    v45 = (rot + v9) & M
    v39 = (((v45 & np.uint64(0xAAAAAAAA)) >> np.uint64(1)) |
           ((v45 & np.uint64(0x55555555)) << np.uint64(1)))
    v38 = np.uint64(K1B)
    v41x = np.where(v9 == 0, np.uint64(0xFFFFFFFF), v9)
    v44 = ((v40 // v41x) + v41x) & M
    v41 = (((v40 + v40) - v44) + v40) & M
    rot4 = ((np.uint64(K4) << np.uint64(10)) & M) | (np.uint64(K4) >> np.uint64(22))
    v45b = (rot4 + v40) & M
    v42 = (((v45b >> np.uint64(8)) & np.uint64(0x00FF00FF)) |
           ((v45b << np.uint64(8)) & np.uint64(0xFF00FF00)))
    v41 = v41 ^ (v41 >> np.uint64(3))
    v41 = (v41 + v38) & M
    v41 = v41 ^ ((v41 << np.uint64(7)) & M)
    v41 = (v41 + v41) & M
    v41 = v41 ^ (v41 >> np.uint64(29))
    v41 = (v41 + v42) & M
    v41 = (v41 + ((((v39 << np.uint64(4)) & M) - v40) ^ v38)) & M
    return (v9 + v41) & M

def prng_round_ref(v):
    sys.path.insert(0, '/workspace/airexplorer-reactor-handoff/work')
    from decrypt_prng import prng_round
    return prng_round(v)

def payload_bytes():
    d = open(EXE, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    for i in range(nsec):
        o = pe + 24 + optsz + 40 * i
        name = d[o:o+8].rstrip(b'\0').decode()
        vsz, va, rsz, ro = struct.unpack_from('<IIII', d, o + 8)
        if name == '.text':
            p_lo = ro + (0x620000 - va)
            p_hi = ro + (0x920000 - va)
            return d[p_lo:p_hi], p_lo
    raise SystemExit('.text not found')

pay, p_lo = payload_bytes()
print(f'payload {len(pay)} bytes at file 0x{p_lo:X}')

# self-test vectorized vs scalar
import random
random.seed(1)
sys.path.insert(0, '/workspace/airexplorer-reactor-handoff/work')
from decrypt_prng import prng_round
tv = np.array([random.getrandbits(32) for _ in range(64)], dtype=np.uint64)
rv = prng_round_vec(tv)
ok = all(int(rv[i]) == prng_round(int(tv[i])) for i in range(64))
print(f'vec self-test: {"OK" if ok else "MISMATCH!"}')
if not ok:
    raise SystemExit(1)

# u32 little-endian at EVERY byte offset
u = np.frombuffer(pay, dtype=np.uint8).astype(np.uint64)
u32_at = (u[:-3] | (u[1:-2] << np.uint64(8)) |
          (u[2:-1] << np.uint64(16)) | (u[3:] << np.uint64(24)))
print(f'u32_at entries: {len(u32_at)}')

import os
probes = ['m_0600428A.bin', 'm_0600212A.bin', 'm_06002133.bin', 'm_06004192.bin',
          'm_0600419C.bin', 'm_06004193.bin']
extra = [x for x in sorted(os.listdir(DUMPDIR)) if x.endswith('.bin')
         and 200 <= os.path.getsize(os.path.join(DUMPDIR, x)) - 24 <= 400][:4]
probes += extra

total_hits = 0
for name in probes:
    p = os.path.join(DUMPDIR, name)
    if not os.path.exists(p):
        print(f'{name}: (no dump, skip)'); continue
    dmp = open(p, 'rb').read()
    tok = struct.unpack_from('<I', dmp, 0)[0]
    ilSize = struct.unpack_from('<i', dmp, 4)[0]
    body = dmp[24:24 + ilSize]
    if len(body) < 8:
        print(f'{name}: body too short'); continue
    P0 = struct.unpack('<I', body[0:4])[0]
    P1 = struct.unpack('<I', body[4:8])[0]
    # ks0[i] = u32_at[i] ^ P0 ; ks1[i] = u32_at[i+4] ^ P1
    ks0 = (u32_at[:-7] ^ np.uint64(P0)) & M
    ks1 = (u32_at[4:-3] ^ np.uint64(P1)) & M
    nxt = prng_round_vec(ks0)
    hits = np.nonzero(nxt == ks1)[0]
    # verify exactly (32B chain) with scalar reference
    real = []
    for h in hits:
        o = int(h)
        if 4 * 8 > len(body):
            break
        # exact 32B: recompute chain over words o..o+7
        w = int(ks0[o]); ok = True
        for j in range(1, 8):
            w = prng_round_ref(w)
            c = int(u32_at[o + 4 * j]) ^ int(struct.unpack_from('<I', body, 4 * j)[0])
            if w != c:
                ok = False; break
        if ok:
            real.append(o)
    if real:
        total_hits += len(real)
        print(f'*** HIT {name} tok={tok:08X} il={ilSize}: payload-offs '
              f'{[hex(p_lo + o) for o in real[:5]]}')
    else:
        print(f'miss {name} tok={tok:08X} il={ilSize} (1-jump cands={len(hits)})')
print(f'TOTAL HITS: {total_hits}')
