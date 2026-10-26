#!/usr/bin/env python3
# v41brute.py — numpy brute-force: find s with v41(s)==ks0 and v41(s+ks0)==ks1
import numpy as np, struct, zipfile, sys
M32 = np.uint32(0xFFFFFFFF)
U64 = np.uint64(0xFFFFFFFFFFFFFFFF)
K1 = np.uint32(506503628); K2 = np.uint32(1959015338); K3 = np.uint32(854276594); K4 = np.uint32(41684485)
K1B = np.uint32((1610158714 + 1328951073 - 1267867220) & 0xFFFFFFFF)
ROTK2 = np.uint32(0xD53A6219); ROTK4 = np.uint32(0xF0381409)
K3K3 = np.uint64((K3 * K3) & np.uint32(0xFFFFFFFF))

def v41_batch(s):
    s = s.astype(np.uint32)
    v43 = (K1 * s).astype(np.uint32)
    v43u = v43.astype(np.uint64)
    v43u[v43 == 0] = U64
    v40 = (K3K3 % v43u).astype(np.uint32)
    v45 = (ROTK2 + s).astype(np.uint32)
    v39 = (((v45 & np.uint32(0xAAAAAAAA)) >> np.uint32(1)) | ((v45 & np.uint32(0x55555555)) << np.uint32(1))).astype(np.uint32)
    v41x = np.where(s == 0, np.uint32(0xFFFFFFFF), s).astype(np.uint32)
    v44 = (v40 // v41x + v41x).astype(np.uint32)
    v41 = ((v40 + v40) - v44 + v40).astype(np.uint32)
    v45b = (ROTK4 + v40).astype(np.uint32)
    v42 = (((v45b & np.uint32(0xFF00FF00)) >> np.uint32(8)) | ((v45b & np.uint32(0x00FF00FF)) << np.uint32(8))).astype(np.uint32)
    v41 = (v41 ^ (v41 >> np.uint32(3))).astype(np.uint32)
    v41 = (v41 + K1B).astype(np.uint32)
    v41 = (v41 ^ ((v41 << np.uint32(7)) & M32)).astype(np.uint32)
    v41 = (v41 + v41).astype(np.uint32)
    v41 = (v41 ^ (v41 >> np.uint32(29))).astype(np.uint32)
    v41 = (v41 + v42).astype(np.uint32)
    v41 = (v41 + (((((v39 << np.uint32(4)) & M32) - v40) & M32) ^ K1B)).astype(np.uint32)
    return v41

def brute(ks0, ks1, chunk=1<<24):
    ks0 = np.uint32(ks0); ks1 = np.uint32(ks1)
    base = 0
    while base < 1<<32:
        s = np.arange(base, min(base+chunk, 1<<32), dtype=np.uint32)
        v = v41_batch(s)
        mask = v == ks0
        if mask.any():
            cand = s[mask]
            for c in cand:
                c2 = (c + ks0).astype(np.uint32)
                if v41_batch(np.array([c2]))[0] == ks1:
                    return int(c)
        base += chunk
    return None

if __name__ == '__main__':
    W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
    mem = open(W + r'\work_a1\rtdump3\reg_24cb5140000.bin','rb').read()
    z = zipfile.ZipFile(W + r'\airexplorer-reactor-handoff\work\dump_official_16598.zip')
    pt = z.read('m_06002133.bin')[24:]
    ct = mem[0x194288:0x194288+len(pt)]
    ks = [int.from_bytes(bytes(a^b for a,b in zip(ct[i*4:i*4+4], pt[i*4:i*4+4])),'little') for i in range(8)]
    print('ks:', [hex(k) for k in ks])
    s0 = brute(ks[0], ks[1])
    print('s0 =', hex(s0) if s0 is not None else None)
    if s0 is not None:
        s = s0
        ok = True
        for k in ks[2:]:
            s = (s + v41_batch(np.array([s], dtype=np.uint32))[0]) & 0xFFFFFFFF
            if v41_batch(np.array([np.uint32(s)], dtype=np.uint32))[0] != np.uint32(k):
                ok = False; break
        print('full 8-dword chain:', ok)
