#!/usr/bin/env python3
# rk27b.py — 在堆 region dump 里全窗口扫候选 AOT key（对 Proc/Emitter 密文头解密打分）。
# prng_round(s) = s + v41(s)，v41 用 numpy 向量化（同 v41brute.py 风格）。
import numpy as np, struct, sys, os

M32 = np.uint32(0xFFFFFFFF)
U64 = np.uint64(0xFFFFFFFFFFFFFFFF)
K1 = np.uint32(506503628); K2 = np.uint32(1959015338); K3 = np.uint32(854276594); K4 = np.uint32(41684485)
K1B = np.uint32((1610158714 + 1328951073 - 1267867220) & 0xFFFFFFFF)
ROTK2 = np.uint32(0xD53A6219); ROTK4 = np.uint32(0xF0381409)
K3K3 = np.uint64((854276594 * 854276594) & 0xFFFFFFFF)

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

def decrypt_head_dwords(cand_u32, ct_dwords, nwords=16):
    """cand_u32: (N,8) uint32 候选 key；返回 (N, nwords) 明文 dword（小端值）。"""
    N = cand_u32.shape[0]
    state = np.zeros(N, dtype=np.uint32)
    out = np.zeros((N, nwords), dtype=np.uint32)
    for i in range(nwords):
        state = (state + cand_u32[:, i % 8]).astype(np.uint32)
        state = (state + v41_batch(state)).astype(np.uint32)
        out[:, i] = ct_dwords[i] ^ state
    return out

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
f = open(W + r'\airexplorer-reactor-handoff\exes\AirExplorer_baseline_verified.exe', 'rb').read()
def ct_bswap_dwords(off, n=16):
    ct = f[off:off + n * 4]
    dws = []
    for i in range(n):
        c = (ct[i*4] << 24) | (ct[i*4+1] << 16) | (ct[i*4+2] << 8) | ct[i*4+3]
        dws.append(np.uint32(c))
    return np.array(dws, dtype=np.uint32)

PROC = ct_bswap_dwords(0x6784b4)
EMIT = ct_bswap_dwords(0x6783b0)

# 验证：已知 key 在自家资源上应得高 small 计数
KNOWN = {
    'Viewer': bytes.fromhex('f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943'),
    'mainlib': bytes.fromhex('cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481'),
    'Factory': bytes.fromhex('37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a'),
}
VIEWER_CT = ct_bswap_dwords(0x6213c4)
cand = np.array([struct.unpack('<8I', KNOWN['Viewer'])], dtype=np.uint32)
out = decrypt_head_dwords(cand, VIEWER_CT)
small = (out < np.uint32(0x930000)).sum(axis=1)
print('self-check Viewer key vs Viewer ct: small=%d/16 (期望高)' % small[0])

fn = sys.argv[1] if len(sys.argv) > 1 else W + r'\work_a1\rk27\out\region_27e80000000.bin'
data = open(fn, 'rb').read()
print('scan %s (%d B)' % (os.path.basename(fn), len(data)))
arr = np.frombuffer(data, dtype=np.uint8)
N = (len(data) - 32) // 4
b = arr[: N * 4].reshape(N, 4).copy()
b4 = b[:, 0].astype(np.uint32) | (b[:, 1].astype(np.uint32) << np.uint32(8)) | (b[:, 2].astype(np.uint32) << np.uint32(16)) | (b[:, 3].astype(np.uint32) << np.uint32(24))
# 候选 = 连续 8 个 dword（起点每 4 字节滑动）；strides 以字节计：行 4、列 4
cand = np.lib.stride_tricks.as_strided(b4, shape=(N - 7, 8), strides=(4, 4)).copy()
print('candidates:', cand.shape[0])

for tgt_name, ct in (('Proc', PROC), ('Emitter', EMIT)):
    out = decrypt_head_dwords(cand, ct)
    small = (out < np.uint32(0x930000)).sum(axis=1)
    tags = ((out == 0) | (out == 1) | (out == 2) | (out == 3)).sum(axis=1)
    score = small.astype(np.int32) * 2 + tags.astype(np.int32)
    top = np.argsort(score)[-12:][::-1]
    print('== %s top candidates ==' % tgt_name)
    for idx in top:
        if score[idx] < 12:
            break
        off = int(idx) * 4
        key = data[off:off + 32].hex()
        print('  off=0x%-8x small=%2d tags=%2d score=%2d key=%s' % (off, small[idx], tags[idx], score[idx], key))
