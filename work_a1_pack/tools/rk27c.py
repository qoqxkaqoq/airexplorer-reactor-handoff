#!/usr/bin/env python3
# rk27c.py — 修正版：pt_dword(LE) = ct_dword(LE) ^ state。全窗口+byte[32]枚举双扫。
import numpy as np, struct, sys, os

M32 = np.uint32(0xFFFFFFFF); U64 = np.uint64(0xFFFFFFFFFFFFFFFF)
K1 = np.uint32(506503628); K2 = np.uint32(1959015338); K3 = np.uint32(854276594); K4 = np.uint32(41684485)
K1B = np.uint32((1610158714 + 1328951073 - 1267867220) & 0xFFFFFFFF)
ROTK2 = np.uint32(0xD53A6219); ROTK4 = np.uint32(0xF0381409)
K3K3 = np.uint64((854276594 * 854276594) & 0xFFFFFFFF)

def v41_batch(s):
    s = s.astype(np.uint32)
    v43 = (K1 * s).astype(np.uint32); v43u = v43.astype(np.uint64); v43u[v43 == 0] = U64
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

def decrypt_dwords(cand, ct_le, n=16):
    N = cand.shape[0]
    state = np.zeros(N, dtype=np.uint32)
    out = np.zeros((N, n), dtype=np.uint32)
    for i in range(n):
        state = (state + cand[:, i % 8]).astype(np.uint32)
        state = (state + v41_batch(state)).astype(np.uint32)
        out[:, i] = ct_le[i] ^ state
    return out

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
f = open(W + r'\airexplorer-reactor-handoff\exes\AirExplorer_baseline_verified.exe', 'rb').read()

def ct_le_dwords(off, n=16):
    return np.array(struct.unpack('<%dI' % n, f[off:off + n * 4]), dtype=np.uint32)

# 真值校验：Viewer key 解 Viewer ct == dec_Viewer.bin[:64]
KV = bytes.fromhex('f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943')
cand1 = np.array([struct.unpack('<8I', KV)], dtype=np.uint32)
pt = decrypt_dwords(cand1, ct_le_dwords(0x6213c4))
mine = b''.join(struct.pack('<I', int(d)) for d in pt[0])
truth = open(W + r'\work_a1\dec_Viewer.bin', 'rb').read()[:64]
print('VALIDATE vectorized vs dec_Viewer.bin[:64]:', mine == truth)
assert mine == truth, 'still broken'

PROC_LE = ct_le_dwords(0x6784b4)
EMIT_LE = ct_le_dwords(0x6783b0)

fn = sys.argv[1] if len(sys.argv) > 1 else W + r'\work_a1\rk27\out\region_27e80000000.bin'
data = open(fn, 'rb').read()
print('scan', os.path.basename(fn), len(data), 'B')

KNOWN = {bytes.fromhex('f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943'): 'Viewer',
         bytes.fromhex('cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481'): 'mainlib',
         bytes.fromhex('37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a'): 'Factory'}

# A) byte[32] 托管数组枚举（去重）
MT = bytes.fromhex('48589e7cfc7f0000')
seen = {}
i = data.find(MT)
while i != -1:
    cnt = struct.unpack_from('<I', data, i + 8)[0]
    if cnt == 32:
        pay = data[i + 16:i + 48]
        seen.setdefault(pay, []).append(i)
    i = data.find(MT, i + 8)
print('unique byte[32] payloads:', len(seen), '(known among them:', set(KNOWN.get(p) for p in seen if p in KNOWN), ')')

# B) 全窗口滑动（4B 对齐）
arr = np.frombuffer(data, dtype=np.uint8)
N = (len(data) - 32) // 4
b = arr[:N * 4].reshape(N, 4).copy()
b4 = b[:, 0].astype(np.uint32) | (b[:, 1].astype(np.uint32) << np.uint32(8)) | (b[:, 2].astype(np.uint32) << np.uint32(16)) | (b[:, 3].astype(np.uint32) << np.uint32(24))
cand = np.lib.stride_tricks.as_strided(b4, shape=(N - 7, 8), strides=(4, 4)).copy()
print('window candidates:', cand.shape[0])

for tgt_name, ct in (('Proc', PROC_LE), ('Emitter', EMIT_LE)):
    out = decrypt_dwords(cand, ct)
    small = (out < np.uint32(0x930000)).sum(axis=1)
    tags = ((out == 0) | (out == 1) | (out == 2) | (out == 3)).sum(axis=1)
    score = small.astype(np.int32) * 2 + tags.astype(np.int32)
    order = np.argsort(score)[-15:][::-1]
    print('== %s top windows ==' % tgt_name)
    shown = 0
    for idx in order:
        if score[idx] < 18:
            break
        off = int(idx) * 4
        pay = data[off:off + 32]
        tag = KNOWN.get(pay, '?')
        ptb = b''.join(struct.pack('<I', int(d)) for d in out[idx])
        print('  off=0x%-8x score=%2d small=%2d tags=%2d %s pt[:24]=%s' % (off, score[idx], small[idx], tags[idx], tag, ptb[:24].hex()))
        shown += 1
        if shown >= 10:
            break
    if shown == 0:
        print('  (nothing scored >=18)')
