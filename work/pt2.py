#!/usr/bin/env python3
# pt2.py — 已知明文定位负载流 v2
# 假设 H1: 负载流 = 某资源文件, 方法密文在 rbx 偏移, pt = ct ^ KS, KS 成 prng_round 链
# 快速版: (a) 固定 rbx 偏移 XOR 链检测  (b) numpy 全字节偏移扫 (两段联合验证)
import struct, sys, os
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decrypt_prng import prng_round

RESDIR = "/workspace/airexplorer-reactor-handoff/work"
LOG = "/tmp/art4/cdb.log"
import re
TARGETS = {"06003909": 0x00334EB0, "060042B0": 0x0040EE88, "060042B1": 0x0040F2A4}
BASE = 0x1a691100000
RBX = {"06003909": 0x3E698, "060042B1": 0x5358C}

evs = {}
for line in open(LOG, encoding="utf-8", errors="replace"):
    m = re.match(r"\[V4\] EVT (\w+) i=\d+ addr=0x([0-9a-f]+) size=4 val=([0-9a-f]+) ", line)
    if m and m.group(1) in TARGETS:
        tok = m.group(1)
        off = int(m.group(2), 16) - BASE - TARGETS[tok]
        evs.setdefault(tok, {})[off] = struct.pack("<I", int(m.group(3), 16))

def segs_of(tok):
    offs = sorted(evs[tok])
    out, cur = [], [offs[0]]
    for o in offs[1:]:
        if o == cur[-1] + 4: cur.append(o)
        else: out.append(cur); cur = [o]
    out.append(cur)
    return [(c[0], b"".join(evs[tok][o] for o in c)) for c in out]

resources = {}
for f in sorted(os.listdir(RESDIR)):
    if f.startswith("res_") and f.endswith(".bin"):
        resources[f] = open(os.path.join(RESDIR, f), "rb").read()

print("=== (a) fixed rbx offset XOR chain check ===")
for tok, rbxoff in RBX.items():
    for off0, pt in segs_of(tok):
        if off0 != 0: continue
        for fname, blob in resources.items():
            if len(blob) < rbxoff + len(pt): continue
            ct = blob[rbxoff:rbxoff + len(pt)]
            ksb = bytes(a ^ b for a, b in zip(ct, pt))
            words = list(struct.unpack(f"<{len(pt)//4}I", ksb[:len(pt)//4*4]))
            chain = all(prng_round(words[i]) == words[i+1] for i in range(len(words)-1))
            print(f"{tok} @rbx={rbxoff:#x} {fname}: ks={ksb.hex()} chain={chain}")

print("\n=== (b) numpy full-offset scan, two-segment joint verification ===")
# H1: 资源在偏移 X 处含方法密文, 同偏移 XOR 成链。
# seg A: 06003909 @0 (16B); 验证 seg B: 06003909 只有 16B → 用 060042B1 seg0(20B)+seg1(20B@0x1ac)
# 若负载流整体一条链(方法连续存放), 060042B1 seg1 应在 seg0 偏移+0x1ac 处。
# 先做单段扫描: 每个 byte offset, ks0=ct[o]^pt0, ks1=ct[o+4]^pt1, prng_vec 检测
M = np.uint64(0xFFFFFFFF); U64 = np.uint64((1 << 64) - 1)
K1 = 506503628
K1B = (1610158714 + 1328951073 - 1267867220) & 0xFFFFFFFF
K2 = 1959015338; K3 = 854276594; K4 = 41684485
K3K3 = (K3 * K3) & 0xFFFFFFFF
def prng_vec(v9):
    v9 = v9 & M
    v43 = ((np.uint64(K1) * v9) & M); v43 = np.where(v43 == 0, U64, v43)
    v40 = ((np.uint64(K3K3) % v43) & M)
    rot = (np.uint64(K2) >> np.uint64(9)) | ((np.uint64(K2) << np.uint64(23)) & M)
    v45 = (rot + v9) & M
    v39 = (((v45 & np.uint64(0xAAAAAAAA)) >> np.uint64(1)) | ((v45 & np.uint64(0x55555555)) << np.uint64(1)))
    v38 = np.uint64(K1B)
    v41x = np.where(v9 == 0, np.uint64(0xFFFFFFFF), v9)
    v44 = ((v40 // v41x) + v41x) & M
    v41 = (((v40 + v40) - v44) + v40) & M
    rot4 = ((np.uint64(K4) << np.uint64(10)) & M) | (np.uint64(K4) >> np.uint64(22))
    v45b = (rot4 + v40) & M
    v42 = (((v45b >> np.uint64(8)) & np.uint64(0x00FF00FF)) | ((v45b << np.uint64(8)) & np.uint64(0xFF00FF00)))
    v41 = v41 ^ (v41 >> np.uint64(3)); v41 = (v41 + v38) & M
    v41 = v41 ^ ((v41 << np.uint64(7)) & M); v41 = (v41 + v41) & M
    v41 = v41 ^ (v41 >> np.uint64(29)); v41 = (v41 + v42) & M
    v41 = (v41 + ((((v39 << np.uint64(4)) & M) - v40) ^ v38)) & M
    return (v9 + v41) & M

def scan(fname, pt, label):
    blob = resources[fname]
    bl = len(blob)
    if bl < len(pt) + 8: return
    n = bl - 8
    u32at = np.frombuffer(blob[:len(blob) // 4 * 4], dtype="<u4")
    # 字节偏移扫描: 用 4 个相位 (byte-align) 分开做
    hits = []
    for ph in range(4):
        idx = np.arange(ph, n, 4)
        if len(idx) < 2: continue
        ct0 = u32at[idx // 4]
        ct1 = u32at[idx // 4 + 1]
        pt0 = struct.unpack("<I", pt[0:4])[0]
        pt1 = struct.unpack("<I", pt[4:8])[0]
        ks0 = (ct0.astype(np.uint64) ^ np.uint64(pt0))
        ks1 = (ct1.astype(np.uint64) ^ np.uint64(pt1))
        pred = prng_vec(ks0)
        m = pred == ks1
        for i in idx[m]:
            hits.append(int(i))
    if hits:
        print(f"HIT {label} {fname}: {len(hits)} hits -> {[hex(h) for h in hits[:10]]}")
        # 全 32B 验证
        for h in hits:
            ct = blob[h:h + len(pt)]
            ks = bytes(a ^ b for a, b in zip(ct, pt))
            w = list(struct.unpack(f"<{len(pt)//4}I", ks[:len(pt)//4*4]))
            ok = all(prng_round(w[i]) == w[i+1] for i in range(len(w)-1))
            print(f"   verify@{h:#x}: full32B chain={ok} ks={ks.hex()}")

PT0909 = b"".join(evs["06003909"][o] for o in (0, 4, 8, 0xC))
print("06003909 pt(16B) =", PT0909.hex())
for fname in resources:
    scan(fname, PT0909, "06003909")
b1 = segs_of("060042B1")
print("060042B1 segs:", [(hex(a), p.hex()) for a, p in b1])
if len(b1) >= 2:
    offB, ptB = b1[1]
    for fname in resources:
        scan(fname, ptB, f"060042B1seg1@{offB:#x}")
