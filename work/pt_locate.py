#!/usr/bin/env python3
# 用 v4b P1 已知明文 (off, dword) 在 6 个资源密文里定位 ct，推导加密结构
import re, struct, os, sys

LOG = "/tmp/art4/cdb.log"
RESDIR = "/workspace/airexplorer-reactor-handoff/work"

# 从 TARGETS 拿 tok->rva
TARGETS = {
    "0600212A": 0x00195D18, "06003909": 0x00334EB0, "06002BD1": 0x0024EA40,
    "06004282": 0x00407F38, "0600418B": 0x003FAA64, "06004196": 0x003FDA7C,
    "060042B0": 0x0040EE88, "060042B1": 0x0040F2A4,
}
BASE = 0x1a691100000  # v4b run 的模块基址（cdb.log 第 52 行）

# rbx 已知：方法密文在负载内偏移
RBX = {"06003909": 0x3E698, "060042B1": 0x5358C}

evs = {}  # tok -> list of (off, bytes4)
for line in open(LOG, encoding="utf-8", errors="replace"):
    m = re.match(r"\[V4\] EVT (\w+) i=\d+ addr=0x([0-9a-f]+) size=4 val=([0-9a-f]+) ", line)
    if not m:
        continue
    tok, addr, val = m.group(1), int(m.group(2), 16), int(m.group(3), 16)
    off = addr - BASE - TARGETS[tok]
    data = struct.pack("<I", val)
    evs.setdefault(tok, []).append((off, data))

for tok in evs:
    evs[tok].sort()
    print(f"== {tok} events={len(evs[tok])} offs={[hex(o) for o,_ in evs[tok]]}")

# 资源列表
res_files = sorted(f for f in os.listdir(RESDIR) if f.startswith("res_") and f.endswith(".bin"))
resources = {f: open(os.path.join(RESDIR, f), "rb").read() for f in res_files}
print("resources:", {f: hex(len(b)) for f, b in resources.items()})

def find_all(hay, needle):
    out, i = [], hay.find(needle)
    while i != -1:
        out.append(i)
        i = hay.find(needle, i + 1)
    return out

print("\n--- 4-byte plaintext search in resources ---")
for tok, plist in evs.items():
    for off, pt in plist:
        for fname, blob in resources.items():
            hits = find_all(blob, pt)
            if hits:
                print(f"{tok} off={off:#x} pt={pt.hex()} -> {fname} hits={[hex(h) for h in hits[:8]]}")

print("\n--- rbx offset neighborhood check (FactoryValidator @ 0x3e698, Viewer @?) ---")
# 06003909 密文据信在负载 off 0x3e698；看各资源该偏移附近字节
for fname, blob in resources.items():
    if len(blob) > 0x3E6A8:
        print(f"{fname} @0x3e698: {blob[0x3E698:0x3E6B8].hex()}")
pt0909 = b"".join(d for _, d in evs["06003909"])
print(f"06003909 plaintext(16B) = {pt0909.hex()}")
ptb0 = bytes(dict(evs['060042B0']).get(o, b'\0'*4) for o in (0, 4, 8, 0xC, 0x10))
print(f"060042B0 pt@0..13f? = {ptb0.hex()}")

# 若 ct 位置 == rbx 偏移（同偏移存储），直接 XOR 得 keystream 片段并检验 prng 链
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decrypt_prng import prng_round

def check_chain(ks_words):
    """ks_words: list of uint32 keystream words; check prng_round chain relation"""
    for i in range(len(ks_words) - 1):
        if prng_round(ks_words[i]) != ks_words[i + 1]:
            return False
    return True

print("\n--- XOR@same-offset keystream hypothesis ---")
for tok, rbxoff in RBX.items():
    # 尝试每个资源
    for fname, blob in resources.items():
        if len(blob) <= rbxoff + 64:
            continue
        ct = blob[rbxoff:rbxoff + 64]
        # 明文序列（该 tok 的事件按 off 拼，允许空洞）
        evmap = dict(evs[tok])
        offs = sorted(evmap)
        base_off = offs[0]
        pt = b""
        for o in offs:
            if o == base_off + len(pt):
                pt += evmap[o]
            else:
                break
        n = len(pt)
        if n < 8:
            continue
        ksb = bytes(a ^ b for a, b in zip(ct[:n], pt))
        # 检查按 dword 对齐的 prng 链
        words = list(struct.unpack(f"<{n//4}I", ksb[:n//4*4]))
        chain = check_chain(words)
        print(f"{tok} rbx={rbxoff:#x} {fname}: pt={n}B ks={ksb[:16].hex()} prng_chain={chain}")

print("\n--- XOR@rbx for all toks with rbx (need pt contiguous from off0) ---")
# 0600212A 无 rbx，但试资源里直接找 1e027b3d0c00042a 已失败；
# 改成: 对每个 tok 的每段连续明文，在所有资源做"全字节窗 XOR 键一致"测试：
# 即假设 ct = pt ^ KS where KS 同一资源偏移处取（同偏移异或），扫所有资源所有偏移,
# 要求 XOR 结果（跨多个 dword）成 prng_round 链 —— 太重，改为:
# 简化: 060042B0 三段连续明文（0..0x10, 0x41c..0x430, 0x5c8..0x5dc）
# 在每个资源的每个 0x100 对齐偏移处取 ct，算 ks，测 prng 链
for tok in ("060042B0", "060042B1"):
    evmap = dict(evs[tok])
    offs = sorted(evmap)
    segs = []
    cur = [offs[0]]
    for o in offs[1:]:
        if o == cur[-1] + 4:
            cur.append(o)
        else:
            segs.append(cur)
            cur = [o]
    segs.append(cur)
    for si, seg in enumerate(segs):
        pt = b"".join(evmap[o] for o in seg)
        words_pt = list(struct.unpack(f"<{len(pt)//4}I", pt))
        # 资源全扫（任意偏移）: 找 ks[0] = ct^pt[0] 后续成链
        pt0 = struct.unpack("<I", pt[:4])[0]
        for fname, blob in resources.items():
            bl = len(blob)
            for i in range(0, bl - 64):
                ct0 = struct.unpack_from("<I", blob, i)[0]
                k0 = ct0 ^ pt0
                k1 = prng_round(k0)
                if i + 8 <= bl:
                    ct1 = struct.unpack_from("<I", blob, i + 4)[0]
                    if ct1 ^ struct.unpack("<I", pt[4:8])[0] != k1:
                        continue
                    print(f"HIT chain {tok} seg{si} {fname} off={i:#x} k0={k0:#x}")
        print(f"{tok} seg{si} offs={[hex(o) for o in seg]} pt={pt.hex()} scanned")

