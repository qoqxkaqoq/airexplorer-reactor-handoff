#!/usr/bin/env python3
# pt3.py — 资源 -> seed0 prng XOR -> Deflate -> 负载流? (复刻 interp.py 主库流程到其余 5 资源)
import struct, sys, os, zlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decrypt_prng import decrypt

RESDIR = "/workspace/airexplorer-reactor-handoff/work"
files = sorted(f for f in os.listdir(RESDIR) if f.startswith("res_") and f.endswith(".bin"))
for f in files:
    data = open(os.path.join(RESDIR, f), "rb").read()
    print(f"== {f} len={len(data):#x} head={data[:16].hex()} tail={data[-8:].hex()}")
    dec = decrypt(data)
    print(f"   seed0-dec head={dec[:16].hex()}")
    # 尝试 raw deflate 从多个起点解
    ok = False
    for start in (0, 2, 4, 8, 12, 16):
        try:
            d = zlib.decompressobj(-15)
            out = d.decompress(dec[start:])
            print(f"   RAW-DEFLATE@{start}: {len(out):#x} bytes, head={out[:16].hex()}")
            open(f"/tmp/pl_{f}", "wb").write(out)
            ok = True
            break
        except Exception as e:
            pass
    # 也许原始资源就是 deflate（没 XOR 层）
    for start in (0, 2, 4):
        try:
            d = zlib.decompressobj(-15)
            out = d.decompress(data[start:])
            print(f"   RAWDEF-ORIG@{start}: {len(out):#x} bytes, head={out[:16].hex()}")
            open(f"/tmp/plr_{f}", "wb").write(out)
            ok = True
            break
        except Exception:
            pass
    if not ok:
        print("   no deflate found (xor/raw)")
