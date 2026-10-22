#!/usr/bin/env python3
# extract_res.py — 从全内存 MiniDump 中扫描 .resources 明文 (BEEFCACE 魔数) 并提取候选
# 用法: python extract_res.py <dump文件> <输出目录> [最大候选间隔MB]
import re
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import os

def main():
    if len(sys.argv) < 3:
        print("usage: extract_res.py <dump> <outdir> [maxGapMB]")
        return 1
    dump, outdir = sys.argv[1], sys.argv[2]
    max_gap = int(sys.argv[3]) * 1024 * 1024 if len(sys.argv) > 3 else 6 * 1024 * 1024
    os.makedirs(outdir, exist_ok=True)
    data = open(dump, 'rb').read()
    print("dump 大小:", len(data))
    magic = b'\xCE\xCA\xEF\xBE'  # 0xBEEFCACE 小端
    poss = [m.start() for m in re.finditer(re.escape(magic), data)]
    print("BEEFCACE 命中:", len(poss))
    # 过滤: 相邻命中间隔 <4KB 视为同源噪声; 每个候选 = [p, min(next, p+max_gap))
    cand = []
    filtered = []
    i = 0
    while i < len(poss):
        p = poss[i]
        if filtered and p - filtered[-1] < 4096:
            i += 1
            continue
        filtered.append(p)
        i += 1
    print("过滤后候选起点:", len(filtered))
    for i, p in enumerate(filtered):
        nxt = filtered[i + 1] if i + 1 < len(filtered) else p + max_gap
        end = min(nxt, p + max_gap)
        blob = data[p:end]
        if len(blob) >= 4096:
            out = os.path.join(outdir, "cand_%02d.resources" % i)
            open(out, "wb").write(blob)
            cand.append(out)
    print("候选(>=4KB):", len(cand))
    for c in cand:
        print("  ", c, os.path.getsize(c), "B")
    return 0

if __name__ == "__main__":
    sys.exit(main())
