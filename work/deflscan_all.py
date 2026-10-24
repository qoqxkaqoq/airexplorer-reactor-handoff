#!/usr/bin/env python3
# Scan ALL 6 CLR resources for a valid raw-deflate start.
import sys, zlib, glob

for src in sorted(glob.glob('/workspace/airexplorer-reactor-handoff/work/res_*.bin')):
    data = open(src, 'rb').read()
    name = src.split('res_')[1]
    hit = None
    for off in range(0, 512):
        try:
            d = zlib.decompressobj(-15)
            out = d.decompress(data[off:off + 262144], 1 << 24)
            if d.eof or len(out) > 4096:
                print(f'{name} len={len(data)}: deflate@{off} out={len(out)} eof={d.eof} unused={len(d.unused_data)}')
                print('   head:', out[:64].hex())
                hit = off
                break
        except Exception:
            pass
    if hit is None:
        print(f'{name} len={len(data)}: no deflate in 0..511')
