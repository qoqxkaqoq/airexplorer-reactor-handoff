#!/usr/bin/env python3
# Scan the raw main-library resource for a valid raw-deflate start offset.
import sys, zlib

SRC = '/workspace/airexplorer-reactor-handoff/work/res_ValidatorGenerator.DefinitionError.bin'
data = open(SRC, 'rb').read()
print('total', len(data), 'head64', data[:64].hex())

hit = None
for off in range(0, 4096):
    try:
        d = zlib.decompressobj(-15)
        out = d.decompress(data[off:off + 65536], 1 << 22)
        if d.eof or len(out) > 256:
            print(f'*** deflate starts at offset {off}: out={len(out)} eof={d.eof} unused={len(d.unused_data)}')
            print('    head:', out[:64].hex())
            hit = off
            break
    except Exception:
        pass
if hit is None:
    print('no deflate start found in 0..4095; trying XOR const layer...')
    for x in range(1, 256):
        dec = bytes(b ^ x for b in data[:65536])
        try:
            d = zlib.decompressobj(-15)
            out = d.decompress(dec, 1 << 20)
            if len(out) > 256:
                print(f'*** XOR 0x{x:02X}: out={len(out)} head={out[:32].hex()}')
                break
        except Exception:
            pass
    else:
        print('XOR const layer: no hit')
