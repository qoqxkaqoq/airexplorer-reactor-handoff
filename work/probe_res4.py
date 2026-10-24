#!/usr/bin/env python3
# probe_res4.py — try seed-0 PRNG keystream decrypt on the 4 unexplored resources;
# then test whether the XOR output is a deflate/zlib stream (2-layer model like mainlib).
import sys, zlib, struct
sys.path.insert(0, '/workspace/airexplorer-reactor-handoff/work')
from decrypt_prng import decrypt, keystream

RES = [
    'res_GlobalValidator.FactoryValidator.bin',
    'res_ErrorReceiver.ValidatorViewer.bin',
    'res_ValidatorAllocator.ValidatorProc.bin',
    'res_ValidatorArgument.EmitterReporter.bin',
]

for name in RES:
    data = open(name, 'rb').read()
    out = decrypt(data)   # seed-0 keystream XOR
    h = out[:16].hex()
    tag = []
    if out[:1] == b'\x78':
        tag.append('zlib-head')
    try:
        dec = zlib.decompressobj(-15).decompress(out)
        tag.append(f'RAW-DEFLATE OK -> {len(dec)} bytes head={dec[:16].hex()}')
    except Exception as e:
        dec = None
    try:
        dec2 = zlib.decompress(out)
        tag.append(f'ZLIB OK -> {len(dec2)} bytes head={dec2[:16].hex()}')
        dec = dec2
    except Exception:
        pass
    print(f'{name}: size={len(data)} xorhead={h} {" ".join(tag) if tag else "not deflate"}')
    if dec and dec[:2] == b'MZ':
        open(name.replace('.bin', '_plain.bin'), 'wb').write(dec)
        print(f'  *** PE assembly written: {name.replace(".bin", "_plain.bin")}')
