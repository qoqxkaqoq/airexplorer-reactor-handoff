#!/usr/bin/env python3
# Probe: does the 2.33MB main library (res_ValidatorGenerator.DefinitionError.bin)
# use the SAME verified PRNG keystream (seed 0, wordwise LE)?
# Reader 0600428A: bytes -> RandomDecryptor -> DeflateStream decompress.
import sys, zlib, struct
sys.path.insert(0, '/workspace/airexplorer-reactor-handoff/work')
from decrypt_prng import keystream, u32

SRC = '/workspace/airexplorer-reactor-handoff/work/res_ValidatorGenerator.DefinitionError.bin'
PREFIX = 65536

data = open(SRC, 'rb').read()
print('total', len(data), 'head', data[:16].hex())

def decrypt_words(buf, seed=0, endian='<'):
    n = len(buf) // 4
    ks = keystream(n) if seed == 0 else keystream_seed(n, seed)
    out = bytearray()
    for w in range(n):
        off = w * 4
        word = struct.unpack(endian + 'I', buf[off:off+4])[0]
        out += struct.pack('<I', u32(ks[w] ^ word))
    return bytes(out)

def keystream_seed(nwords, seed):
    from decrypt_prng import prng_round
    ks = []
    v9 = u32(seed)
    for _ in range(nwords):
        v9 = prng_round(v9)
        ks.append(v9)
    return ks

def decrypt_bytes(buf, seed=0):
    ks = keystream_seed((len(buf) + 3) // 4, seed)
    return bytes(b ^ (ks[i // 4] >> ((i % 4) * 8) & 0xFF) for i, b in enumerate(buf))

def try_deflate(buf, tag):
    for wbits, label in [(-15, 'raw'), (15, 'zlib'), (31, 'gzip')]:
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(buf, 1 << 22)
            print(f'  [{tag}] {label}: OK out={len(out)} unused={len(d.unused_data)} eof={d.eof}')
            print(f'  [{tag}] out head: {out[:48].hex()}')
            try:
                print(f'  [{tag}] out ascii head: {out[:64]!r}')
            except Exception:
                pass
            return (wbits, out)
        except Exception as e:
            print(f'  [{tag}] {label}: FAIL {type(e).__name__}: {e}')
    return None

print('--- 0. raw resource, no decrypt (sanity) ---')
try_deflate(data[:PREFIX], 'raw')

print('--- 1. wordwise-LE decrypt (verified PRNG, seed 0) ---')
dec = decrypt_words(data[:PREFIX])
print('  dec head:', dec[:32].hex())
hit = try_deflate(dec, 'ww-LE')

if not hit:
    print('--- 2. wordwise-BE ---')
    dec = decrypt_words(data[:PREFIX], endian='>')
    try_deflate(dec, 'ww-BE')

if not hit:
    print('--- 3. bytewise keystream ---')
    dec = decrypt_bytes(data[:PREFIX])
    try_deflate(dec, 'bw')

if not hit:
    print('--- 4. seed sweep 1..4095, wordwise-LE, check deflate-start validity ---')
    import decrypt_prng as dp
    for seed in range(1, 4096):
        dec = decrypt_words(data[:4096], seed=seed)
        try:
            d = zlib.decompressobj(-15)
            out = d.decompress(dec, 4096)
            if len(out) > 32:
                print(f'  seed={seed} HIT out={len(out)} head={out[:32].hex()}')
                hit = seed
                break
        except Exception:
            pass
    else:
        print('  no seed hit in 1..4095')
