#!/usr/bin/env python3
# Probe: which resource pair feeds 0600418B GenerateAlphabeticVerifier(key, ?, ct)?
# Formula derived from the IL: s_i = v4 + keyWord[i%kw]; out = prng_round(s); v4 = s + out; plain = ct ^ out
import struct, sys, itertools
sys.path.insert(0, '/workspace/airexplorer-reactor-handoff/work')
from decrypt_prng import prng_round, u32

M32 = 0xFFFFFFFF

def decrypt_pool(key: bytes, ct: bytes):
    kw = len(key) // 4
    if kw == 0: return None
    n = len(ct) // 4 + (1 if len(ct) % 4 else 0)
    out = bytearray()
    v4 = 0
    for i in range(n):
        v5 = u32(key[(i % kw) * 4] | (key[(i % kw) * 4 + 1] << 8) | (key[(i % kw) * 4 + 2] << 16) | (key[(i % kw) * 4 + 3] << 24))
        off = i * 4
        if i == n - 1 and len(ct) % 4:
            rem = len(ct) - off
            word = 0
            for j in range(rem):
                if j > 0: word = (word << 8) & M32
                word |= ct[len(ct) - 1 - j]
        else:
            word = u32(ct[off] | (ct[off+1] << 8) | (ct[off+2] << 16) | (ct[off+3] << 24))
        s = u32(v4 + v5)
        o = prng_round(s)
        v4 = u32(s + o)
        out += struct.pack('<I', u32(o ^ word))
    return bytes(out[:len(ct)])

def pool_score(b):
    """pool format: [int32 len][UTF-16LE str]... — score = plausible-length + utf16-ascii runs"""
    if len(b) < 16: return 0
    # first entry: len = LE32 at 0, then UTF-16LE bytes
    try:
        l0 = struct.unpack_from('<i', b, 0)[0]
    except Exception:
        return 0
    s = 0
    if 0 < l0 <= 1024 and 4 + l0 <= len(b):
        s += 10
        # utf16 ascii check on first string
        chunk = b[4:4 + l0]
        hi = sum(1 for x in chunk[1::2] if x == 0)
        s += 10 * (hi / max(1, len(chunk) // 2))
    return s

RES = {
    'DefinitionError': 'res_ValidatorGenerator.DefinitionError.bin',   # 2337031 main lib
    'FactoryValidator': 'res_GlobalValidator.FactoryValidator.bin',    # 398794 string pool
    'ValidatorViewer': 'res_ErrorReceiver.ValidatorViewer.bin',        # 356328 method bodies?
    'ValidatorProc': 'res_ValidatorAllocator.ValidatorProc.bin',       # 47915
    'ValidatorProject': 'res_CollectorTransaction.ValidatorProject.bin', # 26128 delegate table
    'EmitterReporter': 'res_ValidatorArgument.EmitterReporter.bin',    # 256
}
import os
base = '/workspace/airexplorer-reactor-handoff/work'
D = {}
for k, f in RES.items():
    p = os.path.join(base, f)
    if os.path.exists(p): D[k] = open(p, 'rb').read()

results = []
for kn, key in D.items():
    for cn, ct in D.items():
        if kn == cn: continue
        # cap ct to 64KB for speed on big resources
        sample = ct[:65536] if len(ct) > 65536 else ct
        try:
            dec = decrypt_pool(key, sample)
        except Exception as e:
            continue
        sc = pool_score(dec)
        if sc > 5:
            results.append((sc, kn, cn))
            print(f'HIT score={sc:.1f} key={kn} ct={cn} head={dec[:48].hex()}')

# also: key = prefixes of each resource
print('--- prefix keys ---')
for cn, ct in D.items():
    sample = ct[:65536] if len(ct) > 65536 else ct
    for kn, key in D.items():
        for plen in (16, 32, 64, 128, 256):
            if len(key) < plen: continue
            dec = decrypt_pool(key[:plen], sample)
            sc = pool_score(dec)
            if sc > 5:
                print(f'HIT score={sc:.1f} key={kn}[:{plen}] ct={cn} head={dec[:48].hex()}')
print('done')
