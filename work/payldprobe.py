#!/usr/bin/env python3
# payldprobe.py — locate method bodies inside the 3.2MB Reactor payload.
# Probe A: plaintext token headers (tok, ilSize, maxStack, ehCount, ...) in the clear.
# Probe B: known-plaintext drag + ARX chain test (ks[i+1] == round(ks[i]), seed-free).
import struct, sys

EXE = '/workspace/airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe'

def payload_range():
    d = open(EXE, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    for i in range(nsec):
        o = pe + 24 + optsz + 40 * i
        name = d[o:o+8].rstrip(b'\0').decode()
        vsz, va, rsz, ro = struct.unpack_from('<IIII', d, o + 8)
        if name == '.text':
            return d, ro, va, rsz
    raise SystemExit('.text not found')

d, ro, va, rsz = payload_range()
# payload va 0x620000..0x920000 -> file offsets
p_lo = ro + (0x620000 - va)
p_hi = ro + (0x920000 - va)
print(f'.text raw=0x{ro:X} va=0x{va:X} size=0x{rsz:X}; payload file 0x{p_lo:X}..0x{p_hi:X} ({p_hi-p_lo} bytes)')
pay = d[p_lo:p_hi]

# ---- Probe A: token headers in the clear
hits = 0
for tok in (0x0600212A, 0x06002133, 0x06002145, 0x06002157, 0x06002127, 0x0600428A):
    pat = struct.pack('<I', tok)
    idx = []
    i = pay.find(pat)
    while i >= 0 and len(idx) < 5:
        idx.append(i); i = pay.find(pat, i + 1)
    if idx:
        hits += 1
        print(f'ProbeA tok {tok:08X}: file-offs {[hex(p_lo + x) for x in idx]} ctx {pay[idx[0]:idx[0]+24].hex()}')
print(f'ProbeA: {hits}/6 tokens found plaintext')

# ---- Probe B: known-plaintext ARX chain drag
sys.path.insert(0, '/workspace/airexplorer-reactor-handoff/work')
from decrypt_prng import prng_round

import os
dumpdir = '/tmp/dumps'
probes = ['m_0600428A.bin', 'm_0600212A.bin', 'm_06002133.bin', 'm_06004192.bin',
          'm_0600419C.bin', 'm_06004193.bin']
# pick a few mid-size bodies too
try:
    allb = sorted(os.listdir(dumpdir))
    import random
    random.seed(7)
    cands = [x for x in allb if x.endswith('.bin') and 120 <= os.path.getsize(os.path.join(dumpdir, x)) - 24 <= 400]
    for x in random.sample(cands, 4):
        probes.append(x)
except FileNotFoundError:
    print('NO DUMPDIR — Probe B skipped'); sys.exit(0)

NW = 8  # words to verify (32 bytes)
for name in probes:
    p = os.path.join(dumpdir, name)
    dmp = open(p, 'rb').read()
    ilSize = struct.unpack_from('<i', dmp, 4)[0]
    body = dmp[24:24 + ilSize]
    nw = min(NW, ilSize // 4)
    if nw < 4:
        continue
    P = body[:nw * 4]
    found = []
    # scan word-aligned offsets
    for o in range(0, len(pay) - nw * 4, 4):
        C = pay[o:o + nw * 4]
        ks = struct.unpack('<%dI' % nw, bytes(a ^ b for a, b in zip(C, P)))
        # chain test
        ok = True
        w = ks[0]
        for i in range(1, nw):
            w = prng_round(w)
            if w != ks[i]:
                ok = False; break
        if ok:
            found.append(o)
            if len(found) >= 3: break
    tag = f'{name} tok={struct.unpack_from("<I", dmp, 0)[0]:08X} il={ilSize}'
    if found:
        print(f'ProbeB HIT {tag}: payload-offs {[hex(p_lo + f) for f in found]}')
    else:
        print(f'ProbeB miss {tag}')
