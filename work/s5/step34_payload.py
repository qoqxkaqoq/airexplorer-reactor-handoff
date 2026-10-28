# -*- coding: utf-8 -*-
"""step34: payload region structure analysis (.text 0x620000-0x920000).
Hypotheses for method-body encoding in payload:
  H1 raw deflate per entry -> compress known bodies, search
  H2 fixed-phase PRNG keystream XOR (decrypt_prng.py schedule) -> XOR region, search
  H3 plain (ruled out by step32) / other
"""
import struct, zipfile, zlib, sys
sys.path.insert(0, '/workspace/repo_git/work')
import decrypt_prng

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
data = open(BASE, 'rb').read()

R_START, R_END = 0x620200, 0x920200   # rva 0x620000..0x920000 file offsets
region = data[R_START:R_END]
print('region size: %d (0x%X)' % (len(region), len(region)))

# stats
import collections
cnt = collections.Counter(region)
zeros = cnt[0]
print('zero byte ratio: %.3f' % (zeros / len(region)))
# zero-run length distribution (top)
runs = []
i = 0
while i < len(region):
    if region[i] == 0:
        j = i
        while j < len(region) and region[j] == 0:
            j += 1
        runs.append(j - i)
        i = j
    else:
        i += 1
runs.sort(reverse=True)
print('zero runs: %d, top10 lens: %s' % (len(runs), runs[:10]))
print('first 64B: %s' % region[:64].hex())
print('hexdump head 256B:')
for o in range(0, 256, 32):
    print('  %06X: %s' % (o, region[o:o+32].hex()))

# known bodies
z = zipfile.ZipFile(DUMP)
bodies = {}
for tok in (0x06002127, 0x0600212A, 0x06002133, 0x06002145, 0x06002157, 0x06000CEE, 0x0600217A):
    d = z.read('m_%08X.bin' % tok)
    ilsz = struct.unpack('<I', d[4:8])[0]
    bodies[tok] = d[24:24 + ilsz]

# H1: deflate search
print('== H1 deflate search (levels 1,6,9, raw wbits):')
for tok, il in bodies.items():
    hit = None
    for lvl in (1, 6, 9):
        for strat in (zlib.Z_DEFAULT_STRATEGY, zlib.Z_FILTERED, zlib.Z_HUFFMAN_ONLY, zlib.Z_RLE):
            try:
                c = zlib.compressobj(lvl, zlib.DEFLATED, -15, 9, strat)
                co = c.compress(il) + c.flush()
            except Exception:
                continue
            j = region.find(co)
            if j >= 0:
                hit = (lvl, strat, j)
                break
        if hit: break
    print('   %08X il=%d -> %s' % (tok, len(il), ('HIT lvl=%d strat=%d off=0x%X' % hit) if hit else 'none'))

# H2: fixed-phase keystream XOR
print('== H2 keystream XOR (schedule v9=0 from region start, word-aligned):')
ks = decrypt_prng.keystream(len(region) // 4 + 1)
ksb = b''.join(struct.pack('<I', w) for w in ks)
xr = bytes(a ^ b for a, b in zip(region, ksb[:len(region)]))
for tok, il in bodies.items():
    probe = il[:16]
    j = xr.find(probe)
    print('   %08X -> %s' % (tok, 'HIT @region+0x%X (file 0x%X)' % (j, R_START + j) if j >= 0 else 'none'))
# also try search for 06002133 946B full
il33 = bodies[0x06002133]
j = xr.find(il33)
print('   06002133 full 946B -> %s' % ('HIT' if j >= 0 else 'none'))
