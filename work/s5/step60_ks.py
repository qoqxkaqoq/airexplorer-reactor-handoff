# -*- coding: utf-8 -*-
"""step60: recover keystream KS = C ^ P for res5, test seeded-PRNG hypothesis.
If KS[1] == round(KS[0]) -> seeded PRNG-XOR confirmed; brute-force seed after."""
import struct, sys
sys.path.insert(0, '/workspace/repo_git/work')
from decrypt_prng import prng_round

C = open('/workspace/repo_git/work/s5/res5_FactoryValidator.bin', 'rb').read()
P = open('/tmp/v2art/app/dump/stat2__ExtractorVisitors.bin', 'rb').read()
n = len(C) // 4
KSw = [struct.unpack_from('<I', C, 4*i)[0] ^ struct.unpack_from('<I', P, 4*i)[0] for i in range(16)]
print('KS[0:8] =', ' '.join('%08X' % w for w in KSw[:8]))

# H1: plain chain ks[i+1] = round(ks[i])
pred = prng_round(KSw[0])
print('H1 round(KS0)=%08X vs KS1=%08X  -> %s' % (pred, KSw[1], 'MATCH' if pred == KSw[1] else 'no'))

# H2: chain on C/P words directly?
for name, a, b in [('C0->C1', struct.unpack_from('<I', C, 0)[0], struct.unpack_from('<I', C, 4)[0]),
                   ('P0->P1', struct.unpack_from('<I', P, 0)[0], struct.unpack_from('<I', P, 4)[0])]:
    print('H2 %s: round(%08X)=%08X vs %08X -> %s' % (name, a, prng_round(a), b, 'MATCH' if prng_round(a) == b else 'no'))

# H3: maybe KS is used in reverse or word-swapped; test round on byte-swapped
ks0bsw = struct.unpack('<I', struct.pack('>I', KSw[0]))[0]
print('H3 bswap: round(KS0bsw)=%08X vs KS1bsw=%08X' % (prng_round(ks0bsw), struct.unpack('<I', struct.pack('>I', KSw[1]))[0]))

# H4: differential — check if KS has PRNG-like structure at other alignments:
# try ks[i+1] = round(ks[i]) for i in 1..8
ok = 0
for i in range(1, 12):
    if prng_round(KSw[i]) == KSw[i+1]: ok += 1
print('H4 chain i=1..11 matches: %d/11' % ok)
