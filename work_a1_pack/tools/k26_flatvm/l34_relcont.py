#!/usr/bin/env python3
# l34_relcont.py — Lead 3 (key dword relations + global-stream window theory) & Lead 4 (cross-entry continuity)
import sys, os, struct, binascii
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aot

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'

KV = binascii.unhexlify('f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943')
KM = binascii.unhexlify('cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481')
KF = binascii.unhexlify('37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a')
KZ = bytes(32)
dv = {n: list(struct.unpack('<8I', k)) for n, k in (('Viewer', KV), ('mainlib', KM), ('Factory', KF), ('zero', KZ))}

print('=== Lead 3a: pairwise dword relations ===')
M = 0xFFFFFFFF
def rotl(x, r): return ((x << r) | (x >> (32 - r))) & M if r else x
names = ['Viewer', 'mainlib', 'Factory']
found = 0
for a in names:
    for b in names:
        if a >= b: continue
        A, B = dv[a], dv[b]
        for i in range(8):
            for j in range(8):
                if A[i] ^ B[j] == 0: print('xor-eq', a, i, b, j); found += 1
                for r in range(1, 32):
                    if rotl(A[i], r) == B[j]: print('rot', a, i, b, j, r); found += 1
                if (A[i] + B[j]) & M == 0: print('add-inv', a, i, b, j); found += 1
print('simple relations found:', found)

print('xor diffs Viewer^mainlib:', [hex(x ^ y) for x, y in zip(dv['Viewer'], dv['mainlib'])])
print('xor diffs Viewer^Factory:', [hex(x ^ y) for x, y in zip(dv['Viewer'], dv['Factory'])])
print('xor diffs mainlib^Factory:', [hex(x ^ y) for x, y in zip(dv['mainlib'], dv['Factory'])])
print('add diffs Viewer-mainlib:', [hex((x - y) & M) for x, y in zip(dv['Viewer'], dv['mainlib'])])

print('=== Lead 3b: key dwords as prng outputs ===')
# within-key chain?
for a in names:
    A = dv[a]
    ok = all(aot.prng_round(A[i]) == A[i + 1] for i in range(7))
    print(a, 'self-chain prng_round(k[i])==k[i+1]:', ok)
# cross-key single step
for a in names:
    for b in names:
        if a == b: continue
        ok = all(aot.prng_round(dv[a][i]) == dv[b][i] for i in range(8))
        if ok: print('prng_round maps', a, '->', b)

print('=== Lead 3c: global zero-key stream window theory (first 4M dwords) ===')
N = 4 * 1000 * 1000
st = 0
stream = []
targets = {dv['Viewer'][i]: ('Viewer', i) for i in range(8)}
targets.update({dv['mainlib'][i]: ('mainlib', i) for i in range(8)})
targets.update({dv['Factory'][i]: ('Factory', i) for i in range(8)})
hits = []
for idx in range(N):
    st = aot.prng_round(st)
    if st in targets and len(hits) < 40:
        hits.append((idx, targets[st], hex(st)))
print('single-dword hits in first %d stream words:' % N, hits if hits else 'NONE')

print('=== Lead 3d: key windows inside per-resource keystreams ===')
for res, k in (('Viewer', KV), ('Project', KZ), ('Factory', KF), ('mainlib', KM)):
    ct = aot.res_ct(res)
    n = len(ct) // 4
    ks = aot.keystream_keyed(n, k)
    sset = {}
    for idx, v in enumerate(ks):
        sset.setdefault(v, idx)
    for kn, K in (('Viewer', KV), ('mainlib', KM), ('Factory', KF)):
        d = dv[kn]
        # check all 8 dwords present in order?
        pos = [sset.get(x, -1) for x in d]
        if all(p >= 0 for p in pos):
            print('  %s key dwords all present in %s keystream at' % (kn, res), pos)

print('=== Lead 4: cross-entry continuity ===')
# mainlib end state -> decrypt Factory head, compare to known Factory plaintext from state0=0
ctm = aot.res_ct('mainlib')
n_m = len(ctm) // 4 + (1 if len(ctm) % 4 else 0)
st_end = aot.state_after(n_m, KM)   # state after consuming all mainlib words (incl tail word)
print('mainlib end state:', hex(st_end))
ctf = aot.res_ct('Factory')
cont = aot.decrypt(ctf[:32], KF, state0=st_end)
fresh = aot.decrypt(ctf[:32], KF, state0=0)
print('Factory fresh :', fresh[:32].hex())
print('Factory contd :', cont[:32].hex())
print('continuity verdict: %s' % ('CONTINUOUS' if cont == fresh else 'DISCONTINUOUS (per-entry state=0)'))

# Viewer end -> Emitter with Viewer key (and zero key), 3 shapes
ctv = aot.res_ct('Viewer')
n_v = len(ctv) // 4
st_v = aot.state_after(n_v, KV)
print('Viewer end state:', hex(st_v))
cte = aot.res_ct('Emitter')
print('Emitter ct head32:', cte[:32].hex())
print('Emitter dec w/ Viewer key state0=Viewer_end :', aot.decrypt(cte[:32], KV, st_v)[:32].hex())
print('Emitter dec w/ Viewer key state0=0          :', aot.decrypt(cte[:32], KV, 0)[:32].hex())
print('Emitter dec w/ zero    key state0=Viewer_end:', aot.decrypt(cte[:32], KZ, st_v)[:32].hex())
print('Emitter dec w/ zero    key state0=0         :', aot.decrypt(cte[:32], KZ, 0)[:32].hex())
