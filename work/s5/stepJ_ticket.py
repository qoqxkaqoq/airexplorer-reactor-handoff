# -*- coding: utf-8 -*-
"""stepJ: verify ticket = hash(tail plaintext) hypothesis.
vault entries: 060042F4->fe2d38eb, 06004353->febeb4d1, 060043B5->feb80e1d"""
import sys, struct
sys.path.insert(0, '/workspace/repo_git/work')
from decrypt_prng import prng_round, u32

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
base = open(BASE, 'rb').read()

M = [
    ('060042F4', 0x410F78, 250, 0xfe2d38eb),
    ('06004353', 0x4140AC, 209, 0xfebeb4d1),
    ('060043B5', 0x4176A0, 408, 0xfeb80e1d),
]

def tail_words(tail_start, ilsize):
    data = base[tail_start:tail_start + ilsize - 8]
    n = len(data) // 4 + (1 if len(data) % 4 else 0)
    ws = []
    for w in range(n):
        off = w * 4
        if w == n - 1 and len(data) % 4:
            word = 0
            rem = len(data) - off
            for j in range(rem):
                if j > 0: word = (word << 8) & 0xFFFFFFFF
                word |= data[len(data) - 1 - j]
            ws.append(u32(word))
        else:
            ws.append(u32(data[off] | (data[off+1] << 8) | (data[off+2] << 16) | (data[off+3] << 24)))
    return ws

def tail_bytes(tail_start, ilsize):
    return base[tail_start:tail_start + ilsize - 8]

inits = {'0': 0, 'rva': None, 'ilsize': None, 'pos': None}

for tok, rva, ilsize, ticket in M:
    tail_start = rva - 0x1E00 + 20
    ws = tail_words(tail_start, ilsize)
    tb = tail_bytes(tail_start, ilsize)
    targets = (ticket, ((ticket & 0xFF) << 24) | ((ticket & 0xFF00) << 8) | ((ticket >> 8) & 0xFF00) | (ticket >> 24))
    print('=== %s ilsize=%d nwords=%d ticket=%08x targets=%s' % (tok, ilsize, len(ws), ticket, [hex(t) for t in targets]))

    results = {}

    # fold candidates
    def fold_add_prng(ws, init):  # state=prng_round(state+w)
        s = init
        for w in ws: s = prng_round(u32(s + w))
        return s
    def fold_xor_prng(ws, init):
        s = init
        for w in ws: s = prng_round(u32(s ^ w))
        return s
    def fold_prng_add(ws, init):
        s = init
        for w in ws: s = u32(s + prng_round(w))
        return s
    def fold_prng_xor(ws, init):
        s = init
        for w in ws: s = u32(s ^ prng_round(w))
        return s
    def fold_addonly(ws, init):
        s = init
        for w in ws: s = u32(s + w)
        return s
    def fold_xoronly(ws, init):
        s = init
        for w in ws: s = u32(s ^ w)
        return s
    def fold_prng_state_only(ws, init):
        s = init
        for w in ws: s = prng_round(s)
        return s

    init_cands = {
        '0': 0,
        'rva': rva,
        'tailstart': tail_start,
        'ilsize': ilsize,
        'rvaxil': u32(rva * ilsize),
        '0x45EE': 0x45EE,
    }
    for fname, f in [('add_prng', fold_add_prng), ('xor_prng', fold_xor_prng),
                     ('prng_add', fold_prng_add), ('prng_xor', fold_prng_xor),
                     ('addonly', fold_addonly), ('xoronly', fold_xoronly),
                     ('state_only', fold_prng_state_only)]:
        for iname, iv in init_cands.items():
            r = f(ws, iv)
            results['%s/%s/words' % (fname, iname)] = r
            if r in targets:
                print('  HIT %s init=%s -> %08x' % (fname, iname, r))

    # byte-wise xor of ascii tail
    results['xorbytes'] = 0
    x = 0
    for b in tb: x ^= b
    results['xorbytes'] = x
    results['sumbytes'] = sum(tb) & 0xFFFFFFFF
    for k, v in results.items():
        if v in targets:
            print('  HIT simple %s -> %08x' % (k, v))

    # keystate after full prng chain on the *plaintext as if decrypting*:
    s = 0
    for w in ws: s = prng_round(s)
    print('  state_chain_end=%08x' % s)
    print('  addonly=%08x xoronly=%08x' % (fold_addonly(ws, 0), fold_xoronly(ws, 0)))
    print('  add_prng(0)=%08x xor_prng(0)=%08x' % (fold_add_prng(ws, 0), fold_xor_prng(ws, 0)))
    print('  prng_add(0)=%08x prng_xor(0)=%08x' % (fold_prng_add(ws, 0), fold_prng_xor(ws, 0)))
