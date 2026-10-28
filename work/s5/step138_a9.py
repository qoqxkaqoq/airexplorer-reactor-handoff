#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step138: a9 cross-bisect — separate P1/P2 (plaintext-tail bytes) from P3/P4/P5 (DB entries).

a9_p12 = a1 with P1+P2 reverted  (= baseline + DB-entry changes only)
a9_all = a1 with P3+P4+P5 reverted (= baseline + P1 + P2 only)

verdict matrix (fields = R5.I GetValue count):
  p12=6201 & all=2   -> killers are P1/P2; DB region is FREE (rewrite everything via DB)
  p12=2   & all=6201 -> killers are DB changes; P1/P2 free
  p12=2   & all=2    -> whole-file hash sentinel (or both poisoned) -> hash-replacement route
  p12=6201 & all=6201-> contradicts a8 (P1 reverted alone stayed 2) -> unlikely
"""
BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
A1 = '/workspace/repo_git/exes/AirExplorer_a1.exe'
OUT = '/workspace/repo_git/exes/'

base = open(BASE, 'rb').read()
a1 = open(A1, 'rb').read()
assert len(base) == len(a1)

# regions from step129 diff (a1 vs baseline), grouped by patch
REG = {
    'P1': (0x194524, 0x194525),
    'P2': (0x197AF0, 0x197AF1),
    'P3': (0x6444C0, 0x6444E0),   # DB entry 0600212A (+ margin)
    'P4': (0x64450C, 0x644524),   # DB entry 06002157 (+ margin)
    'P5': (0x6448F4, 0x64490C),   # DB entry 06002127 (+ margin)
}

def revert(src, name):
    buf = bytearray(src)
    lo, hi = REG[name]
    buf[lo:hi] = base[lo:hi]
    return bytes(buf)

def md5(b):
    import hashlib
    return hashlib.md5(b).hexdigest().upper()

variants = {
    'a9_p12': ['P1', 'P2'],
    'a9_all': ['P3', 'P4', 'P5'],
}
for vn, names in variants.items():
    buf = a1
    for nm in names:
        buf = revert(buf, nm)
    # sanity: count remaining diffs vs baseline
    nd = sum(1 for x, y in zip(base, buf) if x != y)
    open(OUT + 'AirExplorer_%s.exe' % vn, 'wb').write(buf)
    print('%s: md5=%s  remaining-diff-bytes-vs-baseline=%d' % (vn, md5(buf), nd))
