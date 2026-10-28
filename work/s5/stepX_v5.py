# -*- coding: utf-8 -*-
"""stepX: V5 = V3 + P7 only (no P6). Discriminate which patch caused ArgumentOutOfRange."""
import hashlib, zipfile

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
OUT  = '/root/.wine64/drive_c/airtest/surgical5_v5.exe'

PAT  = bytes.fromhex('738F4400067A')
MID  = bytes.fromhex('142600000000')
TAIL = bytes.fromhex('142a0000002a')

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
ilmap = {}
for n in z.namelist():
    if n.startswith('m_'):
        ilmap[n[2:-4].lower()] = z.read(n)[24:]

tail_traps = set()
for tok, il in ilmap.items():
    ilsize = len(il)
    pos = 0
    while True:
        off = il.find(PAT, pos)
        if off < 0: break
        pos = off + 1
        if off + 6 >= ilsize:
            tail_traps.add((tok, off))

base = bytearray(open(BASE, 'rb').read())
PATB = bytes(PAT)
vault = {}
for line in open('/workspace/repo_git/work/c2_pack/vault_index.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) > 4 and p[1].lower().startswith('0600'):
        vault[p[1].lower()] = int(p[0], 16)

claimed = {}
for tok, il in sorted(ilmap.items()):
    pos = 0
    while True:
        off = il.find(PAT, pos)
        if off < 0: break
        pos = off + 1
        got = None
        if tok in vault:
            exp = (vault[tok] - 0x1E00) + 20 + off - 8
            if 0 <= exp <= len(base)-6 and bytes(base[exp:exp+6]) == PATB:
                got = (exp, 'vault')
        if got is None:
            w0 = max(0, off - 8)
            win = bytes(il[w0:off+8])
            occ = []
            k = 0
            while True:
                j = base.find(win, k)
                if j < 0: break
                occ.append(j + (off - w0)); k = j + 1
            if len(occ) == 1:
                got = (occ[0], 'uniq')
            elif occ:
                free = [o for o in occ if o not in claimed]
                if len(free) == 1:
                    got = (free[0], 'free')
        if got:
            claimed[got[0]] = (tok, off, got[1])

n_mid = n_tail = 0
for d, (tok, off, how) in sorted(claimed.items()):
    if (tok, off) in tail_traps:
        base[d:d+6] = TAIL; n_tail += 1
    else:
        base[d:d+6] = MID; n_mid += 1
i = 0
while True:
    j = base.find(PATB, i)
    if j < 0: break
    base[j:j+6] = TAIL; i = j + 6

IL92 = 0x3F91DC
assert bytes(base[IL92+0x4E1:IL92+0x4E3]) == bytes.fromhex('FE01')
base[IL92+0x4E1:IL92+0x4E3] = bytes.fromhex('FE04')
for off in (0x995, 0x2289):
    assert base[IL92+off] == 0x17
    base[IL92+off] = 0x16
WRAP = 0x405AC8
assert base[WRAP] == 0x5A
base[WRAP+1:WRAP+23] = bytes.fromhex('172a') + b'\x00'*20

# P7 only
T28 = 0x41E19C
d = T28 + 0x3522 - 8
orig = bytes.fromhex('027B482000046F81450006146F5545000674200000017A')
assert bytes(base[d:d+23]) == orig, bytes(base[d:d+23]).hex()
base[d:d+23] = b'\x00'*23
print('P7 patched @0x%x' % d)

assert len(base) == 9668976
assert base.find(PATB) < 0
open(OUT, 'wb').write(bytes(base))
print('wrote %s md5=%s' % (OUT, hashlib.md5(bytes(base)).hexdigest()))
