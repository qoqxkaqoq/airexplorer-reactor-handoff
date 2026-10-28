# -*- coding: utf-8 -*-
"""step8: V6a = V3 with 4528's 68 traps restored to original PAT (official exception
driven control flow experiment). 92/RSA/other patches kept."""
import hashlib, zipfile

V3   = '/root/.wine64/drive_c/airtest/surgical5_v3.exe'
BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
OUT  = '/root/.wine64/drive_c/airtest/surgical5_v6a.exe'

RVA28 = 0x41FF88
TAIL_BASE = (RVA28 - 0x1E00) + 20          # disk offset of IL[8]
PAT = bytes.fromhex('738F4400067A')

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
il = z.read('m_06004528.bin')[24:]

v3 = bytearray(open(V3, 'rb').read())
base = open(BASE, 'rb').read()

# collect trap IL offsets (>=8, within tail)
offs = []
i = 0
while True:
    j = il.find(PAT, i)
    if j < 0: break
    i = j + 1
    if j >= 8:
        offs.append(j)
print('4528 traps in dump IL: %d' % len(offs))

n = 0
for off in offs:
    d = TAIL_BASE + off - 8
    cur = bytes(v3[d:d+6])
    if cur == PAT:
        continue
    assert bytes(base[d:d+6]) == PAT, 'baseline mismatch at 0x%x' % d
    v3[d:d+6] = PAT
    n += 1
print('restored to PAT: %d (already PAT: %d)' % (n, len(offs) - n))

# restore the 0x303F brfalse guard too (it was never patched in V3, verify)
d = TAIL_BASE + 0x303F - 8
print('0x303F guard bytes now: %s (expect 3965150000)' % bytes(v3[d:d+5]).hex())

assert len(v3) == 9668976
open(OUT, 'wb').write(bytes(v3))
print('wrote %s md5=%s' % (OUT, hashlib.md5(bytes(v3)).hexdigest()))
