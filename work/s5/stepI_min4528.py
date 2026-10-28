# -*- coding: utf-8 -*-
"""stepI: experiment - baseline + ONLY 06004528's 68 traps + 92/RSA patches.
Diagnose whether 060042F4 InvalidProgram is caused by patching its own tail."""
import hashlib, zipfile, sys

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
OUT  = '/root/.wine64/drive_c/airtest/surgical5_min4528.exe'

PAT = bytes.fromhex('738F4400067A')
NEW = bytes.fromhex('142600000000')

# 06004528 tail disk start (verified: TAIL=0x41E19C)
TAIL = 0x41E19C
z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
il = z.read('m_06004528.bin')[24:]

data = bytearray(open(BASE, 'rb').read())
n = 0
pos = 8
while True:
    off = il.find(PAT, pos)
    if off < 0: break
    pos = off + 1
    d = TAIL + off - 8
    assert data[d:d+6] == PAT
    data[d:d+6] = NEW
    n += 1
print('06004528 traps patched: %d' % n)

# 92 flag + RSA wrapper (same as stepH)
IL92 = 0x3F91DC
assert data[IL92+0x4E1:IL92+0x4E3] == bytes.fromhex('FE01')
data[IL92+0x4E1:IL92+0x4E3] = bytes.fromhex('FE04')
for off in (0x995, 0x2289):
    assert data[IL92+off] == 0x17
    data[IL92+off] = 0x16
WRAP = 0x405AC8
assert data[WRAP] == 0x5A
data[WRAP+1:WRAP+23] = bytes.fromhex('172a') + b'\x00'*20

assert len(data) == 9668976
open(OUT, 'wb').write(bytes(data))
print('wrote %s md5=%s' % (OUT, hashlib.md5(bytes(data)).hexdigest()))
