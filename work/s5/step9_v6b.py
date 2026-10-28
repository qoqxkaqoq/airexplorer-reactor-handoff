# -*- coding: utf-8 -*-
"""step9: v6b = baseline + ONLY 92 flag bypass + RSA verify-forever. Zero trap patches.
Best candidate for Windows CI where NRS mechanism is intact."""
import hashlib

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
OUT  = '/root/.wine64/drive_c/airtest/surgical5_v6b.exe'

base = bytearray(open(BASE, 'rb').read())
IL92 = 0x3F91DC
assert bytes(base[IL92+0x4E1:IL92+0x4E3]) == bytes.fromhex('FE01')
base[IL92+0x4E1:IL92+0x4E3] = bytes.fromhex('FE04')
for off in (0x995, 0x2289):
    assert base[IL92+off] == 0x17
    base[IL92+off] = 0x16
WRAP = 0x405AC8
assert base[WRAP] == 0x5A
base[WRAP+1:WRAP+23] = bytes.fromhex('172a') + b'\x00'*20

assert len(base) == 9668976
open(OUT, 'wb').write(bytes(base))
print('wrote %s md5=%s' % (OUT, hashlib.md5(bytes(base)).hexdigest()))
