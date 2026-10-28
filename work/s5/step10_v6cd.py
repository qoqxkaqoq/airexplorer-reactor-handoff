# -*- coding: utf-8 -*-
"""step10: v6c = baseline + RSA only; v6d = baseline + 92 only. Bisection of harmful patch."""
import hashlib

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
base0 = open(BASE, 'rb').read()

def apply92(b):
    IL92 = 0x3F91DC
    assert bytes(b[IL92+0x4E1:IL92+0x4E3]) == bytes.fromhex('FE01')
    b[IL92+0x4E1:IL92+0x4E3] = bytes.fromhex('FE04')
    for off in (0x995, 0x2289):
        assert b[IL92+off] == 0x17
        b[IL92+off] = 0x16
    return b

def apply_rsa(b):
    WRAP = 0x405AC8
    assert b[WRAP] == 0x5A
    b[WRAP+1:WRAP+23] = bytes.fromhex('172a') + b'\x00'*20
    return b

v6c = bytearray(base0); apply_rsa(v6c)
assert len(v6c) == 9668976
open('/root/.wine64/drive_c/airtest/surgical5_v6c.exe', 'wb').write(bytes(v6c))
open('/workspace/repo_git/exes/AirExplorer_v6c.exe', 'wb').write(bytes(v6c))
print('v6c (RSA only) md5=%s' % hashlib.md5(bytes(v6c)).hexdigest())

v6d = bytearray(base0); apply92(v6d)
assert len(v6d) == 9668976
open('/root/.wine64/drive_c/airtest/surgical5_v6d.exe', 'wb').write(bytes(v6d))
open('/workspace/repo_git/exes/AirExplorer_v6d.exe', 'wb').write(bytes(v6d))
print('v6d (92 only)  md5=%s' % hashlib.md5(bytes(v6d)).hexdigest())
