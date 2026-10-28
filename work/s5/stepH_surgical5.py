# -*- coding: utf-8 -*-
"""stepH: generate surgical5.exe = baseline + P1-P4 (92 flag + RSA wrapper) + ALL 182 trap sites.
In-place equal-length patches only. Size must stay 9668976."""
import hashlib

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
OUT  = '/workspace/repo_git/tools3/unpacker/out/surgical5.exe'

PAT = bytes.fromhex('738F4400067A')   # newobj 0600448F (TemplatePredicate); throw
NEW = bytes.fromhex('142600000000')   # ldnull; pop; nop; nop; nop; nop  (6B, stack-neutral)

data = bytearray(open(BASE, 'rb').read())
orig_md5 = hashlib.md5(bytes(data)).hexdigest()
print('baseline: %d bytes md5=%s' % (len(data), orig_md5))
assert len(data) == 9668976
assert orig_md5 == 'a12b5c573e1b54e98cccc29351eaa066'

patches = []

# ---- 1) all trap sites: every on-disk PAT -> ldnull;pop;nop*4 ----
raw = []
i = 0
while True:
    j = data.find(PAT, i)
    if j < 0: break
    raw.append(j); i = j + 1
print('trap sites on disk: %d' % len(raw))
for d in raw:
    assert data[d:d+6] == PAT
    data[d:d+6] = NEW
    patches.append((d, 'trap'))

# ---- 2) 06004192 (InstantiateGlobalCalculator / anti-tamper) ----
# main check IL_04E0: ceq -> clt  (loc12 "verify failed" flag always false)
IL92 = 0x3F91DC
assert data[IL92+0x4E1:IL92+0x4E3] == bytes.fromhex('FE01'), data[IL92+0x4DF:IL92+0x4E5].hex()
data[IL92+0x4E1:IL92+0x4E3] = bytes.fromhex('FE04')
patches.append((IL92+0x4E1, '92-main ceq->clt'))
# catch blocks set loc12=1 -> 0
for off in (0x995, 0x2289):
    assert data[IL92+off] == 0x17, hex(off)
    data[IL92+off] = 0x16
    patches.append((IL92+off, '92-catch ldc.i4.1->0 @+0x%x' % off))

# ---- 3) 060041EE RSA VerifyDynamicStrategy wrapper: tiny 22B body -> ldc.i4.1; ret ----
WRAP = 0x405AC8
assert data[WRAP] == 0x5A, hex(data[WRAP])
assert data[WRAP+1:WRAP+9] == bytes.fromhex('fe090000fe090100')  # ldarg 0; ldarg 1
data[WRAP+1:WRAP+23] = bytes.fromhex('17') + b'\x2a' + b'\x00'*20
patches.append((WRAP+1, 'RSA wrapper -> ldc.i4.1; ret + pad'))

# ---- sanity: no PAT left, no stray 0600448F newobj ----
assert data.find(PAT) < 0, 'PAT still present at 0x%x' % data.find(PAT)
assert len(data) == 9668976, len(data)

open(OUT, 'wb').write(bytes(data))
print('wrote %s: %d bytes md5=%s' % (OUT, len(data), hashlib.md5(bytes(data)).hexdigest()))
print('total patch sites: %d (traps %d + 92/rsa %d)' % (len(patches), len(raw), len(patches)-len(raw)))

# verify readability of every patched trap: dump one 06004528 site
d528 = 0x41E19C
print('06004528 tail first 32B after patch:', bytes(data[d528:d528+32]).hex())
