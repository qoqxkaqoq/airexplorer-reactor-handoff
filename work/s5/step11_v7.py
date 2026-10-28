# -*- coding: utf-8 -*-
"""step11: v7 = baseline + ONLY 182 trap patches (no 92, no RSA/WRAP).
Bisection after CI matrix proved 92 = GAE killer (v6d), RSA/WRAP = tamper killer (v6c).
Goal: A-line trap cleanup candidate — neutralize all `newobj TemplatePredicate(0600448F); throw` sites."""
import hashlib

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
OUT  = '/workspace/repo_git/exes/AirExplorer_v7.exe'

PAT = bytes.fromhex('738F4400067A')   # newobj 0600448F (TemplatePredicate); throw
NEW = bytes.fromhex('142600000000')   # ldnull; pop; nop*4 (6B, stack-neutral)

data = bytearray(open(BASE, 'rb').read())
assert len(data) == 9668976
assert hashlib.md5(bytes(data)).hexdigest() == 'a12b5c573e1b54e98cccc29351eaa066'

sites = []
i = 0
while True:
    j = data.find(PAT, i)
    if j < 0: break
    sites.append(j); i = j + 1
print('trap sites on disk: %d' % len(sites))
for d in sites:
    assert data[d:d+6] == PAT
    data[d:d+6] = NEW

assert data.find(PAT) < 0
assert len(data) == 9668976
open(OUT, 'wb').write(bytes(data))
print('wrote %s md5=%s (traps=%d, no 92, no WRAP)' % (OUT, hashlib.md5(bytes(data)).hexdigest(), len(sites)))
