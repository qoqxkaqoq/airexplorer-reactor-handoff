#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step139: xref 41ED/41EE/41EA/41CE/41E2 + get_Hash MemberRef across ALL program IL.
Confirms 4192 is the only SHA1 hash producer/consumer (no bypass sentinel)."""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse
import dnfile

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'

il = open(ALL, 'rb').read()
bodies = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        bodies[int(p[0], 16)] = (int(p[1]), int(p[4]))

pe = dnfile.dnPE(EXE)
md = pe.net.mdtables

# resolve 0A:000a0b (HashAlgorithm::get_Hash) and 0A:000a0c (RSA::VerifyHash) — find ALL MemberRefs
# whose class is HashAlgorithm and name get_Hash / ComputeHash / TransformFinalBlock / TransformBlock
targets = {}   # tok -> label
for i, m in enumerate(md.MemberRef.rows):
    try:
        cls = m.Class.row
        cn = str(getattr(cls, 'TypeName', '') or '')
        nm = str(m.Name)
    except Exception:
        continue
    if cn in ('HashAlgorithm', 'SHA1', 'SHA1Managed', 'SHA1CryptoServiceProvider') or \
       (nm in ('get_Hash', 'ComputeHash', 'TransformFinalBlock', 'TransformBlock') and 'rypto' in str(getattr(cls, 'TypeNamespace', ''))):
        targets[0x0A000000 | (i + 1)] = '%s::%s' % (cn, nm)

print('[crypto MemberRefs]:')
for t, n in sorted(targets.items()):
    print('  %08x %s' % (t, n))

watch_methods = {0x06000000 | r for r in (0x41ED, 0x41EE, 0x41EA, 0x41E2, 0x41CE, 0x41CF, 0x41EB)}
hits = {t: [] for t in list(targets) + list(watch_methods)}

for tok, (clen, pos) in bodies.items():
    if clen <= 0 or clen > 400000:
        continue
    try:
        for off, name, k, op, plen in parse(il[pos:pos+clen]):
            if k == 'tok' and name in ('call', 'callvirt', 'newobj', 'ldftn') and op in hits:
                hits[op].append((tok, name, off))
    except Exception:
        continue

print('\n[callers of stubs + crypto MemberRefs]:')
for t in sorted(hits):
    lbl = '06:%06x' % (t & 0xFFFFFF) if (t >> 24) == 0x06 else targets.get(t, '%08x' % t)
    lst = hits[t]
    bym = {}
    for tok, nm, off in lst:
        bym.setdefault(tok, []).append(off)
    print('  %s: %d sites in %d methods' % (lbl, len(lst), len(bym)))
    for tok, offs in sorted(bym.items()):
        mark = ' <== 4192' if tok == 0x06004192 else ''
        print('     06:%06x @%s%s' % (tok & 0xFFFFFF, ','.join('%04x' % x for x in offs[:8]), mark))
