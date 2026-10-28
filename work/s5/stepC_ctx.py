# -*- coding: utf-8 -*-
"""stepC: dump guard-source context for traps."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
il = z.read('m_06004528.bin')[24:]
ins = disasm(il)
byoff = {e[0]: e for e in ins}
seq = [e[0] for e in ins]
idx = {o: k for k, o in enumerate(seq)}

PAT = bytes.fromhex('738F4400067A')
offs = []
i = 0
while True:
    j = il.find(PAT, i)
    if j < 0: break
    offs.append(j); i = j + 1

tgts = {}
for off, nm, opb, nxt, tg in ins:
    for t in tg:
        tgts.setdefault(t, []).append((off, nm))

# sample: for traps, take the FIRST brfalse source, print src-12..src+1
shown = 0
for o in offs:
    srcs = [s for s, n in tgts.get(o, []) if n.startswith('brfalse')]
    if not srcs: continue
    s = srcs[0]
    k = idx[s]
    print('=== trap@%04X guard src %04X ===' % (o, s))
    for kk in range(max(0, k-12), k+1):
        print('   ', fmt(ins[kk]))
    shown += 1
    if shown >= 8: break
