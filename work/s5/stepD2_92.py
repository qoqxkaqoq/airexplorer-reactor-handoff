# -*- coding: utf-8 -*-
"""stepD2: 06004192 loc12 sites + 060041EE disk body."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
il92 = z.read('m_06004192.bin')[24:]
ins = disasm(il92)
seq = [e[0] for e in ins]
idx = {o: k for k, o in enumerate(seq)}

print('ilsize=%d' % len(il92))
sites = []
for off, nm, opb, nxt, tg in ins:
    if nm == 'stloc.s' and opb == b'\x0c':
        sites.append((off, 'ST', None))
    elif nm == 'fe.ldloc' and opb == b'\x0c\x00':
        sites.append((off, 'LD', None))
print('local12 touchpoints: %d' % len(sites))
for off, kind, _ in sites:
    k = idx[off]
    print('--- %s@%04X ---' % (kind, off))
    for e in ins[max(0, k-3):k+4]:
        print('   ', fmt(e))
