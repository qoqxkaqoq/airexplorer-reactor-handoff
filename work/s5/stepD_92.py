# -*- coding: utf-8 -*-
"""stepD: 0600448F ctor arg-check + 06004192 loc12 consumer/catch sites."""
import zipfile, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')

def show(tok, lo, hi, note=''):
    il = z.read('m_%s.bin' % tok)[24:]
    ins = disasm(il)
    print('=== %s IL[0x%04X:0x%04X] %s (ilsize=%d) ===' % (tok, lo, hi, note, len(il)))
    for off, nm, opb, nxt, tg in ins:
        if off < lo: continue
        if off >= hi: break
        print('   ', fmt((off, nm, opb, nxt, tg)))

# 0600448F TemplatePredicate ctor: full body
il8f = z.read('m_0600448F.bin')[24:]
print('=== 0600448F full body (ilsize=%d) ===' % len(il8f))
for off, nm, opb, nxt, tg in disasm(il8f):
    print('   ', fmt((off, nm, opb, nxt, tg)))

# 06004192: main check consumer at 0x977, catch sites
show('06004192', 0x970, 0x9B0, 'consumer+catch1')
show('06004192', 0x2270, 0x22B0, 'catch2')
# find all reads of local 12 in 06004192 (FE0C 0C00 / 11 0C stloc / 0C? stloc.3=no)
il92 = z.read('m_06004192.bin')[24:]
ins = disasm(il92)
print('=== 06004192: instructions touching local 12 (11 0C stloc.s12 / FE0C 0C00 ldloc 12) ===')
for off, nm, opb, nxt, tg in ins:
    if nm == 'stloc.s' and opb == b'\x0c':
        print('   %04X stloc.s 12' % off)
    elif nm == 'fe.ldloc' and opb == b'\x0c\x00':
        print('   %04X ldloc 12' % off)
    elif nm in ('brfalse', 'brfalse.s', 'brtrue', 'brtrue.s') and False:
        pass
# context of each ldloc 12 (consumer check)
for off, nm, opb, nxt, tg in ins:
    if nm == 'fe.ldloc' and opb == b'\x0c\x00':
        k = [e[0] for e in ins].index(off)
        print('--- ldloc12@%04X context ---' % off)
        for e in ins[max(0, k-2):k+3]:
            print('   ', fmt(e))
