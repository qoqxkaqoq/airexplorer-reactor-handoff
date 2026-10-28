# -*- coding: utf-8 -*-
"""stepN2: 060046ac not in dump -> check vault + nearby dump tokens; analyze factory block flow."""
import zipfile, sys, struct
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm

Z = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(Z)
allnames = set(z.namelist())

print('=== dump zip tokens 060046a0..060046c0 ===')
for rid in range(0x46a0, 0x46c1):
    tok = 'm_0600%04x.bin' % rid
    if tok in allnames:
        print(' ', tok, len(z.read(tok)) - 24, 'B IL')

print()
print('=== vault_index rows for 060046ac / 06004527 / 06004566 / 06004523 / 06004521 ===')
for line in open('/workspace/repo_git/work/c2_pack/vault_index.tsv'):
    p = line.rstrip('\n').split('\t')
    if p[1].lower() in ('060046ac', '06004527', '06004566', '06004523', '06004521', '06004528'):
        print(' ', '\t'.join(p[:10]))

print()
print('=== bodies_manifest rows 060046a5..060046b5 ===')
for line in open('/workspace/repo_git/work/c2_pack/bodies_manifest.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 3 and p[1].startswith('060046'):
        rid = int(p[1][4:], 16)
        if 0x46a0 <= rid <= 0x46c0:
            print(' ', p[1], p[2], p[3] if len(p) > 3 else '')

# factory block flow in 06004523
il = z.read('m_06004523.bin')[24:]
ins = disasm(il)
print()
print('=== 06004523 IL 0x580..0x680 (factory + condition) ===')
for o, name, opb, no, tg in disasm(il):
    if 0x580 <= o <= 0x680:
        print('  IL_%04x: %-14s %s' % (o, name, opb.hex() if opb else ''))

# who sets local 9?
print()
print('=== stores to local 9 (V_9) in 06004523 ===')
for i, (o, name, opb, no, tg) in enumerate(ins):
    if (name == 'stloc.s' and opb and opb[0] == 9) or (name == 'fe.stloc' and opb and struct.unpack('<H', opb)[0] == 9):
        lo = max(0, i-5)
        print('--- store V_9 @IL_%04x ---' % o)
        for j in range(lo, min(len(ins), i+2)):
            m = ins[j]
            print('    IL_%04x: %-14s %s' % (m[0], m[1], m[2].hex() if m[2] else ''))
