# -*- coding: utf-8 -*-
"""stepN: identify 060046ac (exception factory) + 06004527/06004566 + full flow to factory block."""
import zipfile, sys, struct
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm

Z = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(Z)

# name lookup
names = {}
for line in open('/workspace/repo_git/work/c2_pack/bodies_manifest.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 3 and p[1].startswith('0600'):
        names[p[1]] = p[2]
for t in ('060046ac', '06004527', '06004566', '06004521', '06004523', '06004528', '0600451f', '06004524', '06004525', '06004526'):
    print(t, '=', names.get(t, '?'))

def load(tok):
    return z.read('m_%s.bin' % tok)[24:]

def dump_full(tok, lo=0, hi=10**9):
    il = load(tok)
    print('=== %s (%s) ilsize=%d ===' % (tok, names.get(tok, '?'), len(il)))
    for o, name, opb, no, tg in disasm(il):
        if lo <= o <= hi:
            ann = ''
            if name in ('call', 'callvirt', 'newobj') and opb:
                t = struct.unpack('<I', opb)[0]
                ann = ' ; 0600%x=%s' % (t & 0xFFFFFF, names.get('0600%x' % (t & 0xFFFFFF), '?'))
            print('  IL_%04x: %-14s %s%s' % (o, name, opb.hex() if opb else '', ann))

# 060046ac full
dump_full('060046ac')
print()
# flow into factory block: 0x5be..0x640
dump_full('06004523', 0x5a0, 0x650)
