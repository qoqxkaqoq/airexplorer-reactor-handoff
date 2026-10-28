# -*- coding: utf-8 -*-
"""step2: WriteLocator(0600452E) body + 4528 0x63C/0x303F context + V6a disk offsets."""
import zipfile, struct, sys, glob
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}

def body(tok):
    k = 'm_' + tok + '.bin'
    if k in names:
        return z.read(names[k]), 'dump'
    for pat in ('/workspace/repo_git/work/c2_pack/bodies/*%s*' % tok,):
        g = glob.glob(pat)
        if g:
            return open(g[0], 'rb').read(), g[0]
    return None, None

print('== 0600452E (WriteLocator) ==')
b, src = body('0600452e')
if b:
    print('src=%s len=%d' % (src, len(b)))
    if b[:4] == bytes.fromhex('2e450006'):
        tok, ilsize, maxstack, ehcnt, prex, loctok = struct.unpack('<6I', b[:24])
        print('hdr: tok=%08x ilsize=%d maxstack=%d eh=%d loctok=%08x' % (tok, ilsize, maxstack, ehcnt, loctok))
        il = b[24:24+ilsize]
    else:
        il = b
    n = 0
    for ins in disasm(il):
        print('  ' + fmt(ins)); n += 1
    print('(%d instrs)' % n)
else:
    print('NOT FOUND')

rva28 = None
print('== vault entries ==')
for line in open('/workspace/repo_git/work/c2_pack/vault_index.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) > 4 and p[1].lower() in ('0600452e', '06004528', '06004523', '0600448f', '06004555'):
        print('  %s rva=%s pos=%s size=%s' % (p[1], p[0], p[3], p[4]))
        if p[1].lower() == '06004528':
            rva28 = int(p[0], 16)

b28 = body('06004528')[0]
il28 = b28[24:]

def ctx(il, off, back=0x40, fwd=0x50):
    for ins in disasm(il):
        if off - back <= ins[0] <= off + fwd:
            mark = '>>' if ins[0] == off else '  '
            print('%s %s' % (mark, fmt(ins)))

print('== 4528 around 0x63C (br -> 0x45AF SW2) ==')
ctx(il28, 0x63C, 0x30, 0x10)
print('== 4528 around 0x303F (brfalse -> 0x45A9) ==')
ctx(il28, 0x303F, 0x70, 0x40)

# V6a disk offsets
base = open('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe', 'rb').read()
d = (rva28 - 0x1E00) + 20 + 0x303F - 8
print('V6a disk off for IL 0x303F: 0x%X bytes=%s (expect 3965150000)' % (d, base[d:d+5].hex()))
d2 = (rva28 - 0x1E00) + 20 + 0x2FF2 - 8
print('IL 0x2FF2 call site disk bytes: %s' % base[d2:d2+10].hex())
# also confirm 0x45A9 trap slot (already patched in V3) maps to same formula
d3 = (rva28 - 0x1E00) + 20 + 0x45A9 - 8
print('IL 0x45A9 trap disk bytes (V3-patched in surgical5_v3): %s' % base[d3:d3+6].hex())
