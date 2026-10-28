# -*- coding: utf-8 -*-
"""step7: 0600448F ctor (memdump body) + 06004526 InstantiateLocalSpec + 06004527 dump bodies."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}

def dump_body(tok):
    k = 'm_' + tok + '.bin'
    if k not in names:
        return None
    b = z.read(names[k])
    tokv, ilsize, maxstack, ehcnt, prex, loctok = struct.unpack('<6I', b[:24])
    return b[24:24+ilsize], ilsize

mem = open('/workspace/repo_git/work_a1_pack/memdump/module_text.bin', 'rb').read()

def mem_body(rva):
    off = rva - 0x2000
    b0 = mem[off]
    if b0 & 3 == 2:
        return mem[off+1:off+1+(b0 >> 2)]
    u16 = struct.unpack_from('<H', mem, off)[0]
    hdrsz = (u16 >> 12) * 4
    csz = struct.unpack_from('<I', mem, off+4)[0]
    return mem[off+hdrsz:off+hdrsz+csz]

print('== 0600448F TemplatePredicate ctor (memdump runtime body) ==')
for ins in disasm(mem_body(0x41cbac)):
    print('  ' + fmt(ins))

for tok in ('06004526', '06004527'):
    r = dump_body(tok)
    print('== %s dump body ilsize=%d ==' % (tok, r[1]))
    for ins in disasm(r[0]):
        print('  ' + fmt(ins))
