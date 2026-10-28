# -*- coding: utf-8 -*-
"""step17: 06004192 init block (0x40..0x110), sig read wrapper 060041EB, 0x0AB0-0x0B20."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
b = z.read('m_06004192.bin')
ilsize = struct.unpack_from('<I', b, 4)[0]
il = b[24:24+ilsize]
ins_list = disasm(il)

def dump_range(lo, hi, tag):
    print('==== %s ====' % tag)
    for ins in ins_list:
        if lo <= ins[0] < hi:
            print('  ' + fmt(ins))

dump_range(0x40, 0x110, 'init 0x40-0x110')
dump_range(0x0AA0, 0x0B30, 'hash/alg re-init 0xAA0-0xB30')

print('==== 060041EB body ====')
b2 = z.read('m_060041eb.bin')
ilsize2 = struct.unpack_from('<I', b2, 4)[0]
for ins in disasm(b2[24:24+ilsize2]):
    print('  ' + fmt(ins))
