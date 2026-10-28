# -*- coding: utf-8 -*-
"""step16: all write sites of V_0D/V_17/V_18 in 06004192 (stloc.s one-byte form)."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
b = z.read('m_06004192.bin')
ilsize = struct.unpack_from('<I', b, 4)[0]
il = b[24:24+ilsize]
ins_list = disasm(il)

for slot in (0x0D, 0x17, 0x18):
    print('== writes to V_%02X ==' % slot)
    for ins in ins_list:
        if ins[1] == 'stloc.s' and len(ins[2]) == 1 and ins[2][0] == slot:
            print('  %04X stloc.s %02x' % (ins[0], slot))
        elif ins[1] == 'fe.stloc' and struct.unpack_from('<H', ins[2])[0] == slot:
            print('  %04X stloc %02x' % (ins[0], slot))

# context before each V_18 (signature) write
print('== context around V_18 writes ==')
for idx, ins in enumerate(ins_list):
    if ins[1] == 'stloc.s' and len(ins[2]) == 1 and ins[2][0] == 0x18:
        for j in range(max(0, idx-8), idx+1):
            print('  ' + fmt(ins_list[j]))
        print('  ---')
