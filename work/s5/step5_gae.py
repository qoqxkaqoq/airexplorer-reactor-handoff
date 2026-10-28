# -*- coding: utf-8 -*-
"""step5: GAE full disasm (dump body) + EH + local slots of state vars."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}
b = z.read(names['m_06004523.bin'])
tokv, ilsize, maxstack, ehcnt, prex, loctok = struct.unpack('<6I', b[:24])
il = b[24:24+ilsize]
print('GAE: ilsize=%d maxstack=%d ehcnt=%d' % (ilsize, maxstack, ehcnt))
# eh blob after code (align4)
off = 24 + ilsize
off = (off + 3) & ~3
print('len(b)=%d eh blob at 0x%x' % (len(b), off))
if len(b) >= off + 4:
    u = struct.unpack_from('<I', b, off)[0]
    esz = (u >> 8) & 0xFFFFFF
    off += 4
    for ci in range(ehcnt):
        cl = b[off+ci*24: off+ci*24+24]
        ft, tro, trl, ho, hl, ct = struct.unpack('<IIIIHH', cl[:20])
        print('  clause flags=0x%x try=[%04X..%04X) handler=[%04X..%04X) class=0x%08x' % (ft, tro, tro+trl, ho, ho+hl, ct))

ins_list = disasm(il)
# find switch at 0x20A and its local
print('== all switches ==')
for ins in ins_list:
    if ins[1] == 'switch' and ins[4]:
        print('  switch@%04X %d cases -> %s' % (ins[0], len(ins[4]), ' '.join('%04X' % t for t in ins[4])))
print('== head (state init) ==')
for ins in ins_list:
    if ins[0] <= 0x30:
        print('  ' + fmt(ins))
print('== catch entry 0x1DB.. ==')
for ins in ins_list:
    if 0x1DB <= ins[0] <= 0x230:
        print('  ' + fmt(ins))
print('== V_8 (local 8) writes/reads ==')
for ins in ins_list:
    if ins[1] == 'stloc.s' and ins[3] == b'\x08':
        print('  %04X stloc.s 08' % ins[0])
    elif ins[1] == 'ldloc.s' and ins[3] == b'\x08':
        print('  %04X ldloc.s 08' % ins[0])
    elif ins[1] == 'fe.stloc' and struct.unpack_from('<H', ins[3])[0] == 0x0800:
        print('  %04X stloc 08' % ins[0])
    elif ins[1] == 'fe.ldloc' and struct.unpack_from('<H', ins[3])[0] == 0x0800:
        print('  %04X ldloc 08' % ins[0])
