# -*- coding: utf-8 -*-
"""step5b: GAE catch state machine full walk + V_8 dataflow."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
b = z.read('m_06004523.bin')
tokv, ilsize, maxstack, ehcnt, prex, loctok = struct.unpack('<6I', b[:24])
il = b[24:24+ilsize]
ins_list = disasm(il)

def opb(ins):
    return ins[2]

def dump_range(lo, hi, tag):
    print('==== %s [%04X..%04X) ====' % (tag, lo, hi))
    for ins in ins_list:
        if lo <= ins[0] < hi:
            print('  ' + fmt(ins))

# catch state machine whole
dump_range(0x1DB, 0x727, 'CATCH SM')
