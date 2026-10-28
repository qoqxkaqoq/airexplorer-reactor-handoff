# -*- coding: utf-8 -*-
"""stepO: extract disk bodies of 060046ac (factory) + 06004523/06004521 (check storage form)."""
import dnfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
pe = dnfile.dnPE(BASE)

def body_at(rva):
    off = pe.get_offset_from_rva(rva)
    d = pe.__data__
    b0 = d[off]
    if (b0 & 3) == 2:  # tiny
        size = b0 >> 2
        return 'tiny', size, bytes(d[off+1:off+1+size])
    else:  # fat
        flags_size = struct.unpack_from('<H', d, off)[0]
        hsize = (flags_size >> 12) * 4
        maxstack = struct.unpack_from('<H', d, off+2)[0]
        isize = struct.unpack_from('<I', d, off+4)[0]
        loctok = struct.unpack_from('<I', d, off+8)[0]
        return 'fat', isize, bytes(d[off+hsize:off+hsize+isize]), hex(loctok), hsize

md = pe.net.mdtables
print('MethodDef rows:', len(md.Method.rows), ' Field rows:', len(md.Field.rows) if md.Field else 0)

for tok in (0x060046AC, 0x06004523, 0x06004521, 0x06004528, 0x06004527, 0x0600448F):
    rid = tok & 0xFFFFFF
    row = md.Method.rows[rid-1]
    rva = row.Rva
    name = row.Name.value if row.Name else '?'
    print()
    print('=== 0600%05X %s rva=0x%X ===' % (rid, name, rva))
    if rva == 0:
        print('  RVA=0 (no body)'); continue
    info = body_at(rva)
    print('  header: %s ilsize=%d' % (info[0], info[1]), info[3:] if len(info) > 3 else '')
    il = info[2]
    if tok == 0x060046AC:
        # full disasm of the factory
        ins = disasm(il)
        print('  instructions:', len(ins))
        for o, nm, opb, no, tg in ins:
            print('    IL_%04x: %-14s %s' % (o, nm, opb.hex() if opb else ''))
    else:
        print('  first 48B:', il[:48].hex())
