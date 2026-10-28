# -*- coding: utf-8 -*-
"""step24: read the injected method body of 060041A5 (VerifyProcessor) and 0600419C
(DefineEfficientProfiler) from out/m1_s1_full.exe via RVA; compare with dump bodies."""
import struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt
import zipfile

pe = dnfile.dnPE('/workspace/repo_git/tools3/unpacker/out/m1_s1_full.exe')
md = pe.net.mdtables

def read_body(rva):
    off = pe.get_offset_from_rva(rva)
    data = pe.__data__
    b0 = data[off]
    if (b0 & 3) == 2:  # tiny
        size = b0 >> 2
        return ('tiny', size, bytes(data[off+1:off+1+size]), 0, None)
    # fat
    flags_size = struct.unpack_from('<H', data, off)[0]
    hsize = (flags_size >> 12) * 4
    maxstack = struct.unpack_from('<H', data, off+2)[0]
    csize = struct.unpack_from('<I', data, off+4)[0]
    loctok = struct.unpack_from('<I', data, off+8)[0]
    return ('fat', csize, bytes(data[off+hsize:off+hsize+csize]), maxstack, loctok)

zb = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
nb = {n.lower(): n for n in zb.namelist()}

for tok in (0x060041a5, 0x0600419c):
    r = md.MethodDef.rows[(tok & 0xFFFFFF) - 1]
    print('== %08x %s rva=0x%x ==' % (tok, str(r.Name), r.Rva))
    if r.Rva == 0:
        print('  RVA=0 (no body)')
        continue
    kind, size, il, maxstack, loctok = read_body(r.Rva)
    print('  hdr=%s size=%d maxstack=%s loctok=%s' % (kind, size, maxstack, hex(loctok) if loctok else '0'))
    k = 'm_%08x.bin' % tok
    if k in nb:
        b = zb.read(nb[k])
        dilsize = struct.unpack_from('<I', b, 4)[0]
        dil = b[24:24+dilsize]
        print('  dump ilsize=%d  match=%s' % (dilsize, dil == il[:dilsize]))
        if dil != il[:dilsize] and dilsize == size:
            for i in range(min(dilsize, size)):
                if dil[i] != il[i]:
                    print('  first diff @%04x: disk=%02x dump=%02x' % (i, il[i], dil[i]))
                    break
    if tok == 0x060041a5:
        print('  --- disasm ---')
        for ins in disasm(il):
            print('   ', fmt(ins))
