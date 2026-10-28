# -*- coding: utf-8 -*-
"""step26: compare baseline on-disk body vs dump body for 060041A5/0600419C + count
global disk-vs-dump divergence; resolve 0600427f declaring type."""
import struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt
import zipfile

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

def read_disk_body(tok):
    r = md.MethodDef.rows[(tok & 0xFFFFFF) - 1]
    if r.Rva == 0:
        return None, None, None
    off = pe.get_offset_from_rva(r.Rva)
    data = pe.__data__
    b0 = data[off]
    if (b0 & 3) == 2:
        return ('tiny', b0 >> 2, bytes(data[off+1:off+1+(b0 >> 2)]), 0)
    hs = (struct.unpack_from('<H', data, off)[0] >> 12) * 4
    size = struct.unpack_from('<I', data, off+4)[0]
    loctok = struct.unpack_from('<I', data, off+8)[0]
    return ('fat', size, bytes(data[off+hs:off+hs+size]), loctok)

zb = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
nb = {n.lower(): n for n in zb.namelist()}

for tok in (0x060041a5, 0x0600419c):
    kind, size, il, loctok = read_disk_body(tok)
    print('== %08x disk: %s size=%s loctok=%s ==' % (tok, kind, size, hex(loctok) if loctok else 0))
    k = 'm_%08x.bin' % tok
    if k in nb:
        b = zb.read(nb[k])
        dsize = struct.unpack_from('<I', b, 4)[0]
        dil = b[24:24+dsize]
        print('  dump size=%d equal=%s' % (dsize, il == dil))
        if il and il != dil and len(il) == dsize:
            nd = sum(1 for a, c in zip(il, dil) if a != c)
            print('  byte diffs=%d' % nd)
    if tok == 0x060041a5 and il:
        print('  disk disasm:')
        for ins in disasm(il):
            print('   ', fmt(ins))

# 0600427f declaring type: scan TypeDef method ranges
target_rid = 0x427F
owner = None
for i, t in enumerate(md.TypeDef.rows):
    try:
        rids = [m.row_index for m in t.MethodList]
    except Exception:
        continue
    if not rids:
        continue
    lo, hi = min(rids), max(rids)
    if lo <= target_rid <= hi:
        owner = (0x02000000 + i + 1, str(t.TypeNamespace), str(t.TypeName), lo, hi)
print('0600427f owner:', owner)

# the method's sig
r = md.MethodDef.rows[target_rid - 1]
print('0600427f name=%s implflags=%x' % (str(r.Name), r.ImplFlags))
sig = bytes(r.Signature.value)
print('0600427f sig=%s' % sig.hex())
