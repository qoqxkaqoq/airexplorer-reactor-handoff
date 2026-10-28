# -*- coding: utf-8 -*-
"""step27: disk-vs-dump diff for VerifyProcessor's callees (060041a6, 0600419f, 06004284,
0600427f) + identify which injected bodies changed vs baseline disk."""
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
        return ('rva0', 0, b'', 0)
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

def cmp(tok):
    kind, size, il, loctok = read_disk_body(tok)
    k = 'm_%08x.bin' % tok
    r = md.MethodDef.rows[(tok & 0xFFFFFF) - 1]
    name = str(r.Name)
    if k not in nb:
        print('%08x %-32s disk=%s/%dB dump=MISSING' % (tok, name, kind, size))
        return None
    b = zb.read(nb[k])
    dsize = struct.unpack_from('<I', b, 4)[0]
    dil = b[24:24+dsize]
    eq = (il == dil)
    print('%08x %-32s disk=%s/%d loctok=%s dump=%dB equal=%s' % (tok, name, kind, size, hex(loctok), dsize, eq))
    if not eq and len(il) == dsize:
        nd = sum(1 for a, c in zip(il, dil) if a != c)
        print('    byte diffs=%d' % nd)
    return (name, kind, size, il, dil, eq)

print('== VerifyProcessor callees ==')
for t in (0x060041a6, 0x0600419f, 0x06004284, 0x0600427f, 0x0600419c, 0x060041a5):
    cmp(t)

# global census: how many manifest methods have disk==dump?
print('== census (first 300 manifest rows) ==')
same = diff = missing = rva0 = 0
diffs = []
with open('/workspace/repo_git/work/c2_pack/bodies_manifest.tsv') as f:
    next(f)
    for ln in f:
        p = ln.rstrip('\n').split('\t')
        if len(p) < 2: continue
        rva, tok = p[0], p[1]
        t = int(tok, 16)
        kind, size, il, loctok = read_disk_body(t)
        k = 'm_%08x.bin' % t
        if k not in nb:
            missing += 1; continue
        b = zb.read(nb[k])
        dsize = struct.unpack_from('<I', b, 4)[0]
        dil = b[24:24+dsize]
        if kind == 'rva0':
            rva0 += 1; continue
        if il == dil:
            same += 1
        else:
            diff += 1
            if len(diffs) < 15:
                diffs.append((t, str(md.MethodDef.rows[(t & 0xFFFFFF) - 1].Name), size, dsize))
print('same=%d diff=%d missing=%d rva0=%d' % (same, diff, missing, rva0))
for d in diffs:
    print('  DIFF %08x %s disk=%d dump=%d' % d)
