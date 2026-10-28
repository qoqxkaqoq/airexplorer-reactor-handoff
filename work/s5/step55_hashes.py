# -*- coding: utf-8 -*-
"""step55: match res[1] (8x32B hash table) against file regions (SHA1/SHA256 of
06004192 body, res blobs, sections) to map sentinel coverage."""
import struct, hashlib, dnfile

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
data = open(BASE, 'rb').read()
pe = dnfile.dnPE(BASE)
cor20 = pe.net.struct
rbase = pe.get_offset_from_rva(cor20.ResourcesRva)
RES = [(0x0, 356328), (0x56FEC, 256), (0x570F0, 47915), (0x62C1F, 26128), (0x69233, 2337031), (0x2A3B3E, 398794)]

# res[1] raw (256B) — read as both raw and try as-is
r1 = data[rbase+0x56FEC+4 : rbase+0x56FEC+4+256]
print('res[1] raw:', r1[:64].hex())
entries = [r1[i*32:(i+1)*32] for i in range(8)]

# candidate regions
regions = {}
for idx, (off, sz) in enumerate(RES):
    regions['res%d' % idx] = data[rbase+off+4:rbase+off+4+sz]
# 06004192 disk body: fat header at RVA; find body extent
mdt = pe.net.mdtables
row = mdt.MethodDef.rows[0x4192-1]
o = pe.get_offset_from_rva(row.Rva)
hs = (data[o+1] >> 4) * 4
ilsz = struct.unpack_from('<I', data, o+4)[0]
ehc = struct.unpack_from('<H', data, o+8)[0] >> 11
ehoff = o + hs + ilsz
ehsz = ehc * 24 + 4 if ehc else 0
body = data[o:o+hs+ilsz+ehsz]
regions['m4192_body_full'] = body
regions['m4192_il'] = data[o+hs:o+hs+ilsz]
regions['m4192_hdr+il'] = data[o:o+hs+ilsz]
# also with original bytes (v6e/v6f would change) - baseline = original
# whole cctor? entrypoint 06002D22
row2 = mdt.MethodDef.rows[0x2D22-1]
o2 = pe.get_offset_from_rva(row2.Rva)
hs2 = (data[o2+1] >> 4) * 4
ilsz2 = struct.unpack_from('<I', data, o2+4)[0]
regions['cctor_il'] = data[o2+hs2:o2+hs2+ilsz2]
# resources region whole
regions['res_region'] = data[rbase:rbase+0x30510C]
# metadata
md_off = pe.get_offset_from_rva(cor20.MetaDataRva)
md_size = cor20.ResourcesRva - cor20.MetaDataRva
regions['metadata'] = data[md_off:md_off+md_size]

print('\nentries:')
for i, e in enumerate(entries):
    print(' [%d] %s' % (i, e.hex()))

print('\nregion hash match test:')
for rn, rb in regions.items():
    h1 = hashlib.sha1(rb).digest()
    h256 = hashlib.sha256(rb).digest()
    md5 = hashlib.md5(rb).digest()
    for i, e in enumerate(entries):
        if e[:20] == h1 or e == h1 + e[20:] or h1 in e:
            print('  HIT sha1  %s vs entry%d' % (rn, i))
        if e[:32] == h256 or h256 == e:
            print('  HIT sha256 %s vs entry%d' % (rn, i))
        if h1 == e[:20] or h256 == e[:32] or md5 == e[:16]:
            print('  HIT(prefix) %s vs entry%d' % (rn, i))
# check entry structure: any all-zero tails?
for i, e in enumerate(entries):
    print('  entry%d tail12=%s nonzero=%d' % (i, e[20:].hex(), sum(1 for b in e if b)))
