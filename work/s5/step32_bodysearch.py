# -*- coding: utf-8 -*-
"""step32: where do real bodies live in baseline file?
1) file offsets of 182 trap PAT sites vs payload region (rva 0x620000-0x920000)
2) search plaintext dump-body IL of a1patch targets in whole file
3) RVA->file offset mapping sanity for class-3 real-in-place methods
"""
import struct, zipfile

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
data = open(BASE, 'rb').read()
n = len(data)
print('file size: %d (0x%X)' % (n, n))

import dnfile
pe = dnfile.dnPE(BASE)
# section table
print('sections:')
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode(errors='replace')
    print('  %-8s va=0x%06X vsz=0x%06X raw=0x%06X rsz=0x%06X' % (name, s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData))

def rva2off(rva):
    return pe.get_offset_from_rva(rva)

# 1) trap sites
PAT = bytes.fromhex('738F4400067A')
sites = []
i = 0
while True:
    j = data.find(PAT, i)
    if j < 0: break
    sites.append(j); i = j + 1
print('trap PAT sites: %d' % len(sites))
for d in sites[:8]:
    print('   off=0x%06X' % d)
print('   ... off range: 0x%06X - 0x%06X' % (min(sites), max(sites)))

# 2) plaintext search of a1 target real bodies
z = zipfile.ZipFile(DUMP)
for tok in [0x06002127, 0x0600212A, 0x06002133, 0x06002145, 0x06002157, 0x06000CEE]:
    d = z.read('m_%08X.bin' % tok)
    ilsz = struct.unpack('<I', d[4:8])[0]
    il = d[24:24 + ilsz]
    hits = []
    # search first 16 bytes of IL (enough to be unique-ish)
    probe = il[:16]
    k = 0
    while True:
        j = data.find(probe, k)
        if j < 0: break
        hits.append(j); k = j + 1
    full = data.find(il)
    print('%08X il=%dB  first16 hits=%s fullbody=%s' % (tok, ilsz,
          ['0x%06X' % h for h in hits[:3]] if hits else 'NONE', '0x%06X' % full if full >= 0 else 'NONE'))

# 3) class-3 real-in-place sanity: 060059C4, 06004192, 060041A5
mdt = pe.net.mdtables
for want in (0x060059C4, 0x06004192, 0x060041A5, 0x0600428A):
    rid = want & 0xFFFFFF
    row = mdt.MethodDef.rows[rid - 1]
    rva = row.Rva
    if rva:
        off = rva2off(rva)
        print('%08X %-24s rva=0x%06X fileoff=0x%06X hdr=%02X' % (want, str(row.Name), rva, off, data[off]))
    else:
        print('%08X %-24s rva=0' % (want, str(row.Name)))
