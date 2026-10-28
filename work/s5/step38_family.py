# -*- coding: utf-8 -*-
"""step38: enumerate NRS engine family 06004190-060042A0: rva/ilSize/dump presence.
Find the payload driver(s) with in-place bodies (readable now)."""
import struct, zipfile, dnfile

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
data = open(BASE, 'rb').read()
pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables
z = zipfile.ZipFile(DUMP)
names = set(z.namelist())

print('%-10s %-34s %-9s %8s %8s %s' % ('token', 'name', 'rva', 'ilSize', 'dumpIL', 'owner'))
owner_cache = {}
for i in range(0x4190, 0x42A1):
    row = mdt.MethodDef.rows[i-1]
    rva = row.Rva
    dmp = 'm_%08X.bin' % (0x06000000 + i)
    dill = '-'
    if dmp in names:
        d = z.read(dmp)
        dill = struct.unpack('<I', d[4:8])[0]
    if rva:
        off = pe.get_offset_from_rva(rva)
        hs = (data[off+1] >> 4) * 4 if (data[off] & 3) != 2 else 1
        ilsz = struct.unpack_from('<I', data, off+4)[0] if hs > 1 else data[off] >> 2
        print('0600%04X %-34s 0x%06X  %8d %8s %s' % (i, row.Name, rva, ilsz, dill, 'INPLACE'))
    else:
        print('0600%04X %-34s %-9s %8s %8s %s' % (i, row.Name, '0', '-', dill, 'payload'))
