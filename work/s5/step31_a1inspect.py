# -*- coding: utf-8 -*-
"""step31: audit in-place state of a1patch target methods in baseline_verified.
a1patch five targets: P1 06002133(+0x290 0x16->0x17) P2 06002145(+0x120 0x16->0x17)
P3 0600212A body->{17 2A} P4 06002157 body->{17 2A} P5 06002127 body->{17 2A}
Plus 06000CEE (AssertValidLicense d__8::MoveNext, ref rva=0x3D3404) and 060059C4 (deprecated).
Classify each in-place body: real (== dump IL) / stub / other. rva=0 => payload-only.
"""
import struct, zipfile, io, dnfile

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
TOKENS = [0x06002127, 0x0600212A, 0x06002133, 0x06002145, 0x06002157, 0x06000CEE, 0x060059C4]

z = zipfile.ZipFile(DUMP)
dump_il = {}
for t in TOKENS:
    n = 'm_%08X.bin' % t
    if n in z.namelist():
        d = z.read(n)
        tok, ilsize = struct.unpack('<II', d[:8])
        dump_il[t] = (ilsize, d[24:24 + ilsize])
    else:
        dump_il[t] = None

pe = dnfile.dnPE(BASE)
data = open(BASE, 'rb').read()
# rva -> file offset via pe.get_offset_from_rva
mdt = pe.net.mdtables

def body_at(rva):
    off = pe.get_offset_from_rva(rva)
    b0 = data[off]
    if (b0 & 3) == 2:  # tiny
        ilsize = b0 >> 2
        return ('tiny', ilsize, 1, data[off+1:off+1+ilsize], 0)
    else:  # fat
        hs = (b0 >> 4) * 4
        ilsize = struct.unpack('<I', data[off+4:off+8])[0]
        maxstack = struct.unpack('<H', data[off+2:off+4])[0]
        eh = struct.unpack('<I', data[off+8:off+12])[0] & 0x0FFFFFFF
        locals_tok = struct.unpack('<I', data[off+8:off+12])[0] if False else struct.unpack('<I', data[off+8+4:off+12+4])[0]
        # fat header: 4B flags/size, 2B maxstack, 4B codesize, 4B localvarsig, 4B ehtable+flags -> standard layout:
        # [0..3]=flags+size [4..5]=maxstack [6..9]=codesize [10..13]=localvarsig [14..17]=ehtable+flags
        ilsize = struct.unpack('<I', data[off+6:off+10])[0]
        locals_tok = struct.unpack('<I', data[off+10:off+14])[0]
        ehflags = struct.unpack('<I', data[off+14:off+18])[0]
        eh = ehflags & 0x0FFFFFFF
        return ('fat', ilsize, hs, data[off+hs:off+hs+ilsize], eh)

for i, row in enumerate(mdt.MethodDef.rows):
    tok = 0x06000000 + i + 1
    if tok not in TOKENS:
        continue
    name = str(row.Name)
    rva = row.Rva
    d = dump_il.get(tok)
    print('== %08X %s rva=0x%X' % (tok, name, rva))
    if rva == 0:
        print('   rva=0 (payload-only) dump=%s' % ('%dB' % d[0] if d else 'MISSING'))
        continue
    kind, ilsize, hs, il, eh = body_at(rva)
    print('   in-place: %s ilSize=%d eh=%d' % (kind, ilsize, eh))
    print('   IL[0:48]: %s' % il[:48].hex())
    if d:
        dsz, dil = d
        same = (il == dil)
        print('   dump: %dB  match_inplace=%s' % (dsz, same))
        if not same:
            print('   dump IL[0:48]: %s' % dil[:48].hex())
    else:
        print('   dump: MISSING')
