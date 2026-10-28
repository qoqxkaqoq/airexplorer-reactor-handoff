# -*- coding: utf-8 -*-
"""step33: license write-point & gate anatomy on baseline.
- 0600217A (license field writer per a1patch.cs note) location/classification
- license gate real bodies read fields 04000C3D/04000C4B -> find owners
- xref: which in-place-real (class-3) methods reference license fields/types
"""
import struct, zipfile, dnfile

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
data = open(BASE, 'rb').read()
pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables

def mname(rid):
    return str(mdt.MethodDef.rows[rid - 1].Name)

def mrow(rid):
    return mdt.MethodDef.rows[rid - 1]

def bodyinfo(rid):
    row = mrow(rid)
    rva = row.Rva
    if not rva:
        return 'rva=0(payload)'
    off = pe.get_offset_from_rva(rva)
    b0 = data[off]
    if (b0 & 3) == 2:
        return 'tiny@0x%X ilSize=%d' % (rva, b0 >> 2)
    hs = (b0 >> 4) * 4
    ilsz = struct.unpack('<I', data[off+6:off+10])[0]
    return 'fat@0x%X ilSize=%d' % (rva, ilsz)

# 1) 0600217A
print('== 0600217A', mname(0x217A), bodyinfo(0x217A))

# dump body of 0600217A from dump zip (real IL)
z = zipfile.ZipFile(DUMP)
for tok in (0x0600217A, 0x0600217B):
    n = 'm_%08X.bin' % tok
    if n in z.namelist():
        d = z.read(n)
        ilsz = struct.unpack('<I', d[4:8])[0]
        print('   dump %s il=%dB: %s' % (n, ilsz, d[24:24+ilsz].hex()))
    else:
        print('   dump %s MISSING' % n)

# 2) field 04000C3D / 04000C4B owners
for ftok in (0x04000C3D, 0x04000C4B):
    rid = ftok & 0xFFFFFF
    row = mdt.Field.rows[rid - 1]
    print('== %s name=%s' % (ftok, str(row.Name)))
    # find owner type via TypeDef field list
    for ti, t in enumerate(mdt.TypeDef.rows):
        fl, ll = t.FieldList.row_index if t.FieldList.row_index is not None else 0, 0
    # simpler: scan TypeDef ranges
    nfields = len(mdt.Field.rows)
    starts = []
    for ti, t in enumerate(mdt.TypeDef.rows):
        s = t.FieldList.row_index
        starts.append((s, ti))
    starts.sort()
    import bisect
    idx = bisect.bisect_right([s for s, _ in starts], rid - 1) - 1
    if idx >= 0:
        ti = starts[idx][1]
        print('   owner type rid=%d: %s' % (ti + 1, mdt.TypeDef.rows[ti].TypeName))

# 3) dump bodies referencing field tokens 04000C3D/04000C4B (ldfld 7B / stsfld 80 / ldsfld 7E / stsfld 80)
targets = {0x04000C3D: 'fld_C3D', 0x04000C4B: 'fld_C4B'}
refs = {}
for fn in z.namelist():
    if not fn.endswith('.bin'):
        continue
    d = z.read(fn)
    if len(d) < 28: continue
    tok = struct.unpack('<I', d[:4])[0]
    ilsz = struct.unpack('<I', d[4:8])[0]
    il = d[24:24 + ilsz]
    i = 0
    while i < len(il) - 5:
        b = il[i]
        if b in (0x7B, 0x7F, 0x80, 0x7E, 0x7D):  # ldfld/ldflda/stfld/ldsfld/stsfld
            t = struct.unpack('<I', il[i+1:i+5])[0]
            if t in targets:
                refs.setdefault(tok, set()).add((b, t))
            i += 5
        else:
            i += 1
print('== dump bodies touching license fields:')
for tok in sorted(refs):
    rid = tok & 0xFFFFFF
    ops = ' '.join('%02X:%s' % (b, ft) for b, ft in refs[tok])
    print('   %08X %s  rva=%s  %s' % (tok, mname(rid), ('0x%X' % mrow(rid).Rva) if mrow(rid).Rva else '0', ops))
