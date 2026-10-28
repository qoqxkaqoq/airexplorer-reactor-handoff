# -*- coding: utf-8 -*-
"""step37: resolve 0x407AC8 (RSA WRAP target) identity; read US strings of 06004192; VerifyDynamicStrategy body."""
import struct, dnfile
import cildasm

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
data = open(BASE, 'rb').read()
pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables

# 1) which method owns rva 0x407AC8?
target_rva = 0x407AC8
best = None
for i, row in enumerate(mdt.MethodDef.rows):
    if row.Rva and row.Rva <= target_rva:
        if best is None or row.Rva > best[1].Rva:
            best = (i + 1, row)
rid, row = best
print('rva 0x407AC8 -> rid=0x%06X %s (rva=0x%X)' % (rid, row.Name, row.Rva))
off = pe.get_offset_from_rva(row.Rva)
hs = (data[off+1] >> 4) * 4 if (data[off] & 3) != 2 else 1
ilstart = off + hs
ilsz = struct.unpack_from('<I', data, off+4)[0] if hs > 1 else data[off] >> 2
print('   body off=0x%X hs=%d ilSize=0x%X' % (off, hs, ilsz))
il = data[ilstart:ilstart+ilsz]
print('   IL head 64B: %s' % il[:64].hex())

# owner type of rid
import bisect
starts = []
for ti, t in enumerate(mdt.TypeDef.rows):
    s = t.MethodList.row_index
    starts.append((s, ti))
starts.sort()
idx = bisect.bisect_right([s for s, _ in starts], rid - 1) - 1
td = mdt.TypeDef.rows[starts[idx][1]]
print('   owner type: %s' % td.TypeName)

# disasm head of that method
ins = cildasm.disasm(il[:min(len(il), 400)])
for o, nm, opb, nxt, tg in ins[:40]:
    s = '%04X %-12s' % (o, nm)
    if opb:
        if len(opb) == 4: s += ' 0x%08X' % struct.unpack('<I', bytes(opb))[0]
        else: s += ' ' + bytes(opb).hex()
    if tg: s += ' -> %04X' % tg[0]
    print('   ' + s)

# 2) US strings used by 06004192
us = pe.net.user_strings
for tok in (0x70000A26, 0x70000A42, 0x70000A4C):
    try:
        s = us.get(tok)
        v = s.value if s is not None else None
        print('US %08X = %r' % (tok, v))
    except Exception as e:
        print('US %08X err %s' % (tok, e))

# 3) VerifyDynamicStrategy 060041EE quick body
r2 = mdt.MethodDef.rows[0x41EE-1]
print('== 060041EE %s rva=0x%X' % (r2.Name, r2.Rva))
if r2.Rva:
    o2 = pe.get_offset_from_rva(r2.Rva)
    hs2 = (data[o2+1] >> 4) * 4 if (data[o2] & 3) != 2 else 1
    ils2 = struct.unpack_from('<I', data, o2+4)[0] if hs2 > 1 else data[o2] >> 2
    il2 = data[o2+hs2:o2+hs2+ils2]
    print('   ilSize=0x%X IL: %s' % (ils2, il2[:96].hex()))
    for o, nm, opb, nxt, tg in cildasm.disasm(il2)[:30]:
        s = '   %04X %-12s' % (o, nm)
        if opb:
            if len(opb) == 4: s += ' 0x%08X' % struct.unpack('<I', bytes(opb))[0]
            else: s += ' ' + bytes(opb).hex()
        print(s)
else:
    print('   rva=0 (payload)')
