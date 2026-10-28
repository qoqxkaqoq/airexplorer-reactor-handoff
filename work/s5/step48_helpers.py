# -*- coding: utf-8 -*-
"""step48: disasm runtime helper family 06004218..06004231 (disk in-situ)."""
import struct, sys, dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
import cildasm

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables
data = open(BASE, 'rb').read()

def mname(tok):
    tbl, rid = tok >> 24, tok & 0xFFFFFF
    try:
        if tbl == 0x06: return 'm06:0600%04X' % rid
        if tbl == 0x0A:
            r = mdt.MemberRef.rows[rid-1]
            cls = r.Class.row
            return 'mr:%s::%s' % (getattr(cls, 'TypeName', '?'), r.Name)
        if tbl == 0x04: return 'f:0400%04X' % rid
        if tbl == 0x01: return 'tr:' + str(mdt.TypeRef.rows[rid-1].TypeName)
        if tbl == 0x02: return 'td:' + str(mdt.TypeDef.rows[rid-1].TypeName)
    except Exception:
        return 'tok%08X' % tok
    return 'tok%08X' % tok

for rid in range(0x4218, 0x4232):
    row = mdt.MethodDef.rows[rid-1]
    tokstr = '0600%04X' % rid
    if row.Rva == 0:
        print('===== %s %s RVA=0 =====' % (tokstr, row.Name)); continue
    o = pe.get_offset_from_rva(row.Rva)
    b0 = data[o]
    if b0 & 3 == 2:
        il = bytes(data[o+1:o+1+(b0 >> 2)]); ehc = 0; hs = 1
    else:
        hs = (data[o+1] >> 4) * 4
        ilsz = struct.unpack_from('<I', data, o+4)[0]
        ehc = struct.unpack_from('<H', data, o+8)[0] >> 11
        il = bytes(data[o+hs:o+hs+ilsz])
    ins = cildasm.disasm(il)
    print('===== %s %s il=0x%X eh=%d =====' % (tokstr, row.Name, len(il), ehc))
    for o2, nm, opb, nxt, tg in ins:
        ann = ''
        if opb and len(opb) >= 4 and nm in ('ldstr','call','callvirt','ldsfld','stsfld','ldfld','newobj','ldtoken','box','unbox.any','castclass','isinst','newarr'):
            t = struct.unpack('<I', bytes(opb[:4]))[0]
            ann = ('US:%08X' % t) if nm == 'ldstr' else mname(t)
        print('%04X %-12s %-10s %s' % (o2, nm, opb.hex() if opb else '', ann))
    print()
