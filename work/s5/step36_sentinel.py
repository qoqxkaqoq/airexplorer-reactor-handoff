# -*- coding: utf-8 -*-
"""step36b: sentinel anatomy, fixed fat-header parse (IL starts off+12, confirmed by step10 asserts)."""
import struct, dnfile
import cildasm

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
data = open(BASE, 'rb').read()
pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables

def name_of(tok):
    tbl, rid = tok >> 24, tok & 0xFFFFFF
    try:
        if tbl == 0x06: return 'm:' + str(mdt.MethodDef.rows[rid-1].Name)
        if tbl == 0x0A: return 'mr:' + str(mdt.MemberRef.rows[rid-1].Name)
        if tbl == 0x04: return 'f:' + str(mdt.Field.rows[rid-1].Name)
        if tbl == 0x01: return 'tr:' + str(mdt.TypeRef.rows[rid-1].TypeName)
        if tbl == 0x02: return 'td:' + str(mdt.TypeDef.rows[rid-1].TypeName)
        if tbl == 0x0B: return 'st:' + 'StandAloneSig'
    except Exception:
        return 'tbl%02X:%X(?)' % (tbl, rid)
    return 'tok%08X' % tok

row = mdt.MethodDef.rows[0x4192-1]
off = pe.get_offset_from_rva(row.Rva)
print('hdr16:', data[off:off+16].hex())
hs = (data[off+1] >> 4) * 4
ilsz = struct.unpack_from('<I', data, off+4)[0]
ilstart = off + hs
print('fat hs=%d ilSize=0x%X ilstart=0x%X (assert 0x3F91DC)' % (hs, ilsz, ilstart))
il = data[ilstart:ilstart+ilsz]
ins = cildasm.disasm(il)
print('decoded %d instructions' % len(ins))

# strings + calls summary
for o, nm, opb, nxt, tg in ins:
    if nm == 'ldstr':
        t = struct.unpack('<I', bytes(opb))[0]
        print('ldstr %04X %08X' % (o, t))

# context around patch sites
for site in (0x4E1, 0x995, 0x2289):
    print('=== context @+%X:' % site)
    for o, nm, opb, nxt, tg in ins:
        if site - 14 <= o <= site + 18:
            print('   %04X %-12s %s' % (o, nm, opb.hex()))
