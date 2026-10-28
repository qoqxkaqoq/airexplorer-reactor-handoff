# -*- coding: utf-8 -*-
"""step39: 0600419C DefineEfficientProfiler (37KB) role ID + 06004192 US strings."""
import struct, dnfile
import cildasm

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
data = open(BASE, 'rb').read()
pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables

def get_il(rid):
    row = mdt.MethodDef.rows[rid-1]
    off = pe.get_offset_from_rva(row.Rva)
    hs = (data[off+1] >> 4) * 4 if (data[off] & 3) != 2 else 1
    ilsz = struct.unpack_from('<I', data, off+4)[0] if hs > 1 else data[off] >> 2
    return data[off+hs:off+hs+ilsz], row, off, hs, ilsz

def tokname(tok):
    tbl, r = tok >> 24, tok & 0xFFFFFF
    try:
        if tbl == 0x06: return 'm:' + str(mdt.MethodDef.rows[r-1].Name)
        if tbl == 0x0A: return 'mr:' + str(mdt.MemberRef.rows[r-1].Name)
        if tbl == 0x04: return 'f:' + str(mdt.Field.rows[r-1].Name)
        if tbl == 0x01: return 'tr:' + str(mdt.TypeRef.rows[r-1].TypeName)
        if tbl == 0x02: return 'td:' + str(mdt.TypeDef.rows[r-1].TypeName)
    except Exception:
        return 't%02X:%X' % (tbl, r)
    return '%08X' % tok

# 1) US strings of 06004192
il92, _, _, _, _ = get_il(0x4192)
strs = []
for o, nm, opb, nxt, tg in cildasm.disasm(il92):
    if nm == 'ldstr':
        strs.append(struct.unpack('<I', bytes(opb))[0])
# raw US stream
usdata = None
for s in pe.net.metadata.streams_list:
    if s.struct.Name.rstrip(b'\x00') == b'#US':
        usdata = s.get_data_at_offset(0, s.struct.Size)
        break
def us_read(tok):
    off = tok & 0xFFFFFF
    # compressed length
    b0 = usdata[off]
    if b0 & 0x80 == 0:
        ln = b0; adv = 1
    elif b0 & 0xC0 == 0x80:
        ln = ((b0 & 0x3F) << 8) | usdata[off+1]; adv = 2
    else:
        ln = ((b0 & 0x1F) << 24) | (usdata[off+1] << 16) | (usdata[off+2] << 8) | usdata[off+3]; adv = 4
    raw = usdata[off+adv:off+adv+ln]
    return raw[:-1].decode('utf-16-le', 'replace') if ln else ''
for t in strs:
    print('ldstr %08X = %r' % (t, us_read(t)))

# 2) 0600419C anatomy: calls/refs histogram
il9c, row, off, hs, ilsz = get_il(0x419C)
print('\n0600419C %s ilSize=%d' % (row.Name, ilsz))
hist = {}
for o, nm, opb, nxt, tg in cildasm.disasm(il9c):
    if nm in ('call', 'callvirt', 'newobj', 'ldsfld', 'stsfld', 'ldfld', 'stfld'):
        t = struct.unpack('<I', bytes(opb))[0]
        hist.setdefault(tokname(t), []).append(o)
for k in sorted(hist, key=lambda k: -len(hist[k]))[:40]:
    print('  %-40s x%d  first@%04X' % (k, len(hist[k]), hist[k][0]))

# ldc.i4 constants histogram (entry header magic?)
import collections
c8 = collections.Counter()
for o, nm, opb, nxt, tg in cildasm.disasm(il9c):
    if nm == 'ldc.i4':
        c8[struct.unpack('<i', bytes(opb))[0]] += 1
print('top ldc.i4:', c8.most_common(12))
c1 = collections.Counter()
for o, nm, opb, nxt, tg in cildasm.disasm(il9c):
    if nm == 'ldc.i4.s':
        c1[bytes(opb)[0]] += 1
print('top ldc.i4.s:', c1.most_common(12))
