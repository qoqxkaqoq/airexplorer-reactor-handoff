# -*- coding: utf-8 -*-
"""step47: disasm RandomDecryptor members 06004265-06004269, 060042AC, 060042AD, 060042AF."""
import struct, sys, zipfile, dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
import cildasm

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables
data = open(BASE, 'rb').read()

def mname(tok):
    tbl, rid = tok >> 24, tok & 0xFFFFFF
    try:
        if tbl == 0x06: return 'm:' + str(mdt.MethodDef.rows[rid-1].Name)
        if tbl == 0x0A:
            r = mdt.MemberRef.rows[rid-1]
            cls = r.Class.row
            cn = getattr(cls, 'TypeName', None) or getattr(cls, 'Name', '?')
            return 'mr:%s::%s' % (cn, r.Name)
        if tbl == 0x04: return 'f:' + str(mdt.Field.rows[rid-1].Name)
        if tbl == 0x01: return 'tr:' + str(mdt.TypeRef.rows[rid-1].TypeName)
        if tbl == 0x02: return 'td:' + str(mdt.TypeDef.rows[rid-1].TypeName)
    except Exception:
        return 'tok%08X(!)' % tok
    return 'tok%08X' % tok

z = zipfile.ZipFile(DUMP)

def disk_body(tokstr):
    rid = int(tokstr[4:], 16)
    row = mdt.MethodDef.rows[rid-1]
    o = pe.get_offset_from_rva(row.Rva)
    b0 = data[o]
    if b0 & 3 == 2:
        return bytes(data[o+1:o+1+(b0>>2)]), 0
    hs = (data[o+1] >> 4) * 4
    ilsz = struct.unpack_from('<I', data, o+4)[0]
    ehc = struct.unpack_from('<H', data, o+8)[0] >> 11
    return bytes(data[o+hs:o+hs+ilsz]), ehc

def dump_tok(tokstr):
    try:
        d = z.read('m_%s.bin' % tokstr)
        ilsz = struct.unpack('<I', d[4:8])[0]
        ehc = struct.unpack('<I', d[12:16])[0]
        il = d[24:24+ilsz]
        src = 'dump'
    except KeyError:
        il, ehc = disk_body(tokstr)
        src = 'DISK'
    ins = cildasm.disasm(il)
    print('===== %s [%s] il=0x%X eh=%d ins=%d =====' % (tokstr, src, len(il), ehc, len(ins)))
    for o, nm, opb, nxt, tg in ins:
        ann = ''
        if opb and len(opb) >= 4 and nm in ('ldstr','call','callvirt','ldsfld','stsfld','ldfld','newobj','ldtoken','box','unbox.any','castclass','isinst'):
            t = struct.unpack('<I', bytes(opb[:4]))[0]
            ann = ('US:%08X' % t) if nm == 'ldstr' else mname(t)
        print('%04X %-12s %-10s %s' % (o, nm, opb.hex() if opb else '', ann))
    print()

for t in ('06004265','06004266','06004267','06004268','06004269','060042AC','060042AF'):
    dump_tok(t)
