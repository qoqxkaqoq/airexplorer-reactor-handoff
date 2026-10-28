# -*- coding: utf-8 -*-
"""step44: disasm 06004195 (SearchStrategy, res[5] decrypt candidate) fully +
0600419C window around 0x42D4 (res[0] reader) with call annotation."""
import struct, sys, zipfile, dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
import cildasm

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables

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

def dump_tok(tokstr, lo=None, hi=None):
    d = z.read('m_%s.bin' % tokstr)
    ilsz = struct.unpack('<I', d[4:8])[0]
    ehc = struct.unpack('<I', d[12:16])[0]
    il = d[24:24+ilsz]
    ins = cildasm.disasm(il)
    print('===== %s ilSize=0x%X eh=%d ins=%d =====' % (tokstr, ilsz, ehc, len(ins)))
    for o, nm, opb, nxt, tg in ins:
        if lo is not None and (o < lo or o > hi): continue
        ann = ''
        if opb and len(opb) >= 4 and nm in ('ldstr','call','callvirt','ldsfld','stsfld','ldfld','newobj','ldtoken','box','unbox.any','castclass','isinst'):
            t = struct.unpack('<I', bytes(opb[:4]))[0]
            ann = ('US:%08X' % t) if nm == 'ldstr' else mname(t)
        print('%04X %-12s %-10s %s' % (o, nm, opb.hex() if opb else '', ann))
    print()

dump_tok('06004195')
dump_tok('0600419C', 0x4200, 0x4420)
