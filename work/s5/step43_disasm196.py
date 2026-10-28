# -*- coding: utf-8 -*-
"""step43: full disasm of 06004196 (res[5] reader) and 060042AF (res[2] reader),
with call annotation (member names) to locate GetManifestResourceStream + decrypt loop."""
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
        if tbl == 0x06:
            r = mdt.MethodDef.rows[rid-1]
            return 'm:%s.%s' % ('?', r.Name)
        if tbl == 0x0A:
            r = mdt.MemberRef.rows[rid-1]
            cls = r.Class.row
            cn = getattr(cls, 'TypeName', None) or getattr(cls, 'Name', '?')
            return 'mr:%s::%s' % (cn, r.Name)
        if tbl == 0x04: return 'f:' + str(mdt.Field.rows[rid-1].Name)
        if tbl == 0x01: return 'tr:' + str(mdt.TypeRef.rows[rid-1].TypeName)
        if tbl == 0x02: return 'td:' + str(mdt.TypeDef.rows[rid-1].TypeName)
        if tbl == 0x0B: return 'st:'
    except Exception as e:
        return 'tok%08X(!)' % tok
    return 'tok%08X' % tok

z = zipfile.ZipFile(DUMP)
for tokstr in ('06004196', '060042AF'):
    d = z.read('m_%s.bin' % tokstr)
    ilsz = struct.unpack('<I', d[4:8])[0]
    ehc = struct.unpack('<I', d[12:16])[0]
    il = d[24:24+ilsz]
    ins = cildasm.disasm(il)
    print('===== %s ilSize=0x%X eh=%d ins=%d =====' % (tokstr, ilsz, ehc, len(ins)))
    for o, nm, opb, nxt, tg in ins:
        ann = ''
        if nm in ('ldstr', 'call', 'callvirt', 'ldsfld', 'stsfld', 'ldfld', 'newobj', 'ldtoken', 'box', 'unbox.any', 'castclass', 'isinst', 'ldelem.ref', 'stelem.ref', 'br', 'brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'leave', 'leave.s'):
            if opb and len(opb) >= 4:
                t = struct.unpack('<I', bytes(opb[:4]))[0]
                if nm == 'ldstr':
                    ann = 'US:%08X' % t
                else:
                    ann = mname(t)
        print('%04X %-12s %-10s %s' % (o, nm, opb.hex() if opb else '', ann))
    print()
