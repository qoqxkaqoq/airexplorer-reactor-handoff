# -*- coding: utf-8 -*-
"""step50: scan 06004523 GenerateAdaptableExtractor for the tamper-judgment pattern
(SHA1/comparison + ceq/brtrue merge) and map all System.Exception throw sites."""
import struct, sys, zipfile, dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
import cildasm

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables
z = zipfile.ZipFile(DUMP)

def get_il(tokstr):
    try:
        d = z.read('m_%s.bin' % tokstr)
        ilsz = struct.unpack('<I', d[4:8])[0]
        return d[24:24+ilsz], 'dump'
    except KeyError:
        rid = int(tokstr[4:], 16)
        row = mdt.MethodDef.rows[rid-1]
        o = pe.get_offset_from_rva(row.Rva)
        b0 = o and None  # placeholder
        data = pe.__data__
        b0 = data[o]
        if b0 & 3 == 2:
            return bytes(data[o+1:o+1+(b0 >> 2)]), 'DISK'
        hs = (data[o+1] >> 4) * 4
        ilsz = struct.unpack_from('<I', data, o+4)[0]
        return bytes(data[o+hs:o+hs+ilsz]), 'DISK'

il, src = get_il('06004523')
ins = cildasm.disasm(il)
print('06004523 [%s] il=0x%X ins=%d' % (src, len(il), len(ins)))
# find FE01 (ceq) / FE04 (clt) / ldcstr US:7000087C-like exception strings, throw sites
import collections
prev_op = None
for o, nm, opb, nxt, tg in ins:
    if nm in ('ceq', 'clt', 'clt.un', 'cgt') or nm == 'throw' or (nm == 'ldstr'):
        t = struct.unpack('<I', bytes(opb))[0] if opb and len(opb) == 4 else 0
        print('%04X %-10s %s' % (o, nm, ('US:%08X' % t) if nm == 'ldstr' else ''))
# also print the SHA1-related calls
print('--- callvirt/call to known crypto/exception ---')
for o, nm, opb, nxt, tg in ins:
    if opb and len(opb) >= 4 and nm in ('call', 'callvirt', 'newobj'):
        t = struct.unpack('<I', bytes(opb[:4]))[0]
        tbl, rid = t >> 24, t & 0xFFFFFF
        try:
            if tbl == 0x0A:
                r = mdt.MemberRef.rows[rid-1]
                cls = r.Class.row
                cn = str(getattr(cls, 'TypeName', '') or getattr(cls, 'Name', ''))
                if cn in ('SHA1', 'SHA1CryptoServiceProvider', 'SHA1Managed', 'Exception', 'Assembly', 'AssemblyName', 'Marshal', 'BitConverter', 'CryptoStream', 'MemoryStream', 'SymmetricAlgorithm', 'AesCryptoServiceProvider', 'RijndaelManaged'):
                    print('%04X %-10s mr:%s::%s' % (o, nm, cn, r.Name))
            elif tbl == 0x06:
                r = mdt.MethodDef.rows[rid-1]
                if 'Exception' in str(r.Name) or 'Throw' in str(r.Name):
                    print('%04X %-10s m:0600%04X %s' % (o, nm, rid, r.Name))
        except Exception:
            pass
