# -*- coding: utf-8 -*-
"""step19: resolve wrapper MemberRefs (0a000a02/a03/09a9/09eb) + search whole
assembly for public-key-import calls (ImportParameters/FromXmlString/
ImportCspBlob/ImportEncryptedCspBlob) + find callers of 060041EE (VerifyHash shell)."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

def mref_full(tok):
    r = md.MemberRef.rows[(tok & 0xFFFFFF) - 1]
    cls = r.Class
    try:
        ns, nm = str(cls.row.TypeNamespace), str(cls.row.TypeName)
    except Exception:
        ns, nm = '?', '?'
    sb = bytes(getattr(r.Signature, 'value', b'') or b'')
    return '%s.%s::%s sig=%s' % (ns, nm, str(r.Name), sb.hex())

print('== wrapper MemberRefs ==')
for tok in (0x0a000a02, 0x0a000a03, 0x0a0009a9, 0x0a0009eb, 0x0a000a0c, 0x0a000a0b, 0x0a0009a5):
    print('  %08x %s' % (tok, mref_full(tok)))

print('== whole-assembly scan: RSA public key import calls ==')
targets = ('ImportParameters', 'FromXmlString', 'ImportCspBlob', 'ImportEncryptedCspBlob',
           'ToXmlString', 'ExportParameters', 'ExportCspBlob')
hits = 0
for i, r in enumerate(md.MemberRef.rows):
    nm = str(r.Name)
    if nm in targets:
        try:
            ns, tn = str(r.Class.row.TypeNamespace), str(r.Class.row.TypeName)
        except Exception:
            ns, tn = '?', '?'
        if 'Crypto' in ns or 'Xml' in ns or ns == '?':
            print('  MemberRef %08x %s.%s::%s' % (0x0A000000 + i + 1, ns, tn, nm))
            hits += 1
if hits == 0:
    print('  (none)')

print('== whole-assembly scan: any MemberRef to RSACryptoServiceProvider members ==')
for i, r in enumerate(md.MemberRef.rows):
    try:
        tn = str(r.Class.row.TypeName)
    except Exception:
        continue
    if tn in ('RSACryptoServiceProvider', 'CspParameters', 'RSACryptoServiceProviderExtension'):
        print('  MemberRef %08x %s.%s::%s' % (0x0A000000 + i + 1, str(r.Class.row.TypeNamespace), tn, str(r.Name)))

print('== callers of 060041EE (VerifyHash shell) via MethodDef scan ==')
# scan dumped bodies of all methods that reference 060041EE: use MethodDef IL from dumps
z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}
KEY = b'\xee\x41\x60\x00'  # little-endian token 060041EE
for n in z.namelist():
    if not n.startswith('m_06'):
        continue
    data = z.read(n)
    off = 0
    while True:
        idx = data.find(KEY, off)
        if idx < 0:
            break
        # likely call operand: preceded by 0x28/0x6F opcode
        op = data[idx-1]
        print('  %s @+%d opcode=0x%02x %s' % (n, idx, op, 'call' if op == 0x28 else ('callvirt' if op == 0x6F else '??')))
        off = idx + 1

print('== 060041ee body (VerifyHash shell) re-dump ==')
k = 'm_060041ee.bin'
if k in names:
    b = z.read(names[k])
    ilsize = struct.unpack_from('<I', b, 4)[0]
    for ins in disasm(b[24:24+ilsize]):
        print('  ' + fmt(ins))
