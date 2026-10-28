# -*- coding: utf-8 -*-
"""step12: resolve MemberRefs/Field of RSA chain; find all callers of 060041EE;
find ImportParameters/FromXmlString/key-bytes in 06004192."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

def type_name(t):
    try:
        ns, nm = str(t.TypeNamespace), str(t.TypeName)
        return ('%s.%s' % (ns, nm)) if ns else nm
    except Exception:
        return '?'

def memberref(tok):
    r = md.MemberRef.rows[(tok & 0xFFFFFF) - 1]
    cls = r.Class
    tn = type_name(cls.row) if cls and cls.row else '?'
    try:
        sig = r.Signature.hex()
    except Exception:
        sig = '?'
    return '%s::%s sig=%s' % (tn, str(r.Name), sig[:80])

print('== MemberRefs ==')
for tok in (0x0a000a0c, 0x0a0009a5):
    print('  %08x %s' % (tok, memberref(tok)))
print('== Field 04001fcd ==')
print('  %s' % str(md.Field.rows[0x1FCD - 1].Name))

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}
PAT = bytes.fromhex('ee410006')  # token LE for call/callvirt/newobj ldftn

print('== callers of 060041EE across dump ==')
for k, n in names.items():
    if not k.startswith('m_'):
        continue
    b = z.read(n)
    il = b[24:]
    if PAT not in il:
        continue
    tok = k[2:-4].upper()
    pos = 0
    while True:
        j = il.find(PAT, pos)
        if j < 0: break
        pos = j + 1
        if j >= 1 and il[j-1] in (0x28, 0x6F, 0x73, 0x2B) or (j >= 2 and il[j-2] == 0xFE):
            ctx = il[max(0, j-6):j+5].hex()
            print('  %s @IL_%04X ctx=%s' % (tok, j, ctx))

print('== 06004192: key import sites ==')
b = z.read(names['m_06004192.bin'])
ilsize = struct.unpack_from('<I', b, 4)[0]
il = b[24:24+ilsize]
for ins in disasm(il):
    if ins[1] in ('call', 'callvirt', 'newobj'):
        t = struct.unpack('<I', ins[2], )[0] if len(ins[2]) == 4 else 0
        if 0x0A000000 & t:
            try:
                nm = str(md.MemberRef.rows[(t & 0xFFFFFF) - 1].Name)
            except Exception:
                nm = '?'
            if any(k in nm for k in ('Import', 'FromXml', 'Export', 'Verify', 'Sign', 'Hash', 'Create', 'Compute')):
                print('  %04X %s -> %s' % (ins[0], ins[1], memberref(t)))
