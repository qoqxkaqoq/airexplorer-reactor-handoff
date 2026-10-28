# -*- coding: utf-8 -*-
"""step20: locate call sites of FromXmlString(0a000a06)/set_UseMachineKeyStore(0a000999)/
ComputeHash across all dumped method bodies; check m_06004192.bin presence & its calls."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

# full MemberRef name lookup
mref_names = {}
for i, r in enumerate(md.MemberRef.rows):
    try:
        ns, tn = str(r.Class.row.TypeNamespace), str(r.Class.row.TypeName)
    except Exception:
        ns, tn = '?', '?'
    mref_names[0x0A000000 + i + 1] = '%s.%s::%s' % (ns, tn, str(r.Name))

# MethodDef names
def_names = {}
for i, r in enumerate(md.MethodDef.rows):
    def_names[0x06000000 + i + 1] = str(r.Name)

# find ComputeHash memberrefs
print('== ComputeHash MemberRefs ==')
for tok, nm in sorted(mref_names.items()):
    if 'ComputeHash' in nm or 'MapNameToOID' in nm or 'FromXmlString' in nm or 'UseMachineKeyStore' in nm:
        print('  %08x %s' % (tok, nm))

# scan all dumped bodies for calls to interesting tokens
INTEREST = set()
for tok, nm in mref_names.items():
    if any(k in nm for k in ('ComputeHash', 'FromXmlString', 'UseMachineKeyStore', 'MapNameToOID',
                             'ReadBytes', 'get_Hash', 'VerifyHash', 'SHA1::Create')):
        INTEREST.add(tok)

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}
print('== m_06004192.bin in dump? ==', 'm_06004192.bin' in names)

print('== call sites in dumped bodies ==')
for n in z.namelist():
    if not n.startswith('m_'):
        continue
    data = z.read(n)
    i = 0
    while i < len(data) - 5:
        op = data[i]
        if op in (0x28, 0x6F, 0x73):  # call/callvirt/newobj
            tok = struct.unpack_from('<I', data, i + 1)[0]
            if tok in INTEREST or tok == 0x060041EE or tok == 0x060041ce or tok == 0x060041eb:
                print('  %s +%d op=%02x -> %08x %s' % (n, i, op, tok, mref_names.get(tok, 'MD ' + def_names.get(tok, '?'))))
        i += 1

print('== 06004192 calls (full map, MethodDef + MemberRef) ==')
k = names.get('m_06004192.bin')
if k:
    b = z.read(k)
    ilsize = struct.unpack_from('<I', b, 4)[0]
    code = b[24:24 + ilsize]
    i = 0
    while i < len(code):
        op = code[i]
        if op in (0x28, 0x6F, 0x73):
            tok = struct.unpack_from('<I', code, i + 1)[0]
            label = mref_names.get(tok) or ('MD::' + def_names.get(tok, '?%08x' % tok))
            print('  +%04x op=%02x -> %s' % (i, op, label))
        i += 1
