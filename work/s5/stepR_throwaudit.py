# -*- coding: utf-8 -*-
"""stepR: audit ALL throw sites in 06004528/06004527/06004521 + resolve 0x0A0062 + verify 0x5E0D."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm

Z = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(Z)

names = {}
for line in open('/workspace/repo_git/work/c2_pack/bodies_manifest.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 3 and p[1].startswith('0600'):
        names[p[1]] = p[2]

pe = dnfile = __import__('dnfile').dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables
print('Field rows:', len(md.Field.rows))

def mref(tok):
    t24 = tok & 0xFFFFFF
    if tok >> 24 == 0x0A:
        row = md.MemberRef.rows[t24-1]
        cls = row.Class.row
        tn = cls.TypeName.value if hasattr(cls, 'TypeName') else '?'
        ns = cls.TypeNamespace.value if hasattr(cls, 'TypeNamespace') else ''
        return '%s.%s::%s' % (ns, tn, row.Name.value)
    if tok >> 24 == 0x06:
        return 'MD 0600%x(%s)' % (t24, names.get('0600%x' % t24, '?'))
    if tok >> 24 == 0x04:
        ok = t24 <= len(md.Field.rows)
        return 'Field %08x valid=%s' % (tok, ok)
    return '%08x' % tok

for tok in ('06004528', '06004527', '06004521', '06004524'):
    il = z.read('m_%s.bin' % tok)[24:]
    ins = disasm(il)
    print()
    print('=== %s (%s) ilsize=%d throws=%d ===' % (tok, names.get(tok, '?'), len(il), sum(1 for i in ins if i[1] == 'throw')))
    for i, (o, name, opb, no, tg) in enumerate(ins):
        if name != 'throw':
            continue
        # classify by previous instruction
        prev = ins[i-1]
        pv = '%s %s' % (prev[1], prev[2].hex() if prev[2] else '')
        kind = '?'
        if prev[1] == 'newobj':
            kind = 'NEWOBJ-THROW ' + mref(struct.unpack('<I', prev[2])[0])
        elif prev[1] == 'ldfld':
            kind = 'LDFLD-THROW ' + mref(struct.unpack('<I', prev[2])[0])
        elif prev[1] == 'ldsfld':
            kind = 'LDSFLD-THROW ' + mref(struct.unpack('<I', prev[2])[0])
        elif prev[1].startswith('ldloc'):
            kind = 'LDLOC-THROW (rethrow/cached)'
        elif prev[1] == 'call' or prev[1] == 'callvirt':
            kind = 'CALL-THROW ' + mref(struct.unpack('<I', prev[2])[0])
        print('  IL_%04x: throw | prev: %s | %s' % (o, pv, kind))

# 0x5E0D boundary check in 06004528
il28 = z.read('m_06004528.bin')[24:]
offs = set(o for o, _, _, _, _ in disasm(il28))
print()
print('06004528: 0x5E0D boundary =', 0x5E0D in offs, '| bytes @0x5E0D:', il28[0x5E0D:0x5E13].hex())
# resolve 0x0A0062
print('0x0A0062 =', mref(0x0A0062))
