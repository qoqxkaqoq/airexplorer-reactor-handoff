# -*- coding: utf-8 -*-
"""step18: 060041CE/CF/EB bodies + ctor sig + ComputeHash call sites in 06004192."""
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

print('== 0a0009a5 (RSA ctor) ==')
print('  ', mref_full(0x0a0009a5))

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}

def body(tok):
    k = 'm_' + tok + '.bin'
    return z.read(names[k]) if k in names else None

for tok in ('060041ce', '060041cf', '060041eb', '060041d0'):
    b = body(tok)
    print('== %s ==' % tok)
    if b:
        ilsize = struct.unpack_from('<I', b, 4)[0]
        print('  ilsize=%d' % ilsize)
        for ins in disasm(b[24:24+ilsize]):
            print('  ' + fmt(ins))
    else:
        print('  NOT IN DUMP')

# ComputeHash / HashAlgorithm calls in 06004192
b = body('06004192')
ilsize = struct.unpack_from('<I', b, 4)[0]
il = b[24:24+ilsize]
print('== 06004192: calls to crypto-ish MemberRefs ==')
for ins in disasm(il):
    if ins[1] in ('call', 'callvirt') and len(ins[2]) == 4:
        t = struct.unpack('<I', ins[2])[0]
        if t & 0x0A000000:
            try:
                nm = str(md.MemberRef.rows[(t & 0xFFFFFF) - 1].Name)
                cl = md.MemberRef.rows[(t & 0xFFFFFF) - 1].Class
                try:
                    cn = str(cl.row.TypeName)
                except Exception:
                    cn = '?'
            except Exception:
                continue
            if any(k in nm for k in ('ComputeHash', 'Transform', 'get_Hash', 'Create', 'Verify', 'Import')):
                print('  %04X %s::%s' % (ins[0], cn, nm))
