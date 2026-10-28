# -*- coding: utf-8 -*-
"""step14: 060041ED/060041D3 bodies + MemberRef sigs + V_17/V_18 sources in 06004192."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

def sig_of(tok):
    r = md.MemberRef.rows[(tok & 0xFFFFFF) - 1]
    cls = r.Class
    try:
        ns, nm = str(cls.row.TypeNamespace), str(cls.row.TypeName)
    except Exception:
        ns, nm = '?', '?'
    try:
        sb = bytes(r.Signature.value)
    except Exception:
        sb = bytes(getattr(r.Signature, 'value', b'') or b'')
    return '%s.%s::%s\n    sig=%s' % (ns, nm, str(r.Name), sb.hex())

print('== MemberRef signatures ==')
for t in (0x0a0009fa, 0x0a000a0c):
    print('  %08x %s' % (t, sig_of(t)))

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}

def body(tok):
    k = 'm_' + tok + '.bin'
    return z.read(names[k]) if k in names else None

for tok in ('060041ed', '060041d3'):
    b = body(tok)
    print('== %s ==' % tok)
    if b:
        ilsize = struct.unpack_from('<I', b, 4)[0]
        print('  ilsize=%d' % ilsize)
        for ins in disasm(b[24:24+ilsize]):
            print('  ' + fmt(ins))
    else:
        print('  NOT IN DUMP')

b = body('06004192')
ilsize = struct.unpack_from('<I', b, 4)[0]
il = b[24:24+ilsize]
print('== 06004192: writes to V_17/V_18 (stloc.s 17/18) ==')
for ins in disasm(il):
    if ins[1] == 'stloc.s' and ins[2] in (0x17, 0x18):
        print('  %04X stloc.s %02x' % (ins[0], ins[2]))
