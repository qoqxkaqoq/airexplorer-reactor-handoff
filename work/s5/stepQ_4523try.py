# -*- coding: utf-8 -*-
"""stepQ: full disasm of 06004523 try region 0x100..0x2d0 + catch block 0x1db + newobj@0x24c context.
Resolve MemberRef 0x0A0062 etc via dnfile."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm

Z = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(Z)
il = z.read('m_06004523.bin')[24:]
ins = disasm(il)

names = {}
for line in open('/workspace/repo_git/work/c2_pack/bodies_manifest.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 3 and p[1].startswith('0600'):
        names[p[1]] = p[2]

import dnfile
pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
mr = pe.net.mdtables.MemberRef
td = pe.net.mdtables.TypeDef
ts = pe.net.mdtables.TypeRef

def mref(tok):
    if tok >> 24 == 0x0A:
        row = mr.rows[(tok & 0xFFFFFF) - 1]
        cls = row.Class.row
        cn = row.Name.value
        tn = cls.TypeName.value if hasattr(cls, 'TypeName') else '?'
        ns = cls.TypeNamespace.value if hasattr(cls, 'TypeNamespace') else ''
        return '%s.%s::%s' % (ns, tn, cn)
    if tok >> 24 == 0x06:
        return 'MethodDef 0600%x %s' % (tok & 0xFFFFFF, names.get('0600%x' % (tok & 0xFFFFFF), '?'))
    return 'tok %08x' % tok

for o, name, opb, no, tg in ins:
    if 0x040 <= o <= 0x2d0:
        ann = ''
        if name in ('call', 'callvirt', 'newobj', 'ldstr', 'ldfld', 'ldsfld', 'stfld', 'stsfld', 'castclass', 'isinst', 'box') and opb:
            t = struct.unpack('<I', opb)[0]
            try:
                ann = ' ; ' + (mref(t) if t >> 24 in (0x0A, 0x06) else '%08x' % t)
            except Exception as e:
                ann = ' ; %08x (err)' % t
        print('IL_%04x: %-14s %-12s%s' % (o, name, opb.hex() if opb else '', ann))
