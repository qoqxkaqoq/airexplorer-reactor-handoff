# -*- coding: utf-8 -*-
"""stepU: resolve 0x0A000A62 + disasm GAE 0x24c..0x2be (between newobj@0x24c and record@0x2be)."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm

Z = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(Z)
il = z.read('m_06004523.bin')[24:]

pe = __import__('dnfile').dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables
row = md.MemberRef.rows[0xA62-1]
cls = row.Class.row
tn = cls.TypeName.value if hasattr(cls, 'TypeName') else '?'
ns = cls.TypeNamespace.value if hasattr(cls, 'TypeNamespace') else ''
print('0x0A000A62 = %s.%s::%s' % (ns, tn, row.Name.value))

names = {}
for line in open('/workspace/repo_git/work/c2_pack/bodies_manifest.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 3 and p[1].startswith('0600'):
        names[p[1]] = p[2]

def mref(tok):
    t24 = tok & 0xFFFFFF
    if tok >> 24 == 0x0A:
        r = md.MemberRef.rows[t24-1]
        c = r.Class.row
        return '%s.%s::%s' % (c.TypeNamespace.value if hasattr(c,'TypeNamespace') else '?',
                              c.TypeName.value if hasattr(c,'TypeName') else '?', r.Name.value)
    if tok >> 24 == 0x06:
        return 'MD 0600%x(%s)' % (t24, names.get('0600%x' % t24, '?'))
    if tok >> 24 == 0x04:
        return 'Field %08x' % tok
    if tok >> 24 == 0x72:
        return 'US %08x' % tok
    return '%08x' % tok

ins = disasm(il)
for o, name, opb, no, tg in ins:
    if 0x24c <= o <= 0x2be:
        ann = ''
        if name in ('call', 'callvirt', 'newobj', 'ldstr', 'ldfld', 'ldsfld', 'stfld', 'stsfld', 'castclass', 'isinst', 'box', 'unbox.any') and opb:
            t = struct.unpack('<I', opb)[0]
            try: ann = ' ; ' + mref(t)
            except Exception: ann = ' ; %08x' % t
        print('IL_%04x: %-14s %-12s%s' % (o, name, opb.hex() if opb else '', ann))
