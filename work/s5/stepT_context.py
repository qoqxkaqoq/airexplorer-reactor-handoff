# -*- coding: utf-8 -*-
"""stepT: resolve 0x0A0062; GAE stfld@0x2c1 context; GAE factory block 0x5f0..0x700;
DefineSetSet blocks around castclass;throw@0x3538 and ldfld;throw@0x5e12 (prev-prev + what follows)."""
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

pe = __import__('dnfile').dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

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
        return 'Field %08x' % tok
    return '%08x' % tok

print('0x0A0062 =', mref(0x0A0062))
print()

def show(tok, lo, hi, label):
    il = z.read('m_%s.bin' % tok)[24:]
    ins = disasm(il)
    print('=== %s (%s) %s ===' % (tok, names.get(tok, '?'), label))
    for i, (o, name, opb, no, tg) in enumerate(ins):
        if lo <= o <= hi:
            ann = ''
            if name in ('call', 'callvirt', 'newobj', 'ldstr', 'ldfld', 'ldsfld', 'stfld', 'stsfld', 'castclass', 'isinst', 'box', 'unbox.any', 'ldtoken') and opb:
                t = struct.unpack('<I', opb)[0]
                try: ann = ' ; ' + mref(t)
                except Exception: ann = ' ; %08x' % t
            print('  IL_%04x: %-14s %-12s%s' % (o, name, opb.hex() if opb else '', ann))

# GAE stfld context (the record site) — generous window
show('06004523', 0x2a0, 0x2d0, 'stfld 0400204A record site')
print()
# GAE factory block + after throw block
show('06004523', 0x440, 0x470, 'throw block 0x46d + who enters')
print()
# DefineSetSet around castclass;throw
show('06004528', 0x3510, 0x3550, 'castclass;throw context')
print()
show('06004528', 0x5df0, 0x5e40, 'ldfld;throw context + following block')
