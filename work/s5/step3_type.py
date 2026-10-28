# -*- coding: utf-8 -*-
"""step3: resolve TypeDef 0x63D + MethodDefs 4550/4559/4566/454C; switch targets of 452E;
all stloc.s 02 writes in 4528."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

def typedef_name(rid):
    r = md.TypeDef.rows[rid - 1]
    return '%s.%s' % (r.TypeNamespace, r.TypeName)

def method_info(tok):
    rid = tok & 0xFFFFFF
    r = md.MethodDef.rows[rid - 1]
    return r.Name, r.Rva

print('== TypeDef 0x0200063d (row %d) ==' % 0x63d)
print('  ', typedef_name(0x63d))

for tok in (0x0600452e, 0x06004550, 0x06004559, 0x06004566, 0x0600454c, 0x06004555, 0x0600448f):
    nm, rva = method_info(tok)
    print('  %08x rva=0x%x name=%s' % (tok, rva, nm))

# owning typedef for 4566/4550/4559
def owner(tok):
    rid = tok & 0xFFFFFF
    for ti, t in enumerate(md.TypeDef.rows):
        ml = t.MethodList
        for mi in ml:
            if mi.row_index == rid:
                return typedef_name(ti + 1)
    return '?'

for tok in (0x0600452e, 0x06004550, 0x06004559, 0x06004566, 0x0600454c):
    print('  %08x owner=%s' % (tok, owner(tok)))

# switch full targets of 452E
z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
b = z.read('m_0600452e.bin')
il = b[24:]
print('== 452E switch targets ==')
for ins in disasm(il):
    if ins[1] == 'switch':
        cnt = len(ins[3]) // 4 - 1
        base = ins[4]
        for k in range(cnt):
            print('  case %d -> %04X' % (k, base + struct.unpack_from('<i', ins[3], 4 + 4*k)[0]))

# all stloc.s 02 / stloc 02 in 4528
b28 = z.read('m_06004528.bin')
il28 = b28[24:]
print('== 4528 stloc 02 (local slot 2) write sites ==')
for ins in disasm(il28):
    if ins[1] == 'stloc.s' and ins[3] == b'\x02':
        print('  %04X stloc.s 02' % ins[0])
    elif ins[1] == 'fe.stloc' and struct.unpack_from('<H', ins[3])[0] == 0x0200:
        print('  %04X stloc 02' % ins[0])
