# -*- coding: utf-8 -*-
"""step11: reverse RSA verify chain - VerifyDynamicStrategy(060041EE), key construction
in 06004192 @IL_22A9, and identity of 060042F4 (92-patched method)."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

def typedef_of_method(rid):
    for ti, t in enumerate(md.TypeDef.rows):
        for mi in t.MethodList:
            if mi.row_index == rid:
                return ti + 1
    return None

for tok in (0x060041ee, 0x06004192, 0x060042f4, 0x0600419c, 0x06004193, 0x06004183):
    rid = tok & 0xFFFFFF
    r = md.MethodDef.rows[rid - 1]
    ti = typedef_of_method(rid)
    t = md.TypeDef.rows[ti - 1]
    print('%08x rva=0x%x %s.%s::%s' % (tok, r.Rva, str(t.TypeNamespace), str(t.TypeName), str(r.Name)))

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}

def body(tok):
    k = 'm_' + tok + '.bin'
    return z.read(names[k]) if k in names else None

print('== 060041EE VerifyDynamicStrategy (dump) ==')
b = body('060041ee')
if b:
    ilsize = struct.unpack_from('<I', b, 4)[0]
    for ins in disasm(b[24:24+ilsize]):
        print('  ' + fmt(ins))
else:
    print('  not in dump; use memdump')
    mem = open('/workspace/repo_git/work_a1_pack/memdump/module_text.bin', 'rb').read()
    r = md.MethodDef.rows[0x41EE - 1].Rva
    off = r - 0x2000
    b0 = mem[off]
    if b0 & 3 == 2:
        il = mem[off+1:off+1+(b0 >> 2)]
    else:
        u16 = struct.unpack_from('<H', mem, off)[0]
        hs = (u16 >> 12) * 4
        cs = struct.unpack_from('<I', mem, off+4)[0]
        il = mem[off+hs:off+hs+cs]
    for ins in disasm(il):
        print('  ' + fmt(ins))

print('== 060042F4 dump? ==')
b = body('060042f4')
print('  dump size:', len(b) if b else 'NONE')

print('== 06004192 @IL_22A9 +-0x50 (RSA key construction) ==')
b = body('06004192')
if b:
    ilsize = struct.unpack_from('<I', b, 4)[0]
    il = b[24:24+ilsize]
    print('  ilsize=%d' % ilsize)
    for ins in disasm(il):
        if 0x2270 <= ins[0] <= 0x2320:
            print('  ' + fmt(ins))
