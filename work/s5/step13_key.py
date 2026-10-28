# -*- coding: utf-8 -*-
"""step13: 060041CD body (key import wrapper), 04001fcd referencers, 06004192 0x4DC context,
identity of file offset 0x3F91DC."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

# which method owns file offset 0x3F91DC?
target_rva_candidates = []
for r in md.MethodDef.rows:
    if r.Rva and abs(r.Rva - 0x2000 - 0x3F91DC) < 0x8000:
        target_rva_candidates.append((r.Rva, str(r.Name)))
print('== methods near file 0x3F91DC (rva ~0x3FB1DC) ==')
for rva, nm in sorted(target_rva_candidates)[:8]:
    print('  rva=0x%x %s' % (rva, nm))

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}

def body(tok):
    k = 'm_' + tok + '.bin'
    return z.read(names[k]) if k in names else None

print('== 060041CD dump body ==')
b = body('060041cd')
if b:
    ilsize = struct.unpack_from('<I', b, 4)[0]
    print('  ilsize=%d' % ilsize)
    for ins in disasm(b[24:24+ilsize]):
        print('  ' + fmt(ins))

print('== all references to Field 04001fcd in dump ==')
FPAT = bytes.fromhex('cd1f0004')
for k, n in names.items():
    if not k.startswith('m_'):
        continue
    b = z.read(n)
    il = b[24:]
    if FPAT not in il:
        continue
    pos = 0
    while True:
        j = il.find(FPAT, pos)
        if j < 0: break
        pos = j + 1
        if j >= 1 and il[j-1] in (0x7E, 0x80, 0x7B, 0x7D, 0x58):
            print('  %s @IL_%04X (%s)' % (k[2:-4].upper(), j, {0x7E:'ldsfld',0x80:'stsfld',0x7B:'ldfld',0x7D:'stfld'}.get(il[j-1], 'op')))

print('== 06004192 around 0x4DC (verify call context) ==')
b = body('06004192')
ilsize = struct.unpack_from('<I', b, 4)[0]
il = b[24:24+ilsize]
for ins in disasm(il):
    if 0x4A0 <= ins[0] <= 0x520:
        print('  ' + fmt(ins))
