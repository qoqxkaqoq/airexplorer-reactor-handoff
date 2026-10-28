# -*- coding: utf-8 -*-
"""stepS: whole-dump xref of field 0x0400204A + all ldfld;throw / castclass;throw patterns
at instruction boundaries across dump; resolve TypeRef 0x20; remaining audit 06004527/4521/4524."""
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

def typename(tdrow):
    return '%s.%s' % (tdrow.TypeNamespace.value, tdrow.TypeName.value)

# resolve field 0x0400204A owner type: walk TypeDef->FieldList
TARGET_FID = 0x204A
owner = '?'
def first_fld_rid(td):
    try:
        return td.FieldList[0].row_index if len(td.FieldList) else 0
    except Exception:
        return 0
for i, td in enumerate(md.TypeDef.rows):
    fl = first_fld_rid(td)
    nxt = first_fld_rid(md.TypeDef.rows[i+1]) if i+1 < len(md.TypeDef.rows) else len(md.Field.rows)+1
    if fl and fl <= TARGET_FID < nxt:
        owner = typename(td)
        break
print('field 0x0400204A owner type:', owner)
try:
    tr = md.TypeRef.rows[0x20-1]
    print('TypeRef 0x20:', tr.TypeNamespace.value, tr.TypeName.value)
except Exception as e:
    print('TypeRef 0x20 err', e)

TARGET = struct.pack('<I', 0x0400204A)
print()
print('=== raw byte hits of field token 0x0400204A in dump bodies ===')
for n in sorted(z.namelist()):
    if not n.startswith('m_'): continue
    il = z.read(n)[24:]
    tok = n[2:-4].lower()
    pos = 0
    while True:
        j = il.find(TARGET, pos)
        if j < 0: break
        pos = j + 1
        op = il[j-1] if j >= 1 else 0
        if op in (0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80):
            namesop = {0x7B:'ldfld',0x7C:'ldflda',0x7D:'stfld',0x7E:'ldsfld',0x7F:'ldsflda',0x80:'stsfld'}[op]
            print('  %s (%s) IL@0x%x %s' % (tok, names.get(tok, '?'), j-1, namesop))

print()
print('=== all LDFLD;THROW / LDSFLD;THROW / CASTCLASS;THROW at boundaries (whole dump) ===')
for n in sorted(z.namelist()):
    if not n.startswith('m_'): continue
    tok = n[2:-4].lower()
    il = z.read(n)[24:]
    try:
        ins = disasm(il)
    except Exception:
        continue
    for i, (o, name, opb, no, tg) in enumerate(ins):
        if name == 'throw' and i >= 1:
            pv = ins[i-1]
            if pv[1] in ('ldfld', 'ldsfld') or pv[1] == 'castclass':
                t = struct.unpack('<I', pv[2])[0] if pv[2] else 0
                det = ''
                if pv[1] in ('ldfld', 'ldsfld'):
                    det = 'field %08x' % t
                else:
                    det = 'type %08x' % t
                print('  %s (%s) IL@0x%04x %s;throw %s' % (tok, names.get(tok, '?'), o, pv[1], det))

print()
print('=== remaining audit 06004527/06004521/06004524 ===')
for tok in ('06004527', '06004521', '06004524'):
    il = z.read('m_%s.bin' % tok)[24:]
    ins = disasm(il)
    print('--- %s (%s) ilsize=%d throws=%d' % (tok, names.get(tok, '?'), len(il), sum(1 for x in ins if x[1] == 'throw')))
    for i, (o, name, opb, no, tg) in enumerate(ins):
        if name == 'throw':
            pv = ins[i-1]
            print('   IL_%04x throw | prev %s %s' % (o, pv[1], pv[2].hex() if pv[2] else ''))
