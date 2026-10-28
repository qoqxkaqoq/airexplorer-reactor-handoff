# -*- coding: utf-8 -*-
"""step46: resolve MethodSpec 0x2B000170 target; list declaring type of 06004264;
disasm 060042AF (res[2] reader) and MethodSpec target method."""
import struct, sys, zipfile, dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
import cildasm

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables
data = open(BASE, 'rb').read()

# --- MethodSpec 0x170 ---
ms = mdt.MethodSpec.rows[0x170-1]
mcoded = ms.Method
print('MethodSpec.Method row_type=%s row_index=%s' % (mcoded.table.name if hasattr(mcoded, 'table') else '?', mcoded.row_index))
mrow = mcoded.row
print('  target:', mrow.Name if hasattr(mrow, 'Name') else mrow)

# coded index: 2 bits tag
if hasattr(mcoded, 'table'):
    tbl = mcoded.table
    rid = mcoded.row_index
    if tbl.name == 'MethodDef':
        tgt = '0600%04X' % rid
    else:
        tgt = 'MemberRef rid %X' % rid
else:
    val = ms.Method.value if hasattr(ms.Method, 'value') else int(ms.Method)
    tgt = 'coded=0x%X tag=%d rid=0x%X' % (val, val & 3, val >> 2)
    if val & 3 == 0:
        tgt += ' -> 0600%04X' % (val >> 2)
print('  resolved:', tgt)
blob = ms.Instantiation
print('  instantiation blob:', blob.hex() if isinstance(blob, (bytes, bytearray)) else blob)

# --- declaring type of 06004264 ---
owner = None
for i, td in enumerate(mdt.TypeDef.rows):
    ml = td.MethodList
    rids = [ (m.row_index if hasattr(m, 'row_index') else 0) for m in ml ] if isinstance(ml, list) else []
    if rids and 0x4264 in rids:
        start, end = min(rids), max(rids)
        owner = (i+1, td.TypeName, td.TypeNamespace, start, end)
        break
assert owner, 'owner not found'
print('owner of 06004264: TypeDef rid 0x%04X %s.%s methods %d..%d' % owner)

rid0, tname, tns, mstart, mend = owner
print('  methods:')
for r in range(mstart, mend+1):
    m = mdt.MethodDef.rows[r-1]
    print('   0600%04X %-40s RVA=0x%X impl=%s' % (r, m.Name, m.Rva, m.ImplFlags))

# fields of owner type: simple scan around 0x1FE1
fstart = fend = None
for i, td in enumerate(mdt.TypeDef.rows):
    fl = td.FieldList
    rids = [ (f.row_index if hasattr(f, 'row_index') else 0) for f in fl ] if isinstance(fl, list) else []
    if rids and 0x1FE1 in rids:
        fstart, fend = min(rids), max(rids)
        break
print('  fields 0x%04X..0x%04X:' % (fstart or 0, fend or 0))
for r in range(fstart, fend+1):
    f = mdt.Field.rows[r-1]
    sig = f.Signature.hex() if isinstance(f.Signature, (bytes, bytearray)) else f.Signature
    print('   0400%04X %-40s sig=%s' % (r, f.Name, sig))
