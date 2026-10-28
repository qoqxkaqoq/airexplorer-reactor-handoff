# -*- coding: utf-8 -*-
"""step28: <Module> global type methods disk-vs-dump + StopClient(0600419f) flags +
MethodImpl/semantics audit for RVA=0 methods called via `call`."""
import struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt
import zipfile

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

def read_disk_body(tok):
    r = md.MethodDef.rows[(tok & 0xFFFFFF) - 1]
    if r.Rva == 0:
        return ('rva0', 0, b'', 0)
    off = pe.get_offset_from_rva(r.Rva)
    data = pe.__data__
    b0 = data[off]
    if (b0 & 3) == 2:
        return ('tiny', b0 >> 2, bytes(data[off+1:off+1+(b0 >> 2)]), 0)
    hs = (struct.unpack_from('<H', data, off)[0] >> 12) * 4
    size = struct.unpack_from('<I', data, off+4)[0]
    loctok = struct.unpack_from('<I', data, off+8)[0]
    return ('fat', size, bytes(data[off+hs:off+hs+size]), loctok)

zb = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
nb = {n.lower(): n for n in zb.namelist()}

def show(tok, label):
    r = md.MethodDef.rows[(tok & 0xFFFFFF) - 1]
    fl = r.Flags
    print('%08x %-16s name=%-28s flags=%06x abstract=%s rva=%08x' % (
        tok, label, str(r.Name), getattr(fl.mdAbstract, "corhdr_enum", 0), bool(getattr(fl.mdAbstract, 'corhdr_enum', 0)), r.Rva))
    kind, size, il, loctok = read_disk_body(tok)
    k = 'm_%08x.bin' % tok
    dstate = 'MISSING' if k not in nb else str(struct.unpack_from('<I', zb.read(nb[k]), 4)[0]) + 'B'
    print('    disk=%s/%dB  dump=%s  equal=%s' % (kind, size, dstate,
          (il == zb.read(nb[k])[24:24+struct.unpack_from('<I', zb.read(nb[k]), 4)[0]]) if k in nb and kind != 'rva0' else '-'))
    if k in nb and kind != 'rva0':
        b = zb.read(nb[k]); ds = struct.unpack_from('<I', b, 4)[0]
        if il != b[24:24+ds]:
            print('    CHANGED! disk head:', il[:24].hex(), ' dump head:', b[24:24+24].hex())
    return r

print('== <Module> global type (rid 1) methods ==')
t = md.TypeDef.rows[0]
print('typedef0 name=%r ns=%r' % (str(t.TypeName), str(t.TypeNamespace)))
try:
    for m in t.MethodList:
        row = m.row if hasattr(m, 'row') else m
        rid = m.row_index
        show(0x06000000 + rid, 'module')
except Exception as e:
    print('iter fail:', e)

print('== StopClient 0600419f + TemplateBuilder::Invoke 0600427f flags ==')
show(0x0600419f, 'StopClient')
show(0x0600427f, 'Invoke')
r = md.MethodDef.rows[0x419f - 1]
sig = bytes(r.Signature.value)
print('0600419f sig=%s' % sig.hex())
r = md.MethodDef.rows[0x427f - 1]
sig = bytes(r.Signature.value)
print('0600427f sig=%s' % sig.hex())

# MethodImpl rows referencing these
print('== MethodImpl table ==')
try:
    for mri, r in enumerate(md.MethodImpl.rows):
        cls = r.Class
        try:
            cn = str(cls.row.TypeName)
        except Exception:
            cn = '?'
        mb = r.MethodBody
        md_ = r.MethodDeclaration
        try:
            btok = mb.row_index if hasattr(mb, 'row_index') else 0
        except Exception:
            btok = 0
        print('  MI%d class=%s body=%s decl=%s' % (mri, cn, hex(btok) if btok else '?', md_))
except Exception as e:
    print('  no MethodImpl or fail:', e)
