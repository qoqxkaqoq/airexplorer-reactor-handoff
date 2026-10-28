# -*- coding: utf-8 -*-
"""step29: how does the bootstrap read the payload? Scan <Module>.cctor(06000002) +
DefineEfficientProfiler(0600419C) IL for resource/memory/file MemberRefs."""
import struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt
import zipfile

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables
mref_names = {}
for i, r in enumerate(md.MemberRef.rows):
    try:
        ns, tn = str(r.Class.row.TypeNamespace), str(r.Class.row.TypeName)
    except Exception:
        ns, tn = '?', '?'
    mref_names[0x0A000000 + i + 1] = '%s.%s::%s' % (ns, tn, str(r.Name))
def_names = {}
for i, r in enumerate(md.MethodDef.rows):
    def_names[0x06000000 + i + 1] = str(r.Name)

zb = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
nb = {n.lower(): n for n in zb.namelist()}

KEYS = ('ManifestResourceStream', 'GetHInstance', 'GetModuleHandle', 'FileStream', 'MemoryStream',
        'UnmanagedMemory', 'get_Location', 'GetExecutingAssembly', 'ResourceReader', 'GetManifestResource',
        'ReadByte', 'ReadBytes', 'ReadInt32', 'set_Position', 'get_BaseStream', 'WriteInt32', 'ReadProcessMemory',
        'VirtualProtect', 'get_Module', 'Assembly', 'Load')

for tok in ('06000002', '0600419c'):
    k = 'm_%s.bin' % tok
    print('==', tok, '==')
    if tok == '06000002':
        # disk body (not in dump)
        r = md.MethodDef.rows[1]
        off = pe.get_offset_from_rva(r.Rva)
        data = pe.__data__
        hs = (struct.unpack_from('<H', data, off)[0] >> 12) * 4
        size = struct.unpack_from('<I', data, off+4)[0]
        code = bytes(data[off+hs:off+hs+size])
        print('  (disk body %dB)' % size)
    else:
        b = zb.read(nb[k])
        size = struct.unpack_from('<I', b, 4)[0]
        code = b[24:24+size]
    seen = {}
    i = 0
    while i < len(code) - 5:
        op = code[i]
        if op in (0x28, 0x6F, 0x73, 0x7E, 0x80, 0x7B, 0x7D):
            t = struct.unpack_from('<I', code, i+1)[0]
            nm = mref_names.get(t) or ('MD::' + def_names.get(t, '%08x' % t) if (t >> 24) == 6 else None)
            if nm and any(kk in nm for kk in KEYS):
                seen.setdefault(nm, []).append(i)
        i += 1
    for nm, offs in sorted(seen.items()):
        print('  +%s %s' % (','.join('%04x' % o for o in offs[:6]), nm))
    if tok == '06000002':
        print('  disasm:')
        for ins in disasm(code):
            print('   ', fmt(ins))
