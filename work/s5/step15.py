# -*- coding: utf-8 -*-
"""step15: resolve 0a000a0b/0a000a93; fe.stloc 17/18 writes; sources of hash and sig."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

def mref(tok):
    r = md.MemberRef.rows[(tok & 0xFFFFFF) - 1]
    cls = r.Class
    try:
        ns, nm = str(cls.row.TypeNamespace), str(cls.row.TypeName)
    except Exception:
        ns, nm = '?', '?'
    return '%s.%s::%s' % (ns, nm, str(r.Name))

for t in (0x0a000a0b, 0x0a000a93, 0x0a0009a3):
    print('%08x %s' % (t, mref(t)))

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
b = z.read('m_06004192.bin')
ilsize = struct.unpack_from('<I', b, 4)[0]
il = b[24:24+ilsize]
print('== 06004192: fe.stloc 17 / fe.stloc 18 / V_0D writes ==')
for ins in disasm(il):
    if ins[1] == 'fe.stloc':
        v = struct.unpack_from('<H', ins[2])[0]
        if v in (0x17, 0x18, 0x0D):
            print('  %04X stloc %d' % (ins[0], v))
