# -*- coding: utf-8 -*-
"""step35b: tight resource directory parse."""
import struct, dnfile

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
data = open(BASE, 'rb').read()
pe = dnfile.dnPE(BASE)
cor20 = pe.net.struct
print('cor20 ResourcesRva=0x%X size=0x%X' % (cor20.ResourcesRva, cor20.ResourcesSize))
# raw check via dnfile's own offsets
base = pe.get_offset_from_rva(cor20.ResourcesRva)
end = base + cor20.ResourcesSize
print('resources file range: 0x%X - 0x%X' % (base, end))
p = base
i = 0
while p < end - 8:
    off, size = struct.unpack_from('<II', data, p)
    q = p + 8
    nlen = struct.unpack_from('<I', data, q)[0]
    nb = data[q+4:q+4+min(nlen, 48)]
    sane = 0 < nlen < 4096
    print('res[%d] @0x%X off=0x%X size=0x%X(%d) nlen=%d name[:32]=%s' % (i, p, off, size, size, nlen, nb[:32].hex() if sane else 'BAD'))
    if not sane:
        print('   next 32B after hdr: %s' % data[p:p+48].hex())
        break
    p = q + 4 + nlen
    p = (p + 3) & ~3
    i += 1
print('entries=%d  cursor=0x%X  (dir end=0x%X)' % (i, p, end))
