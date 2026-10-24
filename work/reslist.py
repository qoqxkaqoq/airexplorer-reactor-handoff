#!/usr/bin/env python3
# reslist.py — parse cor20 managed resources directory: list every resource (name, size, first bytes)
import struct

EXE = '/workspace/airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe'
d = open(EXE, 'rb').read()

pe = struct.unpack_from('<I', d, 0x3C)[0]
nsec = struct.unpack_from('<H', d, pe + 6)[0]
optsz = struct.unpack_from('<H', d, pe + 20)[0]
secs = []
for i in range(nsec):
    o = pe + 24 + optsz + 40 * i
    name = d[o:o+8].rstrip(b'\0').decode()
    vsz, va, rsz, ro = struct.unpack_from('<IIII', d, o + 8)
    secs.append((name, va, vsz, ro, rsz))
    print(f'sec {name:8} va=0x{va:X} vsz=0x{vsz:X} raw=0x{ro:X} rsz=0x{rsz:X}')

def rva2off(rva):
    for name, va, vsz, ro, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ro + (rva - va)
    raise SystemExit(f'rva 0x{rva:X} not mapped')

# cor20 header: pe + 24 + 96 (PE32 data dirs start) -> CLI header is 15th entry (index 14)
cor = pe + 24 + 96 + 14 * 8
res_rva, res_size = struct.unpack_from('<II', d, cor)
print(f'\ncor20 Resources rva=0x{res_rva:X} size=0x{res_size:X} fileoff=0x{rva2off(res_rva):X}')

base = rva2off(res_rva)
end = base + res_size
p = base
i = 0
total_data = 0
while p < end - 8:
    off, size = struct.unpack_from('<II', d, p)
    if off == 0 and size == 0:
        break
    # name: skip 4-byte offset+size, then length-prefixed name (u32 len + UTF8, aligned 4)
    q = p + 8
    nlen = struct.unpack_from('<I', d, q)[0]
    name = d[q+4:q+4+nlen].decode('utf-8', 'replace')
    # data starts at Resources base + off
    doff = base + off
    head = d[doff:doff+16].hex()
    # entropy estimate on first 4KB
    import math
    blob = d[doff:doff+4096]
    if blob:
        freq = {}
        for b in blob:
            freq[b] = freq.get(b, 0) + 1
        ent = -sum(c/len(blob) * math.log2(c/len(blob)) for c in freq.values())
    else:
        ent = 0
    print(f'res[{i}] off=0x{off:X} size={size} ({size/1048576:.3f}MB) name={name!r} ent4k={ent:.3f} head={head}')
    total_data += size
    p = q + 4 + nlen
    p = (p + 3) & ~3
    i += 1
print(f'\nresources={i} total_data={total_data} ({total_data/1048576:.3f}MB) dir_size={res_size}')
