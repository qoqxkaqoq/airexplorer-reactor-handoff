#!/usr/bin/env python3
# Parse the CLR managed-resources blob of the baseline exe and compare with work/res_*.bin
import struct, hashlib, sys, os

exe = sys.argv[1] if len(sys.argv) > 1 else '../exes/AirExplorer_baseline_verified.exe'
d = open(exe, 'rb').read()

# PE headers
e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
assert d[e_lfanew:e_lfanew+4] == b'PE\0\0'
coff = e_lfanew + 4
nsec = struct.unpack_from('<H', d, coff+2)[0]
optsz = struct.unpack_from('<H', d, coff+16)[0]
opt = coff + 20
# PE32
ddoff = opt + 96
res_rva, res_size = struct.unpack_from('<II', d, ddoff + 14*8)  # CLR header dir = 14th
# CLR header (cor20)
clr_rva = res_rva
cb, maj, mnr, mdrva, mdsz, flags, eptok = struct.unpack_from('<IHHIIII', d, 0)  # placeholder
mo = struct.unpack_from('<I', d, 0)[0]
# map rva->file offset via sections
sec = opt + optsz
secs = []
for i in range(nsec):
    o = sec + i*40
    name = d[o:o+8].rstrip(b'\0').decode()
    vsz, va, rsz, ro = struct.unpack_from('<IIII', d, o+8)
    secs.append((va, vsz, ro, rsz, name))
def r2o(rva):
    for va, vsz, ro, rsz, name in secs:
        if va <= rva < va + max(vsz, rsz):
            return ro + (rva - va)
    return None
co = r2o(clr_rva)
cb, majr, minr, mdrva, mdsz, flags, eptok = struct.unpack_from('<IHHIIII', d, co)
res_rva, res_sz = struct.unpack_from('<II', d, co + 24)
print(f'CLR resources rva={res_rva:X} size={res_sz:X} (={res_sz})')
off = r2o(res_rva)
names = []
end = off + res_sz
while off < end - 4:
    ln = struct.unpack_from('<I', d, off)[0]
    off += 4
    if ln == 0 or off + ln > end: break
    payload = d[off:off+ln]
    md5 = hashlib.md5(payload).hexdigest()
    print(f'  len={ln:8d} md5={md5} first16={payload[:16].hex()}')
    names.append((ln, md5, payload))
    off += ln

# compare with work/res_*.bin
print('--- compare ---')
for f in sorted(os.listdir('.')):
    if not f.startswith('res_'): continue
    b = open(f, 'rb').read()
    m = hashlib.md5(b).hexdigest()
    hit = [ (ln, md5) for ln, md5, _ in names if md5 == m ]
    print(f'{f}: len={len(b)} md5={m} match={hit}')
