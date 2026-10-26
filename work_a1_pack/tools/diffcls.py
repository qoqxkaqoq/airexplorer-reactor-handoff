#!/usr/bin/env python3
# diffcls.py — 分类 .text 文件 vs 运行时差异: 桩槽回填 / IAT / 重定位 / 其他(Reactor自改)
import struct

exe = open('airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe','rb').read()
text = open('memdump/module_text.bin','rb').read()  # rva base 0x2000

pe = struct.unpack_from('<I', exe, 0x3C)[0]
nsec = struct.unpack_from('<H', exe, pe+6)[0]
optsz = struct.unpack_from('<H', exe, pe+20)[0]
opt = pe + 24
magic = struct.unpack_from('<H', exe, opt)[0]
ddoff = opt + (0x60 if magic == 0x10B else 0x70)
def dd(i):
    return struct.unpack_from('<II', exe, ddoff + i*8)
imp_rva, imp_sz = dd(1)
reloc_rva, reloc_sz = dd(5)
iat_rva, iat_sz = dd(12)
ep_rva = struct.unpack_from('<I', exe, opt + 16)[0]
print('EP rva=0x%x import=0x%x(%x) reloc=0x%x(%x) IAT=0x%x(%x)' % (ep_rva, imp_rva, imp_sz, reloc_rva, reloc_sz, iat_rva, iat_sz))

# import thunk RVAs (IAT entries live in import range)
import_rvas = set()
if imp_rva:
    o = imp_rva
    while True:
        oft, ts, fc, namerva, fthunk = struct.unpack_from('<5I', exe, o)
        if oft == 0 and fthunk == 0: break
        # FirstThunk array entries = thunk rvas (in .text)
        j = 0
        while True:
            tv = struct.unpack_from('<Q', exe, o + 20 + j*8)[0] if False else None
            break
        import_rvas.add(o + 20)  # the DIT FirstThunk field rva
        o += 20

# relocation targets in .text
reloc_targets = set()
if reloc_rva:
    o = reloc_rva
    end = reloc_rva + reloc_sz
    while o < end:
        pageva, blksz = struct.unpack_from('<II', exe, o)
        if blksz == 0: break
        n = (blksz - 8) // 2
        for i in range(n):
            if o + 10 + i*2 > len(exe): break
            e = struct.unpack_from('<H', exe, o + 8 + i*2)[0]
            typ = e >> 12
            off = e & 0xFFF
            if typ == 10:  # DIR64
                reloc_targets.add(pageva + off)
            elif typ == 8 or typ == 6:  # highlow/section
                reloc_targets.add(pageva + off)
        o += blksz
reloc_text = set(t for t in reloc_targets if 0x2000 <= t < 0x2000+0x927000)
print('reloc targets in .text: %d' % len(reloc_text))

# all method stub ranges from metadata
d = exe
e_lfanew = pe
coff = e_lfanew + 4
nsec, = struct.unpack_from('<H', d, coff + 2)
optsz, = struct.unpack_from('<H', d, coff + 16)
clr_rva, _ = struct.unpack_from('<II', d, ddoff + 14*8)
sec0 = coff + 20 + optsz
secs = []
for i in range(nsec):
    o = sec0 + i*40
    va, vsz = struct.unpack_from('<I', d, o+12)[0], struct.unpack_from('<I', d, o+8)[0]
    raw, rawsz = struct.unpack_from('<I', d, o+20)[0], struct.unpack_from('<I', d, o+16)[0]
    secs.append((va, vsz, raw, rawsz))
def rva2off(rva):
    for va, vsz, raw, rawsz in secs:
        if va <= rva < va + max(vsz, rawsz): return raw + (rva - va)
mo = rva2off(rva2off(clr_rva))  # clr header -> metadata rva
cor = rva2off(clr_rva)
md_rva, _ = struct.unpack_from('<II', d, cor + 8)
mo = rva2off(md_rva)
vlen, = struct.unpack_from('<I', d, mo + 12)
p = mo + 16 + vlen
nstr, = struct.unpack_from('<H', d, p + 2)
p += 4
streams = {}
for i in range(nstr):
    so, ssz = struct.unpack_from('<II', d, p)
    nm = d[p+8:d.index(b'\0', p+8)].decode()
    streams[nm] = (mo + so, ssz)
    p += 8 + len(nm) + 1
    p = (p + 3) & ~3
tto, _ = streams['#~']
hs = d[tto + 6]
si = 4 if hs & 1 else 2
valid, = struct.unpack_from('<Q', d, tto + 8)
rows = {}
q = tto + 24
for b in range(64):
    if valid & (1 << b):
        rows[b], = struct.unpack_from('<I', d, q)
        q += 4
def ci(tabs): return 4 if any(rows.get(t, 0) > 0xFFFF for t in tabs) else 2
RS = ci([0x00, 0x1A, 0x23, 0x01]); TDOR = ci([0x02, 0x01, 0x1B])
RSZ, GSZ, BSZ = si, (4 if hs & 2 else 2), (4 if hs & 4 else 2)
fsz = {0x00: 2 + RSZ + 3*GSZ, 0x01: RS + RSZ + RSZ,
       0x02: 4 + RSZ + RSZ + TDOR + ci([0x04]) + ci([0x06]),
       0x03: ci([0x04]), 0x04: 2 + RSZ + BSZ, 0x05: ci([0x06]),
       0x06: 4 + 2 + 2 + RSZ + BSZ + ci([0x08])}
off = q
for b in sorted(fsz):
    if b >= 0x06: break
    if b in rows: off += fsz[b] * rows[b]
mrow = fsz[0x06]; n = rows[0x06]
# il sizes from dump zip
import zipfile
z = zipfile.ZipFile('airexplorer-reactor-handoff/work/dump_official_16598.zip')
sizes = {}
for nm in z.namelist():
    if nm.endswith('.bin'):
        sz = struct.unpack_from('<I', z.read(nm), 4)[0]
        sizes[nm] = sz
stub_ranges = []
nofile = 0
for r in range(1, n+1):
    rva, = struct.unpack_from('<I', d, off + (r-1)*mrow)
    tok = '0600%04X' % (r & 0xFFFF) if False else None
    key = '0600%06X' % r
    key = '0600' + ('%04X' % r) if r < 0x10000 else '0600%X' % r
    # dump names are like m_06002133.bin -> token = 0x06000000 + rid
    nm = 'm_0600%04X.bin' % r if r <= 0xFFFF else 'm_0600%05X.bin' % r
    if nm in sizes: il = sizes[nm]
    else: il = None; nofile += 1
    if rva and il is not None:
        # slot = fat(12)+il or tiny(1+il); runtime wrote fat for most; use 12+il upper bound
        stub_ranges.append((rva, 12 + il + 0x40))
print('methods=%d nodump=%d stub ranges=%d' % (n, nofile, len(stub_ranges)))

# diff blocks
diffs = []
for i in range(0, min(len(exe[0x200:0x200+len(text)]), len(text)), 16):
    if exe[0x200+i:0x200+i+16] != text[i:i+16]:
        diffs.append(0x2000 + i)
print('diff 16B blocks: %d' % len(diffs))

def in_stub(rva):
    # binary search over sorted stub ranges
    import bisect
    starts = [s for s, _ in stub_ranges]
    i = bisect.bisect_right(starts, rva) - 1
    if i >= 0:
        s, l = stub_ranges[i]
        if s <= rva < s + l: return True
    return False

cat = {'stub': 0, 'reloc': 0, 'import': 0, 'other': 0}
others = []
for rva in diffs:
    if in_stub(rva): cat['stub'] += 1
    elif rva in reloc_text: cat['reloc'] += 1
    elif imp_rva and imp_rva <= rva < imp_rva + max(imp_sz, 0x1000): cat['import'] += 1
    else:
        cat['other'] += 1
        others.append(rva)
print('category:', cat)
if others:
    print('other diff rvas (%d): first 30 = %s' % (len(others), [hex(x) for x in others[:30]]))
    # cluster others
    cl = []
    s = others[0]; prev = others[0]
    for x in others[1:]:
        if x - prev > 0x80:
            cl.append((s, prev)); s = x
        prev = x
    cl.append((s, prev))
    print('other clusters: %d -> %s' % (len(cl), [(hex(a), hex(b)) for a, b in cl[:40]]))
