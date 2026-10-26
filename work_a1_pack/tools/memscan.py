#!/usr/bin/env python3
# memscan.py — 本机活进程内存扫描: 模块区/私有可执行区(驱动器)/大堆块
import ctypes, ctypes.wintypes as wt, os, sys

k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
psapi.EnumProcessModulesEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD]
psapi.GetModuleFileNameExW.restype = wt.DWORD
psapi.GetModuleFileNameExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.LPWSTR, wt.DWORD]

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 12312
h = k32.OpenProcess(0x0410, False, PID)
assert h, 'OpenProcess failed %d' % ctypes.GetLastError()

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                ("AllocationProtect", wt.DWORD), ("_pad", wt.DWORD), ("RegionSize", ctypes.c_uint64),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]

MEM_COMMIT, MEM_PRIVATE, MEM_IMAGE, MEM_MAPPED = 0x1000, 0x20000, 0x1000000, 0x40000
PAGE_EXEC = {0x10, 0x20, 0x40, 0x80}
PAGE_R = 0x02
PAGE_RW = 0x04

mods = (ctypes.c_void_p * 1024)()
cb = wt.DWORD()
psapi.EnumProcessModulesEx(h, ctypes.cast(mods, ctypes.c_void_p), ctypes.sizeof(mods), ctypes.byref(cb), 3)
abase = None
for i in range(cb.value // ctypes.sizeof(ctypes.c_void_p)):
    b = ctypes.create_unicode_buffer(512)
    psapi.GetModuleFileNameExW(h, mods[i], b, 512)
    if 'airexplorer' in b.value.lower():
        abase = ctypes.cast(mods[i], ctypes.c_void_p).value or 0
        print('AirExplorer base=0x%x' % abase)
        break
assert abase

regions = []
addr = 0
m = MBI()
while addr < 0x7FFFFFFFEFFF:
    r = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(m), ctypes.sizeof(m))
    if not r:
        addr += 0x1000
        continue
    sz = int(m.RegionSize)
    if m.State == MEM_COMMIT and sz > 0:
        regions.append((int(m.BaseAddress), sz, m.Protect, m.Type))
    addr = int(m.BaseAddress) + sz if sz else addr + 0x1000
print('regions: %d bytes=0x%x' % (len(regions), sum(r[1] for r in regions)))

def readmem(a, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t()
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(a), buf, n, ctypes.byref(got))
    return buf.raw[:got.value] if ok else None

# module image regions (sections incl .text stubs + resource)
print('--- module image regions ---')
img = [(a, s, p) for a, s, p, t in regions if t == MEM_IMAGE and a <= abase < a + s]
allocs = {}
for a, s, p, t in regions:
    if t == MEM_IMAGE:
        allocs.setdefault(a, 0)
for a, s, p, t in regions:
    if t == MEM_IMAGE:
        for k in allocs:
            if k <= a < k + 0x10000000 and a != k:
                pass
# simpler: find contiguous image allocation containing abase
imgtot = sum(s for a, s, p, t in regions if t == MEM_IMAGE and a >= abase and a < abase + 0x2000000)
print('module image total bytes=0x%x' % imgtot)
for a, s, p, t in regions:
    if t == MEM_IMAGE and abase <= a < abase + 0x2000000:
        print('  sec 0x%x (rva 0x%x) size=0x%x prot=0x%x' % (a, a - abase, s, p))

# stub slots
print('--- stub slots ---')
for rva in [0x196088, 0x1997C4, 0x195D18, 0x334EB0, 0x334EB0 + 0x8C8, 0x407FC4, 0x3FD34C]:
    d = readmem(abase + rva, 0x40)
    print('stub 0x%06x: %s' % (rva, d[:32].hex() if d else '<unread>'))

# private exec regions = native driver candidates
drv = [(a, s, p) for a, s, p, t in regions if t == MEM_PRIVATE and (p in PAGE_EXEC)]
print('--- private exec regions: %d ---' % len(drv))
os.makedirs(r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff\memdump', exist_ok=True)
for i, (a, s, p) in enumerate(drv):
    d = readmem(a, 64)
    head = d[:16].hex() if d else '<unread>'
    nz = None
    if d and s <= 0x40000:
        full = readmem(a, s)
        if full:
            fn = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff\memdump\drv_%d_0x%x.bin' % (i, a)
            open(fn, 'wb').write(full)
            nz = sum(1 for x in full if x)
    print('  0x%x size=0x%x prot=0x%x head=%s nz=%s' % (a, s, p, head, nz))

# big private regions
print('--- big private (heap) ---')
big = sorted([(s, a, p) for a, s, p, t in regions if t == MEM_PRIVATE and s > 0x100000], reverse=True)[:30]
for s, a, p in big:
    print('  0x%x size=0x%x prot=0x%x' % (a, s, p))
