#!/usr/bin/env python3
# memdump2.py — 全量转储: 模块镜像 / 私有可执行 / 大堆 (分块读, 跨保护页)
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

PID = int(sys.argv[1])
OUT = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff\memdump'
h = k32.OpenProcess(0x0410, False, PID)
assert h

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                ("AllocationProtect", wt.DWORD), ("_pad", wt.DWORD), ("RegionSize", ctypes.c_uint64),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]

regions = []
addr = 0
m = MBI()
while addr < 0x7FFFFFFFEFFF:
    r = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(m), ctypes.sizeof(m))
    if not r:
        addr += 0x1000
        continue
    sz = int(m.RegionSize)
    if m.State == 0x1000 and sz > 0:
        regions.append((int(m.BaseAddress), sz, m.Protect, m.Type))
    addr = int(m.BaseAddress) + sz if sz else addr + 0x1000

abase = None
mods = (ctypes.c_void_p * 1024)()
cb = wt.DWORD()
psapi.EnumProcessModulesEx(h, ctypes.cast(mods, ctypes.c_void_p), ctypes.sizeof(mods), ctypes.byref(cb), 3)
for i in range(cb.value // ctypes.sizeof(ctypes.c_void_p)):
    b = ctypes.create_unicode_buffer(512)
    psapi.GetModuleFileNameExW(h, mods[i], b, 512)
    if 'airexplorer' in b.value.lower():
        abase = ctypes.cast(mods[i], ctypes.c_void_p).value or 0
        break
print('abase=0x%x regions=%d' % (abase, len(regions)))

def readmem(a, n):
    # chunked read to survive guard/protected pages
    out = bytearray()
    left = n
    off = 0
    while left > 0:
        chunk = min(left, 0x100000)
        buf = ctypes.create_string_buffer(chunk)
        got = ctypes.c_size_t()
        ok = k32.ReadProcessMemory(h, ctypes.c_void_p(a + off), buf, chunk, ctypes.byref(got))
        if not ok or got.value == 0:
            break
        out += buf.raw[:got.value]
        off += got.value
        left -= got.value
    return bytes(out)

os.makedirs(OUT, exist_ok=True)
# 1) full module image
img = readmem(abase, 0x938000)
open(os.path.join(OUT, 'module_image.bin'), 'wb').write(img)
print('module_image.bin len=0x%x' % len(img))

# 2) private exec regions (full)
PAGE_EXEC = {0x10, 0x20, 0x40, 0x80}
i = 0
for a, s, p, t in regions:
    if t == 0x20000 and p in PAGE_EXEC and s <= 0x100000:
        d = readmem(a, s)
        if d:
            open(os.path.join(OUT, 'pexec_0x%x.bin' % a), 'wb').write(d)
            print('pexec 0x%x size=0x%x got=0x%x nz=%d' % (a, s, len(d), sum(1 for x in d if x)))
        i += 1

# 3) big private heap regions
for a, s, p, t in regions:
    if t == 0x20000 and s >= 0x100000 and s <= 0x3000000 and p in (0x04, 0x40, 0x08):
        d = readmem(a, min(s, 0x3000000))
        if d and sum(1 for x in d[:0x10000] if x) > 0:
            fn = os.path.join(OUT, 'heap_0x%x.bin' % a)
            if not os.path.exists(fn):
                open(fn, 'wb').write(d)
                print('heap 0x%x size=0x%x got=0x%x' % (a, s, len(d)))
print('done')
