#!/usr/bin/env python3
# a9_incept7.py — t=0 起高频快照: 抓 0.00-0.10s 窗口的大数组(完整体流假设在桩槽翻转前的更早窗口).
import ctypes, ctypes.wintypes as wt, os, sys, time, struct, subprocess, pickle

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
EXEDIR = os.path.join(W, 'localapp_rt')
OUT = os.path.join(W, 'work_a1', 'a9_incept7')
os.makedirs(OUT, exist_ok=True)
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

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                ("AllocationProtect", wt.DWORD), ("_p", wt.DWORD), ("RegionSize", ctypes.c_uint64),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]

envd = os.path.join(OUT, 'env')
for sub in ('a', 'b', r'a\tmp'):
    os.makedirs(os.path.join(envd, sub), exist_ok=True)
env = dict(os.environ)
env['APPDATA'] = os.path.join(envd, 'a')
env['LOCALAPPDATA'] = os.path.join(envd, 'b')
p = subprocess.Popen([os.path.join(EXEDIR, 'AirExplorer.exe')], cwd=EXEDIR, env=env)
PID = p.pid
t0 = time.time()
print('pid', PID, flush=True)
h = k32.OpenProcess(0x0410, False, PID)
assert h

def readmem(a, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t()
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(a), buf, n, ctypes.byref(got))
    return buf.raw[:got.value] if ok and got.value else b''

def module_base():
    mods = (ctypes.c_void_p * 1024)()
    cb = wt.DWORD()
    psapi.EnumProcessModulesEx(h, ctypes.cast(mods, ctypes.c_void_p), ctypes.sizeof(mods), ctypes.byref(cb), 3)
    for i in range(cb.value // ctypes.sizeof(ctypes.c_void_p)):
        b = ctypes.create_unicode_buffer(512)
        psapi.GetModuleFileNameExW(h, mods[i], b, 512)
        if 'airexplorer' in b.value.lower():
            return ctypes.cast(mods[i], ctypes.c_void_p).value or 0
    return 0

def regions():
    out = []
    addr = 0
    m = MBI()
    while addr < 0x7FFFFFFEFFFF:
        r = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(m), ctypes.sizeof(m))
        if not r:
            addr += 0x1000
            continue
        sz = int(m.RegionSize)
        if m.State == 0x1000 and m.Type == 0x20000 and sz <= 0x2000000 and (m.Protect & 0x06):
            out.append((int(m.BaseAddress), sz))
        addr = int(m.BaseAddress) + (sz if sz else 0x1000)
    return out

MB = None
MTPAT = bytes.fromhex('48589e7cfc7f0000')
PROCTAG = bytes.fromhex('3a9c012e')
t0 = time.time()
dumped = False
found_out = False
while time.time() - t0 < 400.0 and not found_out:
    if MB is None:
        MB = module_base()
        if not MB:
            time.sleep(0.002)
            continue
    for base, sz in regions():
        if sz > 0x4000000:
            continue
        data = readmem(base, sz)
        if not data:
            continue
        if not found_out:
            i2 = data.find(MTPAT + struct.pack('<I', 0xbb2b))
            while i2 >= 0:
                head4 = data[i2+16:i2+20]
                if head4 != PROCTAG and head4.count(0) < 3:
                    open(os.path.join(OUT, 'PROC_OUT_%x.bin' % (base+i2)), 'wb').write(data[i2+16:i2+16+0xbb2b])
                    print('t=%.3f *** PROC OUT FOUND @0x%x head=%s' % (time.time()-t0, base+i2, head4.hex()), flush=True)
                    found_out = True
                i2 = data.find(MTPAT + struct.pack('<I', 0xbb2b), i2 + 1)
        if not dumped and PROCTAG in data:
            # find the actual 0xbb2b array via MT pattern nearby
            i = data.find(MTPAT + struct.pack('<I', 0xbb2b))
            print('t=%.3f PROC copy found in region 0x%x (MT+cnt @0x%x)' % (time.time()-t0, base, i), flush=True)
            # DUMP ALL REGIONS NOW (raw)
            for b2, s2 in regions():
                d2 = readmem(b2, min(s2, 0x2000000))
                if len(d2) > 0x1000:
                    fn = os.path.join(OUT, 'raw_%x.bin' % b2)
                    if not os.path.exists(fn):
                        open(fn, 'wb').write(d2)
            time.sleep(0.12)
            for b2, s2 in regions():
                d2 = readmem(b2, min(s2, 0x2000000))
                if len(d2) > 0x1000:
                    fn = os.path.join(OUT, 'late_%x.bin' % b2)
                    if not os.path.exists(fn):
                        open(fn, 'wb').write(d2)
            print('all regions dumped (early+late)', flush=True)
            dumped = True
            break
    time.sleep(0.005)
print('done over %.2fs' % (time.time() - t0), flush=True)
if p.poll() is None:
    subprocess.run(['taskkill', '/F', '/PID', str(PID)], capture_output=True)
print('done', flush=True)
