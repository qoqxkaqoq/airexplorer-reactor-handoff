#!/usr/bin/env python3
# a9_incept6.py — 轮询桩槽(0x196088 等)的翻转时刻(nop桩→完整体fat), 翻转瞬间全堆dump大数组+小数组.
# 正常运行无调试器. 目标: 完整体(phase-B)数据源.
import ctypes, ctypes.wintypes as wt, os, sys, time, struct, subprocess, pickle

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
EXEDIR = os.path.join(W, 'localapp_rt')
OUT = os.path.join(W, 'work_a1', 'a9_incept6')
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

WATCH = [
    (0x196088, '13300600b2030000', '06002133'),   # fat dw0=0x00063013, dw1=0x3b2
    (0x1997C4, '1b300700d7010000', '06002145'),
    (0x195CD4, '1330020014000000', '06002127'),
]

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
while not MB:
    MB = module_base()
    if not MB:
        time.sleep(0.01)
print('base 0x%x' % MB, flush=True)

MTPAT = bytes.fromhex('48589e7cfc7f0000')
t0 = time.time()
flipped = {}
snapshot_taken = False
last_states = {}
while time.time() - t0 < 90:
    for rva, fat_hex, tok in WATCH:
        cur = readmem(MB + rva, 8)
        key = cur.hex()
        if rva not in last_states or last_states[rva] != key:
            last_states[rva] = key
            print('t=%.2f %s slot=%s' % (time.time()-t0, tok, key), flush=True)
        if bytes.fromhex(fat_hex) == cur and tok not in flipped:
            flipped[tok] = time.time() - t0
            print('FLIP %s at t=%.2f' % (tok, flipped[tok]), flush=True)
    if len(flipped) == len(WATCH) and not snapshot_taken:
        snapshot_taken = True
        print('=== all flipped — dumping heaps ===', flush=True)
        break
    time.sleep(0.005)

if snapshot_taken or flipped:
    # dump all big + small arrays now (and also a second snapshot 0.3s later)
    for tag in ['snap1', 'snap2']:
        time.sleep(0.25)
        bigs = []
        smalls = []
        for base, sz in regions():
            data = readmem(base, sz)
            if not data:
                continue
            off = 0
            while True:
                off = data.find(MTPAT, off + 1)
                if off < 0 or off + 12 > len(data):
                    break
                cnt = struct.unpack_from('<I', data, off + 8)[0]
                doff = off + 16
                if 0x1000 <= cnt <= 0x800000:
                    a = base + doff
                    full = readmem(a, min(cnt, 0x800000))
                    open(os.path.join(OUT, '%s_big_%x_%x.bin' % (tag, a, cnt)), 'wb').write(full)
                    bigs.append((hex(a), cnt))
                elif 0x10 <= cnt <= 0x400:
                    d2 = data[doff:doff+cnt]
                    if len(d2) == cnt and d2.count(0) < cnt - 4:
                        smalls.append((base + doff, cnt, d2))
        print('%s: bigs=%s' % (tag, bigs), flush=True)
        pickle.dump([(a, c, d.hex()) for a, c, d in smalls], open(os.path.join(OUT, '%s_smalls.pkl' % tag), 'wb'))
        print('%s smalls: %d' % (tag, len(smalls)), flush=True)

if p.poll() is None:
    subprocess.run(['taskkill', '/F', '/PID', str(PID)], capture_output=True)
print('done flips=%s' % flipped, flush=True)
