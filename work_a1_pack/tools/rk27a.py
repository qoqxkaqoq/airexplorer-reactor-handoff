#!/usr/bin/env python3
# rk27a.py — 阶段A：无调试器高频堆扫，搜三把已知 AOT key（地面真值校准）。
# 命中→dump 邻域（找 key 表：同形态 32B 数组 = Proc/Emitter 候选）。
import ctypes, ctypes.wintypes as wt, os, sys, time, struct, subprocess, hashlib

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
EXEDIR = os.path.join(W, 'work_a1', 'rk27', 'bin')
EXE = os.path.join(EXEDIR, 'AirExplorerRK.exe')
OUT = os.path.join(W, 'work_a1', 'rk27', 'out')
os.makedirs(OUT, exist_ok=True)

KV = bytes.fromhex('f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943')
KM = bytes.fromhex('cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481')
KF = bytes.fromhex('37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a')
PATTERNS = []
for nm, k in (('Viewer', KV), ('mainlib', KM), ('Factory', KF)):
    PATTERNS.append((nm + ':raw32', k))
    h = k.hex().encode()
    PATTERNS.append((nm + ':hexascii', h))
    PATTERNS.append((nm + ':hexutf16', h.decode().encode('utf-16-le')))

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_uint64), ('AllocationBase', ctypes.c_uint64),
                ('AllocationProtect', wt.DWORD), ('RegionSize', ctypes.c_uint64),
                ('State', wt.DWORD), ('Protect', wt.DWORD), ('Type', wt.DWORD)]

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
WRITABLE = {0x04, 0x40, 0x02, 0x20, 0x08, 0x80}  # RW/RWX/RO等可读即可，全读
READABLE_PROT = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80

LOG = open(os.path.join(OUT, 'rk27a.log'), 'w', buffering=1)
def P(s):
    print(s, flush=True); LOG.write(s + '\n')

env = dict(os.environ)
envd = os.path.join(W, 'work_a1', 'rk27', 'env')
for sub in ('a', 'b', r'a\tmp'):
    os.makedirs(os.path.join(envd, sub), exist_ok=True)
env['APPDATA'] = os.path.join(envd, 'a'); env['LOCALAPPDATA'] = os.path.join(envd, 'b')
env['TMP'] = os.path.join(envd, 'a', 'tmp'); env['TEMP'] = env['TMP']

p = subprocess.Popen([EXE], cwd=EXEDIR, env=env)
PID = p.pid
P('pid %d  t0' % PID)
h = None
t0 = time.time()
hits = {}          # (patname, region_base, off) -> t
dumped = set()
sweeps = 0
total_bytes = 0
buf = ctypes.create_string_buffer(0x2000000)
got = ctypes.c_size_t(0)
mbi = MBI()
max_t = 40.0

def sweep():
    global total_bytes
    addr = 0
    found = []
    while addr < 0x7FFFFFFFFFFF:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base, size = mbi.BaseAddress, mbi.RegionSize
        if size == 0:
            break
        addr = base + size
        if mbi.State != MEM_COMMIT or mbi.Type != MEM_PRIVATE:
            continue
        if not (mbi.Protect & READABLE_PROT) or mbi.Protect & 0x100:  # skip PAGE_GUARD
            continue
        if size > 0x2000000:
            continue
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(got)):
            continue
        data = buf.raw[:got.value]
        total_bytes += got.value
        for nm, pat in PATTERNS:
            i = data.find(pat)
            while i != -1:
                key = (nm, base, i)
                if key not in hits:
                    hits[key] = time.time() - t0
                    found.append((nm, base, i, got.value))
                i = data.find(pat, i + 1)
    return found

while time.time() - t0 < max_t:
    if h is None:
        h = k32.OpenProcess(0x041F, False, PID)
        if not h:
            time.sleep(0.01); continue
    if p.poll() is not None:
        P('process exited rc=%s at %.2fs' % (p.returncode, time.time() - t0)); break
    ts = time.time() - t0
    for nm, base, off, rsize in sweep():
        P('HIT %-18s region=0x%x off=0x%x t=%.3f' % (nm, base, off, hits[(nm, base, off)]))
        safe = nm.replace(':', '_')
        dkey = (base, off)
        if dkey not in dumped:
            dumped.add(dkey)
            # 整区 dump 一次（≤32MB），key 表候选全在里面
            rfn = os.path.join(OUT, 'region_%x.bin' % base)
            if not os.path.exists(rfn) and rsize <= 0x2000000:
                if k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, rsize, ctypes.byref(got)) and got.value:
                    open(rfn, 'wb').write(buf.raw[:got.value])
                    P('  region dump -> %s (%d B)' % (os.path.basename(rfn), got.value))
            lo = max(0, off - 0x400); hi = min(0x2000000, off + 0x1000)
            if k32.ReadProcessMemory(h, ctypes.c_void_p(base + lo), buf, hi - lo, ctypes.byref(got)) and got.value:
                fn = os.path.join(OUT, 'hit_%s_%x_%x.bin' % (safe, base, off))
                open(fn, 'wb').write(buf.raw[:got.value])
                P('  dump -> %s (%d B)' % (os.path.basename(fn), got.value))
    sweeps += 1
    if sweeps % 100 == 0:
        P('progress t=%.1fs sweeps=%d scanned=%.1fMB hits=%d' % (time.time() - t0, sweeps, total_bytes / 1e6, len(hits)))
    time.sleep(0.02)

P('done: sweeps=%d bytes_scanned=%.1fMB hits=%d elapsed=%.1fs' % (sweeps, total_bytes / 1e6, len(hits), time.time() - t0))
if p.poll() is None:
    subprocess.run(['taskkill', '/F', '/PID', str(PID)], capture_output=True)
P('killed')
