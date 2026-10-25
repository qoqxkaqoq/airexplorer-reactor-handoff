#!/usr/bin/env python3
# a9_incept3.py — 正常运行瞬态猎手 v3: 找到全部资源密文堆副本后, 全进程搜同 count 数组(输入/输出对) + 小数组(key候选)
# 并离线验证 key 候选 (AOT 头部解密出结构特征).
import ctypes, ctypes.wintypes as wt, os, sys, time, struct, subprocess, json, pickle

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
EXEDIR = os.path.join(W, 'localapp_rt')
OUT = os.path.join(W, 'work_a1', 'a9_incept3')
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

exe = open(W + r'\airexplorer-reactor-handoff\exes\AirExplorer_baseline_verified.exe', 'rb').read()
OFFS = {'Viewer': 0x6213c4, 'Emitter': 0x6783b0, 'Proc': 0x6784b4, 'Project': 0x683fe3,
        'mainlib': 0x68a5f7, 'Factory': 0x8c4f02}
SIZES = {'Viewer': 0x56fe8, 'Emitter': 0x100, 'Proc': 0xbb2b, 'Project': 0x6610,
         'mainlib': 0x23a907, 'Factory': 0x615ca}
FPS = {nm: exe[o:o+32] for nm, o in OFFS.items()}

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

# phase 1: wait until all 6 ct copies present (poll fast)
found = {}
t0 = time.time()
while time.time() - t0 < 30 and len(found) < 6:
    for base, sz in regions():
        if sz > 0x4000000:
            continue
        data = readmem(base, sz)
        if not data:
            continue
        for nm, fp in FPS.items():
            if nm in found:
                continue
            i = data.find(fp)
            if i >= 0:
                found[nm] = base
                print('HIT %s in region 0x%x (t=%.2f) pre32=%s' % (nm, base, time.time()-t0, data[max(0,i-32):i].hex()), flush=True)
                open(os.path.join(OUT, 'pre_%s.bin' % nm), 'wb').write(data[max(0,i-64):i+64])
    time.sleep(0.02)
print('found: %s' % sorted(found), flush=True)

# phase 2: full scan of all regions — arrays with Byte[] MT + interesting counts
# Byte[] MT pattern discovered this boot: 48589e7cfc7f0000 — but discover dynamically from a known copy:
sample = None
for base, sz in regions():
    data = readmem(base, min(sz, 0x100000))
    if not data:
        continue
    for nm, fp in FPS.items():
        i = data.find(fp)
        if i >= 0x10:
            # walk back to find MT: array header [MT 8][count 4][data]. data starts at i => MT at i-12
            mt = data[i-12:i-4]
            cnt = struct.unpack_from('<I', data, i-4)[0]
            if cnt == SIZES[nm]:
                sample = mt
                print('MT discovered: %s (from %s, count=0x%x)' % (mt.hex(), nm, cnt), flush=True)
                break
    if sample:
        break
# hardcoded this-boot Byte[] MT (seen in all pre32 dumps); skip flaky discovery
MTPAT = bytes.fromhex('48589e7cfc7f0000')
print('MTPAT hardcoded:', MTPAT.hex(), flush=True)

arrays = {}
small = []
for base, sz in regions():
    if sz > 0x4000000:
        data = readmem(base, sz)
    else:
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
        if cnt in SIZES.values():
            nm = [k for k, v in SIZES.items() if v == cnt][0]
            arrays.setdefault(nm, []).append((base + off + 16, cnt, data[doff:doff+min(cnt, 0x200)]))
        elif 0x10 <= cnt <= 0x400:
            d2 = data[doff:doff+cnt]
            if len(d2) == cnt and d2.count(0) < cnt - 4:
                small.append((base + off + 16, cnt, d2))

for nm, lst in arrays.items():
    print('%s: %d arrays %s' % (nm, len(lst), [(hex(a), hex(c)) for a, c, _ in lst]), flush=True)
    for j, (a, c, head) in enumerate(lst):
        open(os.path.join(OUT, 'arr_%s_%d.bin' % (nm, j)), 'wb').write(head)
        print('   [%d] @0x%x head=%s' % (j, a, head[:24].hex()), flush=True)
print('small arrays: %d' % len(small), flush=True)
pickle.dump(small, open(os.path.join(OUT, 'small.pkl'), 'wb'))

# phase 3: verify key candidates per resource
sys.path.insert(0, W + r'\airexplorer-reactor-handoff\work')
from decrypt_prng import prng_round
M32 = 0xFFFFFFFF

def aot_head(ct, key, n=8):
    state = 0
    out = bytearray()
    for i in range(n):
        state = (state + key[i % len(key)]) & M32
        state = prng_round(state)
        d = ct[i*4:i*4+4]
        c = (d[3]<<24)|(d[2]<<16)|(d[1]<<8)|d[0]
        out += struct.pack('<I', c ^ state)
    return bytes(out)

def looks_struct(o, n):
    nv = sum(1 for j in range(n) if 0x2050 <= struct.unpack_from('<I', o, j*4)[0] <= 0x44b81c)
    if nv >= 2:
        return True
    if o[:2] in (b'\x78\x9c', b'\x78\xda', b'\x78\x01'):
        return True
    return False

for nm in found:
    if nm == 'Viewer':
        continue
    ct = exe[OFFS[nm]:OFFS[nm]+64]
    hits = []
    for a, cnt, d2 in small:
        if len(d2) % 4:
            continue
        key = [struct.unpack_from('<I', d2, j*4)[0] for j in range(len(d2)//4)]
        o = aot_head(ct, key)
        if looks_struct(o, 8):
            hits.append((hex(a), cnt, o[:24].hex()))
    print('%s KEY HITS: %s' % (nm, hits[:8]), flush=True)
    if hits:
        for j, (a, cnt, hh) in enumerate(hits[:2]):
            d2 = dict((x[0], x[2]) for x in small)[int(a, 16)]
            open(os.path.join(OUT, 'key_%s.bin' % nm), 'wb').write(d2)

if p.poll() is None:
    subprocess.run(['taskkill', '/F', '/PID', str(PID)], capture_output=True)
print('done', flush=True)
