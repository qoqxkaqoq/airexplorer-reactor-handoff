#!/usr/bin/env python3
# a9_incept.py — 正常运行(无调试器)瞬态猎手: 高频轮询进程内存找各资源密文堆副本+小数组key候选.
# 正常启动会出窗(反调试不触发), 启动期 Factory 等资源被解密(回填数据源), key/密文瞬态驻留堆.
import ctypes, ctypes.wintypes as wt, os, sys, time, struct, subprocess, threading

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
EXEDIR = os.path.join(W, 'localapp_rt')
OUT = os.path.join(W, 'work_a1', 'a9_incept')
os.makedirs(OUT, exist_ok=True)
k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
psapi.EnumProcessModulesEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD]

exe = open(W + r'\airexplorer-reactor-handoff\exes\AirExplorer_baseline_verified.exe','rb').read()
# resource ciphertext head fingerprints (32B) and sizes
RES = {
    'Viewer':   (exe[0x6213c4:0x6213c4+32], 0x56fe8),
    'Emitter':  (exe[0x6783b0:0x6783b0+32], 0x100),
    'Proc':     (exe[0x6784b4:0x6784b4+32], 0xbb2b),
    'Project':  (exe[0x683fe3:0x683fe3+32], 0x6610),
    'mainlib':  (exe[0x68a5f7:0x68a5f7+32], 0x23a907),
    'Factory':  (exe[0x8c4f02:0x8c4f02+32], 0x615ca),
}
ViewerKey = bytes.fromhex('f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943')

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
        # committed, readable, private (heaps), skip image (resource copy destination is heap)
        if m.State == 0x1000 and sz <= 0x800000 and (m.Protect & 0x04):
            out.append((int(m.BaseAddress), sz))
        addr = int(m.BaseAddress) + (sz if sz else 0x1000)
    return out

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

found = {}   # resname -> (region base, offset)
key_cands = []  # snapshot of small arrays captured near hits
t0 = time.time()
rounds = 0
MB = None
while time.time() - t0 < 60:
    rounds += 1
    if MB is None:
        MB = module_base()
        if not MB:
            time.sleep(0.05)
            continue
    for base, sz in regions():
        data = readmem(base, sz)
        if not data:
            continue
        for nm, (fp, rsz) in RES.items():
            if nm in found:
                continue
            i = data.find(fp)
            if i >= 0:
                found[nm] = (base, i, sz)
                print('HIT %s @0x%x+0x%x (t=%.2f r=%d)' % (nm, base, i, time.time()-t0, rounds), flush=True)
                # dump this region + hunt small arrays in whole process now
                open(os.path.join(OUT, 'ct_%s.bin' % nm), 'wb').write(data[max(0,i-0x40):i+min(rsz+0x100, len(data)-i)])
    if len(found) == len(RES):
        break
    time.sleep(0.02)

print('found resources: %s / %d rounds=%d elapsed=%.1f' % (list(found), len(RES), rounds, time.time()-t0), flush=True)

# capture key candidates: 32B arrays with plausible托管 header [MT][0x20][32B data]
# scan all regions for pattern: qword MT ptr, dword 0x20, then 32 bytes not all-zero
cands = []
for base, sz in regions():
    data = readmem(base, sz)
    if not data or len(data) < 0x40:
        continue
    off = 0
    while True:
        off = data.find(struct.pack('<I', 0x20), off + 1)
        if off < 0 or off + 0x30 > len(data):
            break
        # check qword before looks like a pointer (MethodTable)
        if off >= 8:
            mt = struct.unpack_from('<Q', data, off - 8)[0]
            if 0x7ffc00000000 <= mt < 0x7ffd00000000:
                kb = data[off+4:off+4+32]
                if len(kb) == 32 and kb.count(0) < 30:
                    cands.append((base + off, kb))
    if len(cands) > 4000:
        break
print('key candidates: %d' % len(cands), flush=True)
json_out = []
for a, kb in cands:
    json_out.append((hex(a), kb.hex()))
import json
json.dump(json_out, open(os.path.join(OUT, 'keycands.json'), 'w'))

# verify each candidate against Factory head: AOT decrypt first 8 dwords, look for RVA-like dwords
sys.path.insert(0, W + r'\airexplorer-reactor-handoff\work')
from decrypt_prng import prng_round
M32 = 0xFFFFFFFF
for nm, (fp, rsz) in RES.items():
    if nm not in found or nm == 'Viewer':
        continue
    ct = exe[list(RES).index(nm) and {k: v for k, v in [(k2, i2) for i2, (k2, v2) in enumerate(RES.items())]}.get(nm, 0)] if False else None
# simpler: recompute offsets
OFFS = {'Viewer': 0x6213c4, 'Emitter': 0x6783b0, 'Proc': 0x6784b4, 'Project': 0x683fe3, 'mainlib': 0x68a5f7, 'Factory': 0x8c4f02}
for nm in found:
    if nm == 'Viewer':
        continue
    ct = exe[OFFS[nm]:OFFS[nm]+64]
    hits = []
    for a, kb in cands:
        key = [struct.unpack_from('<I', kb, j*4)[0] for j in range(8)]
        state = 0
        out = bytearray()
        for i in range(8):
            state = (state + key[i % 8]) & M32
            state = prng_round(state)
            d = ct[i*4:i*4+4]
            c = (d[3]<<24)|(d[2]<<16)|(d[1]<<8)|d[0]
            out += struct.pack('<I', c ^ state)
        # check for RVA-like or structure
        o = bytes(out)
        nvalid = sum(1 for j in range(8) if 0x2050 <= struct.unpack_from('<I', o, j*4)[0] <= 0x44b81c)
        if nvalid >= 2 or o[:2] in (b'\x78\x9c', b'\x78\xda'):
            hits.append((hex(a), o[:24].hex(), nvalid))
    print('%s key-verify hits: %s' % (nm, hits[:6]), flush=True)

if p.poll() is None:
    subprocess.run(['taskkill', '/F', '/PID', str(PID)], capture_output=True)
print('done', flush=True)
