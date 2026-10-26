#!/usr/bin/env python3
# k26_guard.py — 6 资源页 PAGE_GUARD + 命中时全栈窗(rbp-0x800..rbp+0x80)数组指针追踪 + 堆搜已知 key
# 改造自 a9_guard7.py（先例：DEBUG_ONLY_THIS_PROCESS 创建即调试不出窗）
import ctypes, ctypes.wintypes as wt, os, sys, time, struct, json, subprocess

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
EXEDIR = os.path.join(W, 'work_a1', 'k26', 'bin')
EXE = os.path.join(EXEDIR, 'AirExplorerK26.exe')
OUT = os.path.join(W, 'work_a1', 'k26', 'guard1')
os.makedirs(OUT, exist_ok=True)
k32 = ctypes.windll.kernel32
DEBUG_ONLY_THIS_PROCESS = 2
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
GUARD_PAGE = 0x80000001
SINGLE_STEP = 0x80000004
PAGE_GUARD_F = 0x100
PAGE_READWRITE = 4
PAGE_READONLY = 2

import binascii
KV = binascii.unhexlify('f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943')
KM = binascii.unhexlify('cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481')
KF = binascii.unhexlify('37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a')
KEYS = {'KV': KV, 'KM': KM, 'KF': KF}

# resource file offsets -> page RVAs to guard
GUARD_RVAS = [0x621000, 0x678000, 0x683000, 0x68A000, 0x8C4000]
RES_NAME = {0x621000: 'Viewer', 0x678000: 'Emitter/Proc', 0x683000: 'Project', 0x68A000: 'mainlib', 0x8C4000: 'Factory'}

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [(n, ctypes.c_void_p) for n in ('cb','lpReserved','lpDesktop','lpTitle')] + \
               [(n, wt.DWORD) for n in ('dwX','dwY','dwXSize','dwYSize','dwXCountChars','dwYCountChars','dwFillAttribute','dwFlags')] + \
               [(n, wt.WORD) for n in ('wShowWindow','cbReserved2')] + \
               [(n, ctypes.c_void_p) for n in ('lpReserved2','hStdInput','hStdOutput','hStdError')]
class PROCESS_INFOW(ctypes.Structure):
    _fields_ = [('hProcess', ctypes.c_void_p), ('hThread', ctypes.c_void_p),
                ('dwProcessId', wt.DWORD), ('dwThreadId', wt.DWORD)]
class EXCEPTION_RECORD64(ctypes.Structure):
    _fields_ = [('ExceptionCode', wt.DWORD), ('ExceptionFlags', wt.DWORD),
                ('ExceptionRecord', ctypes.c_uint64), ('ExceptionAddress', ctypes.c_uint64),
                ('NumberParameters', wt.DWORD), ('__pad', wt.DWORD),
                ('ExceptionInformation', ctypes.c_uint64 * 15)]
class DEBUG_EVENT(ctypes.Structure):
    class U(ctypes.Union):
        _fields_ = [('Exception', EXCEPTION_RECORD64), ('raw', ctypes.c_byte * 160)]
    _fields_ = [('dwDebugEventCode', wt.DWORD), ('dwProcessId', wt.DWORD), ('dwThreadId', wt.DWORD), ('u', U)]
class CONTEXT(ctypes.Structure):
    _fields_ = [('P1Home', ctypes.c_uint64*3), ('P4Home', ctypes.c_uint64*3),
                ('ContextFlags', wt.DWORD), ('MxCsr', wt.DWORD),
                ('SegCs', wt.WORD), ('SegDs', wt.WORD), ('SegEs', wt.WORD), ('SegFs', wt.WORD),
                ('SegGs', wt.WORD), ('SegSs', wt.WORD), ('EFlags', wt.DWORD),
                ('Dr0', ctypes.c_uint64), ('Dr1', ctypes.c_uint64), ('Dr2', ctypes.c_uint64),
                ('Dr3', ctypes.c_uint64), ('Dr6', ctypes.c_uint64), ('Dr7', ctypes.c_uint64),
                ('Rax', ctypes.c_uint64), ('Rcx', ctypes.c_uint64), ('Rdx', ctypes.c_uint64),
                ('Rbx', ctypes.c_uint64), ('Rsp', ctypes.c_uint64), ('Rbp', ctypes.c_uint64),
                ('Rsi', ctypes.c_uint64), ('Rdi', ctypes.c_uint64),
                ('R8', ctypes.c_uint64), ('R9', ctypes.c_uint64), ('R10', ctypes.c_uint64),
                ('R11', ctypes.c_uint64), ('R12', ctypes.c_uint64), ('R13', ctypes.c_uint64),
                ('R14', ctypes.c_uint64), ('R15', ctypes.c_uint64), ('Rip', ctypes.c_uint64),
                ('Flt', ctypes.c_byte * 512), ('Vect', ctypes.c_byte * 416),
                ('DebugCtl', ctypes.c_uint64), ('LastBranchToRip', ctypes.c_uint64),
                ('LastBranchFromRip', ctypes.c_uint64), ('LastExceptionToRip', ctypes.c_uint64),
                ('LastExceptionFromRip', ctypes.c_uint64)]
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                ("AllocationProtect", wt.DWORD), ("_p", wt.DWORD), ("RegionSize", ctypes.c_uint64),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]

LOG = open(os.path.join(OUT, 'log.txt'), 'w', buffering=1)
def P(s):
    print(s, flush=True); LOG.write(s + '\n'); LOG.flush()

envd = os.path.join(OUT, 'env')
for sub in ('a', 'b', r'a\tmp'):
    os.makedirs(os.path.join(envd, sub), exist_ok=True)
env = dict(os.environ)
env['APPDATA'] = os.path.join(envd, 'a')
env['LOCALAPPDATA'] = os.path.join(envd, 'b')
env['TMP'] = os.path.join(envd, r'a\tmp')
env['TEMP'] = os.path.join(envd, r'a\tmp')
si = STARTUPINFOW(); si.cb = ctypes.sizeof(si)
pi = PROCESS_INFOW()
cmd = ctypes.create_unicode_buffer('"%s"' % EXE)
ok = k32.CreateProcessW(None, cmd, None, None, False, DEBUG_ONLY_THIS_PROCESS, None, EXEDIR, ctypes.byref(si), ctypes.byref(pi))
assert ok, 'CreateProcess failed'
hProc, PID = pi.hProcess, pi.dwProcessId
P('pid %d' % PID)
t0 = time.time()

def readmem(a, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t()
    ok2 = k32.ReadProcessMemory(hProc, ctypes.c_void_p(a), buf, n, ctypes.byref(got))
    return buf.raw[:got.value] if ok2 and got.value else b''

guards = {}
pending_ss = {}
snap_count = 0
heap_hits = []
keytable_hits = []
IMAGE_BASE = None
scans_done = [0]

def apply_guard(page, prot=PAGE_READONLY):
    old = wt.DWORD()
    if k32.VirtualProtectEx(hProc, ctypes.c_void_p(page), 0x1000, prot | PAGE_GUARD_F, ctypes.byref(old)):
        guards[page] = (old.value, prot)
        return True
    return False

def unguard(page):
    g = guards.pop(page, None)
    if g:
        k32.VirtualProtectEx(hProc, ctypes.c_void_p(page), 0x1000, g[0], None)

def regions_iter(maxsz=0x4000000):
    addr = 0
    m = MBI()
    while addr < 0x7FFFFFFEFFFF:
        r = k32.VirtualQueryEx(hProc, ctypes.c_void_p(addr), ctypes.byref(m), ctypes.sizeof(m))
        if not r:
            addr += 0x1000; continue
        sz = int(m.RegionSize)
        if m.State == 0x1000 and sz <= maxsz and (m.Protect & 0x04) and m.Type == 0x20000:
            yield int(m.BaseAddress), sz
        addr = int(m.BaseAddress) + (sz if sz else 0x1000)

EXE_CT = {}
def _load_ct():
    if not EXE_CT:
        exe = open(EXE, 'rb').read()
        for nm, off, ln in (('Emitter', 0x6783B0, 0x100), ('Proc', 0x6784B4, 0xBB2B)):
            EXE_CT[nm] = exe[off:off+ln]
    return EXE_CT

def prng_round(v9):
    M32L = 0xFFFFFFFF
    K1 = 506503628; K1B = (1610158714 + 1328951073 - 1267867220) & M32L
    K2 = 1959015338; K3 = 854276594; K4 = 41684485
    v43u = (K1 * v9) & M32L
    if v43u == 0: v43u = (1 << 64) - 1
    v40 = ((K3 * K3) & M32L) % v43u
    v45 = (((K2 >> 9) | ((K2 << 23) & M32L)) + v9) & M32L
    v39 = (((v45 & 0xAAAAAAAA) >> 1) | ((v45 & 0x55555555) << 1)) & M32L
    v41x = v9 if v9 != 0 else M32L
    v44 = ((v40 // v41x) + v41x) & M32L
    v41 = (((v40 + v40) - v44) + v40) & M32L
    v45b = ((((K4 << 10) & M32L) | (K4 >> 22)) + v40) & M32L
    v42 = (((v45b & 0xFF00FF00) >> 8) | ((v45b & 0x00FF00FF) << 8)) & M32L
    v41 = (v41 ^ (v41 >> 3)) & M32L
    v41 = (v41 + K1B) & M32L
    v41 = (v41 ^ ((v41 << 7) & M32L)) & M32L
    v41 = (v41 + v41) & M32L
    v41 = (v41 ^ (v41 >> 29)) & M32L
    v41 = (v41 + v42) & M32L
    v41 = (v41 + ((((v39 << 4) & M32L) - v40) & M32L ^ K1B)) & M32L
    return (v9 + v41) & M32L

def test_key32(key32):
    """test a 32B candidate as Emitter/Proc key; returns (escore, pscore)"""
    ctE = _load_ct()['Emitter']; ctP = _load_ct()['Proc']
    kdw = struct.unpack('<8I', key32)
    # emitter: 64 dwords
    st = 0; tok = 0
    ctd = struct.unpack('<64I', ctE)
    for i in range(64):
        st = (st + kdw[i % 8]) & 0xFFFFFFFF
        st = prng_round(st)
        v = st ^ ctd[i]
        tb = v >> 24
        if tb in (4, 6, 0xA, 0x4A): tok += 2
        elif 1 <= tb <= 0x1B: tok += 1
    st = 0; psc = 0
    ctp = struct.unpack('<16I', ctP[:64])
    for i in range(16):
        st = (st + kdw[i % 8]) & 0xFFFFFFFF
        st = prng_round(st)
        v = st ^ ctp[i]
        tb = v >> 24
        if tb == 0 or 0x42 <= tb <= 0x47: psc += 2
        elif tb <= 0x1B: psc += 1
    return tok, psc

B32SEEN = {}
B16SEEN = {}
CANDDIR = os.path.join(OUT, 'b32')
os.makedirs(CANDDIR, exist_ok=True)
def heap_scan(tag):
    """scan MEM_PRIVATE heap for known keys + census of ALL Byte[32] arrays"""
    scans_done[0] += 1
    found = []
    newb32 = 0
    for base, sz in regions_iter():
        step = 0
        CH = 4 * 1024 * 1024
        while step < sz:
            n = min(CH, sz - step)
            data = readmem(base + step, n)
            if not data:
                break
            for kn, K in KEYS.items():
                i = data.find(K)
                while i >= 0:
                    absa = base + step + i
                    if absa not in [h[0] for h in heap_hits]:
                        ctx_lo = max(0, i - 4096)
                        blob = data[ctx_lo:i + 4096]
                        fn = os.path.join(OUT, 'keyhit_%s_0x%x.bin' % (kn, absa))
                        open(fn, 'wb').write(blob)
                        # managed array header check: [MT 8][count 4][pad 4][data +16]
                        hdr = data[i-16:i] if i >= 16 else b''
                        cnt = struct.unpack_from('<I', hdr, 12)[0] if len(hdr) == 16 else -1
                        heap_hits.append((absa, kn, cnt))
                        P('  HEAP-HIT %s @0x%x (hdr cnt=%d) ctx->%s' % (kn, absa, cnt, os.path.basename(fn)))
                        found.append(absa)
                    i = data.find(K, i + 1)
            step += n
        # Byte[32] census: MT + count 0x20
        step = 0
        while step < sz:
            n = min(CH, sz - step)
            data = readmem(base + step, n)
            if not data:
                break
            j = 0
            MT = bytes.fromhex('48589e7cfc7f0000')
            while True:
                j = data.find(MT + b'\x20\x00\x00\x00', j)
                if j < 0 or j + 16 + 32 > len(data):
                    break
                blob = data[j+16:j+48]
                h = hash(blob)
                if h not in B32SEEN and blob.count(0) < 24:
                    B32SEEN[h] = (blob, base + step + j, tag)
                    newb32 += 1
                    open(os.path.join(CANDDIR, 'b32_%04d_%s.bin' % (len(B32SEEN), blob.hex()[:12])), 'wb').write(blob)
                j += 1
            step += n
    if newb32:
        P('  b32-census: %d new Byte[32] candidates (total %d)' % (newb32, len(B32SEEN)))
        for h, (blob, addr, tg) in list(B32SEEN.items()):
            if h not in getattr(heap_scan, 'tested', set()):
                if not hasattr(heap_scan, 'tested'): heap_scan.tested = set()
                heap_scan.tested.add(h)
                eS, pS = test_key32(blob)
                if eS >= 60 or pS >= 22:
                    P('  *** KEY CANDIDATE STRONG E=%d/128 P=%d/32 @0x%x %s -> %s' % (eS, pS, addr, tg, blob.hex()))
                    open(os.path.join(OUT, 'CANDIDATE_%s.bin' % blob.hex()[:16]), 'wb').write(blob)
    return found

def dump_frame(ctx, tag):
    """full stack window + chase array pointers"""
    global snap_count
    rbp = ctx.Rbp
    P('== SNAP %s rip=0x%x rbp=0x%x ==' % (tag, ctx.Rip, rbp))
    win = readmem(rbp - 0x800, 0x880)
    open(os.path.join(OUT, 'snap%02d_stack.bin' % snap_count), 'wb').write(win)
    slots = {}
    for off in range(0, len(win) - 8, 8):
        ptr = struct.unpack_from('<Q', win, off)[0]
        if 0x10000 < ptr < 0x7FFE00000000 and ptr & 7 == 0:
            hdr = readmem(ptr, 0x10)
            if len(hdr) == 0x10:
                cnt = struct.unpack_from('<I', hdr, 8)[0]
                mt = struct.unpack_from('<Q', hdr, 0)[0]
                if 0 < cnt <= 0x10000 and mt > 0x10000:
                    data = readmem(ptr + 0x10, min(cnt, 0x10000))
                    if data.count(0) < len(data) - 4:
                        nm = 'o%03x_c%d' % (0x800 - off, cnt)
                        fn = os.path.join(OUT, 'snap%02d_%s.bin' % (snap_count, nm))
                        open(fn, 'wb').write(data)
                        slots[hex(0x800 - off)] = (hex(ptr), cnt, data[:32].hex())
                        P('  [rbp-0x%x] ptr=0x%x cnt=%d head=%s' % (0x800 - off, ptr, cnt, data[:32].hex()))
    json.dump(slots, open(os.path.join(OUT, 'snap%02d.json' % snap_count), 'w'))
    snap_count += 1

ev = DEBUG_EVENT()
exited = False
phase = 1
hitcount = {}
while ev_count_guard := True:
    if time.time() - t0 > 75:
        P('time limit'); break
    if not k32.WaitForDebugEvent(ctypes.byref(ev), 1500):
        continue
    cont = DBG_CONTINUE
    code = ev.dwDebugEventCode
    if code == 3:
        vals = struct.unpack_from('<4Q', ev.u.raw, 0)
        IMAGE_BASE = vals[3]
        P('image base 0x%x' % IMAGE_BASE)
        for rva in GUARD_RVAS:
            if apply_guard(IMAGE_BASE + rva):
                P('guard %s @0x%x' % (RES_NAME[rva], IMAGE_BASE + rva))
    elif code == 1:
        er = ev.u.Exception
        c = er.ExceptionCode
        if c == GUARD_PAGE:
            acc = er.ExceptionInformation[1]
            page = acc & ~0xFFF
            # which resource?
            res = None
            for rva, nm in RES_NAME.items():
                if IMAGE_BASE and page - (IMAGE_BASE + rva) < 0x300000 and page >= IMAGE_BASE + rva - 0x1000:
                    res = nm
                    break
            hitcount[page] = hitcount.get(page, 0) + 1
            unguard(page)
            hThread = k32.OpenThread(0x001F03FF, False, ev.dwThreadId)
            ctx = CONTEXT(); ctx.ContextFlags = 0x100003
            k32.GetThreadContext(hThread, ctypes.byref(ctx))
            P('GUARD HIT %s page=0x%x (n=%d) rip=0x%x' % (res, page, hitcount[page], ctx.Rip))
            dump_frame(ctx, res or 'pg%x' % (page & 0xFFF))
            # decrypt window: heap scan now (throttle: first 3 hits per resource)
            if hitcount[page] <= 3:
                heap_scan('after-%s' % res)
            ctx.EFlags |= 0x100
            k32.SetThreadContext(hThread, ctypes.byref(ctx))
            k32.CloseHandle(hThread)
            pending_ss[ev.dwThreadId] = page
            cont = DBG_CONTINUE
        elif c == SINGLE_STEP:
            page = pending_ss.pop(ev.dwThreadId, None)
            if page is not None:
                g = hitcount.get(page, 0)
                if g <= 40:
                    apply_guard(page, PAGE_READONLY)
            cont = DBG_CONTINUE
        else:
            cont = DBG_EXCEPTION_NOT_HANDLED if (c >> 31) else DBG_CONTINUE
    elif code == 5:
        P('exit process t=%.1f' % (time.time() - t0))
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
        exited = True
        break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

P('elapsed=%.1f snaps=%d heapscans=%d heapHits=%s' % (time.time() - t0, snap_count, scans_done[0], [(hex(a), k, c) for a, k, c in heap_hits]))
if not exited:
    subprocess.run(['taskkill', '/F', '/PID', str(PID)], capture_output=True)
    P('killed own pid')
P('done')
