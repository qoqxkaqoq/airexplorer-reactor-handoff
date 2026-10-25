#!/usr/bin/env python3
# a9_guard7.py — 在解密循环(驱动器+0x6891)命中时 dump 现场数组: [rbp-0x220](key?)/[rbp-0x278](ct)/
# [rbp-0x1f8](out)/[rbp-0x208]/[rbp-0x270] + 局部槽, 直接拿 key 字节。
import ctypes, ctypes.wintypes as wt, os, sys, time, struct, json, subprocess, threading

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
EXEDIR = os.path.join(W, 'localapp_rt')
EXE = os.path.join(EXEDIR, 'AirExplorer.exe')
OUT = os.path.join(W, 'work_a1', 'a9_guard7')
os.makedirs(OUT, exist_ok=True)
k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi
DEBUG_ONLY_THIS_PROCESS = 2
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
GUARD_PAGE = 0x80000001
SINGLE_STEP = 0x80000004
PAGE_GUARD_F = 0x100
PAGE_READWRITE = 4

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

LOG = open(os.path.join(OUT, 'log.txt'), 'w', buffering=1)
def P(s):
    print(s, flush=True); LOG.write(s + '\n'); LOG.flush()

envd = os.path.join(OUT, 'env')
for sub in ('a','b', r'a\tmp'): os.makedirs(os.path.join(envd, sub), exist_ok=True)
si = STARTUPINFOW(); si.cb = ctypes.sizeof(si)
pi = PROCESS_INFOW()
cmd = ctypes.create_unicode_buffer(EXE)
ok = k32.CreateProcessW(None, cmd, None, None, False, DEBUG_ONLY_THIS_PROCESS, None, EXEDIR, ctypes.byref(si), ctypes.byref(pi))
assert ok
hProc, PID = pi.hProcess, pi.dwProcessId
P('pid %d' % PID)

IMAGE_BASE = None
guards = {}
pending_ss = {}
memcpy_rips = set()
phase = 1
dst_pages = set()
guard_counts = {}
DRIVER_BASE = None
snap_count = 0
t0 = time.time()
ev_count = 0
MAXEVT = 500000
RES_RVA0 = 0x623000
VCR_LO, VCR_HI = 0x7ffc7fda0000, 0x7ffc7fdbd000

def readmem(a, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t()
    ok2 = k32.ReadProcessMemory(hProc, ctypes.c_void_p(a), buf, n, ctypes.byref(got))
    return buf.raw[:got.value] if ok2 and got.value else b''

def find_driver_base():
    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                    ("AllocationProtect", wt.DWORD), ("_p", wt.DWORD), ("RegionSize", ctypes.c_uint64),
                    ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]
    m = MBI()
    addr = 0
    best = None
    while addr < 0x7FFFFFFEFFFF:
        r = k32.VirtualQueryEx(hProc, ctypes.c_void_p(addr), ctypes.byref(m), ctypes.sizeof(m))
        if not r: addr += 0x1000; continue
        sz = int(m.RegionSize)
        if m.State == 0x1000 and m.Type == 0x20000 and (m.Protect & 0xF0):
            # driver region: contains jmp-table dispatcher code at +0x15cb — probe bytes 15 cb pattern
            probe = readmem(m.BaseAddress + 0x15c1, 8)
            if len(probe) == 8 and probe[0:2] == b'\x3b\xff' or (probe[1:3] == b'\x81\xf9'):
                pass
            # better probe: read +0x15cb..0x15d5 compare with known dispatcher bytes
            disp = readmem(m.BaseAddress + 0x15cb, 0x10)
            if len(disp) == 0x10 and disp[:6] == bytes.fromhex('81ff700200'):
                best = m.BaseAddress
                break
            # fallback: match mov edi,0x212; cmp edi,0x270 pattern = bf 12 02 00 00 / 81 ff 70 02 00 00
            d2 = readmem(m.BaseAddress + 0x1590, 0x40)
            if b'\xbf\x12\x02\x00\x00' in d2 or b'\xbe\xb8\xb4\x6f\x68' in d2:
                best = m.BaseAddress
                break
        addr = int(m.BaseAddress) + (sz if sz else 0x1000)
    return best

def mod_of(a):
    if VCR_LO <= a < VCR_HI: return 'VCR'
    return 'DYN'

def apply_guard(page, prot=2):
    old = wt.DWORD()
    if k32.VirtualProtectEx(hProc, ctypes.c_void_p(page), 0x1000, prot | PAGE_GUARD_F, ctypes.byref(old)):
        guards[page] = (old.value, prot)
        return True
    return False

def unguard(page):
    g = guards.pop(page, None)
    if g:
        k32.VirtualProtectEx(hProc, ctypes.c_void_p(page), 0x1000, g[0], None)

def dump_arrays(ctx, tag):
    global snap_count
    rbp = ctx.Rbp
    P('== SNAPSHOT %s rip=0x%x ==' % (tag, ctx.Rip))
    slots = {-0x220: 'arr220', -0x278: 'arr278', -0x1f8: 'arr1f8', -0x208: 'arr208',
             -0x270: 'arr270', -0x230: 'arr230', -0x210: 'arr210'}
    out = {}
    for off, nm in slots.items():
        ptr = struct.unpack_from('<Q', readmem(rbp + off, 8), 0)[0] if len(readmem(rbp + off, 8)) == 8 else 0
        if 0x10000 < ptr < 0x7FFE00000000:
            hdr = readmem(ptr, 0x10)
            if len(hdr) == 0x10:
                cnt = struct.unpack_from('<I', hdr, 8)[0]
                if 0 < cnt <= 0x400000:
                    data = readmem(ptr + 0x10, min(cnt, 0x4000))
                    open(os.path.join(OUT, 'snap%02d_%s.bin' % (snap_count, nm)), 'wb').write(data)
                    out[nm] = (hex(ptr), cnt, data[:24].hex())
                    P('  %s ptr=0x%x count=0x%x head=%s' % (nm, ptr, cnt, data[:24].hex()))
    for off, nm in [(-0x3c, 'v3c'), (-0x5c, 'v5c'), (-0x12c, 'v12c'), (-0x16c, 'v16c'), (-0x4c, 'v4c')]:
        d = readmem(rbp + off, 4)
        if len(d) == 4:
            P('  %s = 0x%08x' % (nm, struct.unpack_from('<I', d, 0)[0]))
    P('  rsi=0x%x rdi=0x%x rbx=0x%x r10=0x%x' % (ctx.Rsi, ctx.Rdi, ctx.Rbx, ctx.R10))
    json.dump(out, open(os.path.join(OUT, 'snap%02d.json' % snap_count), 'w'))
    snap_count += 1

ev = DEBUG_EVENT()
exited = False
phase1_hits = 0
while ev_count < MAXEVT and time.time() - t0 < 70 and not exited:
    if not k32.WaitForDebugEvent(ctypes.byref(ev), 2500):
        P('wait timeout'); break
    ev_count += 1
    code = ev.dwDebugEventCode
    cont = DBG_CONTINUE
    if code == 3:
        vals = struct.unpack_from('<4Q', ev.u.raw, 0)
        IMAGE_BASE = vals[3]
        P('image base 0x%x' % IMAGE_BASE)
        apply_guard(IMAGE_BASE + RES_RVA0)
        P('phase1 guard RVA 0x%x' % RES_RVA0)
    elif code == 1:
        er = ev.u.Exception
        c = er.ExceptionCode
        if c == GUARD_PAGE:
            acc = er.ExceptionInformation[1]
            rw = er.ExceptionInformation[0]
            page = acc & ~0xFFF
            unguard(page)
            hThread = k32.OpenThread(0x001F03FF, False, ev.dwThreadId)
            ctx = CONTEXT(); ctx.ContextFlags = 0x100003
            k32.GetThreadContext(hThread, ctypes.byref(ctx))
            rip = ctx.Rip
            is_vcr = (VCR_LO <= rip < VCR_HI)
            if phase == 1:
                phase1_hits += 1
                if is_vcr:
                    memcpy_rips.add(rip)
                    dstp = ctx.Rdi & ~0xFFF
                    if 0x10000 < dstp < 0x7FFE00000000:
                        dst_pages.add(dstp)
                    if dst_pages:
                        # find driver base now (driver born by the time resource is copied? maybe not yet)
                        phase = 2
                        for pg in list(guards): unguard(pg)
                        for pg in sorted(dst_pages)[:48]:
                            apply_guard(pg, PAGE_READWRITE)
                        P('== PHASE2 guards on %d pages ==' % len(guards))
                ctx.EFlags |= 0x100
                k32.SetThreadContext(hThread, ctypes.byref(ctx))
                k32.CloseHandle(hThread)
                pending_ss[ev.dwThreadId] = ('res', page)
            else:
                if is_vcr or rip in memcpy_rips:
                    dstp = ctx.Rdi & ~0xFFF
                    if dstp and dstp not in dst_pages and len(dst_pages) < 64:
                        dst_pages.add(dstp)
                        apply_guard(dstp, PAGE_READWRITE)
                    ctx.EFlags |= 0x100
                    k32.SetThreadContext(hThread, ctypes.byref(ctx))
                    k32.CloseHandle(hThread)
                    pending_ss[ev.dwThreadId] = ('follow', page)
                else:
                    # driver consumer hit
                    if DRIVER_BASE is None:
                        DRIVER_BASE = find_driver_base()
                        P('driver base = %s' % (hex(DRIVER_BASE) if DRIVER_BASE else 'NOT FOUND'))
                    if DRIVER_BASE:
                        rel = rip - DRIVER_BASE
                        P('consumer hit rel=+0x%x (snap_count=%d)' % (rel, snap_count))
                        if rel in (0x6891, 0x208b, 0x6964, 0x69a5) and snap_count < 12:
                            dump_arrays(ctx, 'rel0x%x' % rel)
                    ctx.EFlags |= 0x100
                    k32.SetThreadContext(hThread, ctypes.byref(ctx))
                    k32.CloseHandle(hThread)
                    pending_ss[ev.dwThreadId] = ('reguard', page)
                cont = DBG_CONTINUE
        elif c == SINGLE_STEP:
            act = pending_ss.pop(ev.dwThreadId, None)
            if act:
                _, page = act
                g = guard_counts.get(page, 0)
                if g < 1500:
                    guard_counts[page] = g + 1
                    prot = 2 if act[0] == 'res' else PAGE_READWRITE
                    apply_guard(page, prot)
            cont = DBG_CONTINUE
        else:
            cont = DBG_EXCEPTION_NOT_HANDLED if (c >> 31) else DBG_CONTINUE
    elif code == 5:
        P('exit process'); k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE); exited = True; break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

P('events=%d elapsed=%.1f snaps=%d' % (ev_count, time.time()-t0, snap_count))
subprocess.run(['taskkill', '/F', '/PID', str(PID)], capture_output=True)
P('done')
