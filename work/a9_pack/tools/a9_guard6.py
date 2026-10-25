#!/usr/bin/env python3
# a9_guard6.py — 一击必中: phase1 guard 资源头页(RVA 0x623000) 抓 memcpy; 用 rdi(dst, guard2 实测) 定位堆缓冲;
# phase2 对 dst 页 RW guard, 过滤 VCRUNTIME(memcpy) 写命中 — 其余 rip = 解密器/消费者。
import ctypes, ctypes.wintypes as wt, os, sys, time, struct, json, subprocess, threading

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
EXEDIR = os.path.join(W, 'localapp_rt')
EXE = os.path.join(EXEDIR, 'AirExplorer.exe')
OUT = os.path.join(W, 'work_a1', 'a9_guard6')
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
MODULES = []
guards = {}
pending_ss = {}
memcpy_rips = set()      # learned in phase1
ripstats = {}
code_dumped = set()
dyn_dumped = False
phase = 1
dst_pages = set()
t0 = time.time()
ev_count = 0
MAXEVT = 500000
RES_RVA0 = 0x623000
# VCRUNTIME140_CLR0400 range (this boot) for classify; learn exact rips dynamically
VCR_LO, VCR_HI = 0x7ffc7fda0000, 0x7ffc7fdbd000

def readmem(a, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t()
    ok2 = k32.ReadProcessMemory(hProc, ctypes.c_void_p(a), buf, n, ctypes.byref(got))
    return buf.raw[:got.value] if ok2 and got.value else b''

def enum_modules():
    MODULES.clear()
    mods = (ctypes.c_uint64 * 4096)()
    cb = wt.DWORD()
    if psapi.EnumProcessModulesEx(hProc, ctypes.cast(mods, ctypes.c_void_p), ctypes.sizeof(mods), ctypes.byref(cb), 3):
        for i in range(cb.value // 8):
            b = ctypes.create_unicode_buffer(512)
            psapi.GetModuleFileNameExW(hProc, ctypes.c_void_p(mods[i]), b, 512)
            class MBI(ctypes.Structure):
                _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                            ("AllocationProtect", wt.DWORD), ("_p", wt.DWORD), ("RegionSize", ctypes.c_uint64),
                            ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]
            m = MBI()
            k32.VirtualQueryEx(hProc, ctypes.c_void_p(mods[i]), ctypes.byref(m), ctypes.sizeof(m))
            MODULES.append((mods[i], max(int(m.RegionSize), 0x1000), b.value.split('\\')[-1]))

def mod_of(a):
    for b, s, nm in MODULES:
        if b <= a < b + s: return '%s+0x%x' % (nm, a - b)
    if IMAGE_BASE and IMAGE_BASE <= a < IMAGE_BASE + 0x938000:
        return 'IMG+0x%x' % (a - IMAGE_BASE)
    if VCR_LO <= a < VCR_HI: return 'VCRUNTIME+0x%x' % (a - VCR_LO)
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

def dump_dyn(tag):
    global dyn_dumped
    if dyn_dumped: return
    dyn_dumped = True
    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                    ("AllocationProtect", wt.DWORD), ("_p", wt.DWORD), ("RegionSize", ctypes.c_uint64),
                    ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]
    m = MBI()
    addr = 0
    n = 0
    while addr < 0x7FFFFFFEFFFF and n < 60:
        r = k32.VirtualQueryEx(hProc, ctypes.c_void_p(addr), ctypes.byref(m), ctypes.sizeof(m))
        if not r: addr += 0x1000; continue
        sz = int(m.RegionSize)
        if m.State == 0x1000 and m.Type == 0x20000 and (m.Protect & 0xF0) and 0x1000 <= sz <= 0x200000:
            d = readmem(m.BaseAddress, min(sz, 0x100000))
            if d:
                open(os.path.join(OUT, 'dyn_%s_0x%x.bin' % (tag, m.BaseAddress)), 'wb').write(d)
                n += 1
        addr = int(m.BaseAddress) + (sz if sz else 0x1000)
    P('dyn dump (%s): %d regions' % (tag, n))

ev = DEBUG_EVENT()
exited = False
phase1_hits = 0
guard_counts = {}
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
        def _late():
            time.sleep(3.0); enum_modules(); P('modules(late): %d' % len(MODULES))
        threading.Thread(target=_late, daemon=True).start()
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
                    if 0x10000 < dstp < 0x7FFE00000000 and mod_of(dstp) == 'DYN':
                        dst_pages.add(dstp)
                    if dst_pages and phase1_hits >= 1:
                        phase = 2
                        for pg in list(guards):
                            unguard(pg)
                        for pg in sorted(dst_pages)[:48]:
                            apply_guard(pg, PAGE_READWRITE)
                        P('== PHASE2: guards on %d dst pages %s ==' % (len(guards), [hex(p) for p in sorted(dst_pages)[:6]]))
                else:
                    # non-memcpy reader of resource head even in phase1: interesting
                    if rip not in code_dumped:
                        code_dumped.add(rip)
                        cd = readmem(rip - 0x400, 0x800)
                        open(os.path.join(OUT, 'code_p1_rip_0x%x.bin' % rip), 'wb').write(cd)
                        P('P1 non-memcpy rip=0x%x (%s) acc_rva=0x%x' % (rip, mod_of(rip), acc - IMAGE_BASE))
                # re-guard resource page
                ctx.EFlags |= 0x100
                k32.SetThreadContext(hThread, ctypes.byref(ctx))
                k32.CloseHandle(hThread)
                pending_ss[ev.dwThreadId] = ('res', page)
                cont = DBG_CONTINUE
            else:
                if is_vcr or rip in memcpy_rips:
                    # memcpy's own write: follow dst page
                    dstp = ctx.Rdi & ~0xFFF
                    if dstp and dstp not in dst_pages and len(dst_pages) < 64:
                        dst_pages.add(dstp)
                        apply_guard(dstp, PAGE_READWRITE)
                    ripstats[('memcpy', rw)] = ripstats.get(('memcpy', rw), 0) + 1
                    # do not re-guard this page (let memcpy finish); track page for later re-guard
                    ctx.EFlags |= 0x100
                    k32.SetThreadContext(hThread, ctypes.byref(ctx))
                    k32.CloseHandle(hThread)
                    pending_ss[ev.dwThreadId] = ('follow', page)
                else:
                    ripstats[(hex(rip), rw)] = ripstats.get((hex(rip), rw), 0) + 1
                    if rip not in code_dumped:
                        code_dumped.add(rip)
                        cd = readmem(rip - 0x400, 0x800)
                        open(os.path.join(OUT, 'code_consumer_0x%x.bin' % rip), 'wb').write(cd)
                        st = readmem(ctx.Rsp, 0x300)
                        words = [struct.unpack_from('<Q', st, i)[0] for i in range(0, len(st)-7, 8)]
                        P('*** CONSUMER rip=0x%x (%s) rw=%d acc=0x%x rcx=0x%x rdx=0x%x r8=0x%x' % (
                            rip, mod_of(rip), rw, acc, ctx.Rcx, ctx.Rdx, ctx.R8))
                        P('    stack: %s' % ' '.join(mod_of(w) for w in words[:18] if w > 0x10000))
                        dump_dyn('consumer')
                    ctx.EFlags |= 0x100
                    k32.SetThreadContext(hThread, ctypes.byref(ctx))
                    k32.CloseHandle(hThread)
                    pending_ss[ev.dwThreadId] = ('reguard', page)
                cont = DBG_CONTINUE
        elif c == SINGLE_STEP:
            act = pending_ss.pop(ev.dwThreadId, None)
            if act:
                _, page = act
                gcount = guard_counts.get(page, 0)
                if gcount < 1500:
                    guard_counts[page] = gcount + 1
                    if act[0] == 'res':
                        apply_guard(page, 2)
                    elif act[0] in ('follow', 'reguard'):
                        apply_guard(page, PAGE_READWRITE)
            cont = DBG_CONTINUE
        else:
            cont = DBG_EXCEPTION_NOT_HANDLED if (c >> 31) else DBG_CONTINUE
    elif code == 5:
        P('exit process'); k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE); exited = True; break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

P('events=%d elapsed=%.1f phase=%d' % (ev_count, time.time()-t0, phase))
P('== stats ==')
for k, n in sorted(ripstats.items(), key=lambda x: -x[1])[:30]:
    P('  %s x%d' % (k, n))
subprocess.run(['taskkill', '/F', '/PID', str(PID)], capture_output=True)
P('done')
