#!/usr/bin/env python3
# a9_guard17.py — 篡改版 exe 创建即调试: 不下任何 guard, 等崩溃异常事件 → 抓全线程栈+regs+驱动器dump.
# 崩溃栈 = native 校验器调用链真身.
import ctypes, ctypes.wintypes as wt, os, sys, time, struct, subprocess, threading

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
EXEDIR = os.path.join(W, 'localapp_crash')
EXE = os.path.join(EXEDIR, 'AirExplorer.exe')
OUT = os.path.join(W, 'work_a1', 'a9_guard17')
os.makedirs(OUT, exist_ok=True)
k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi
DEBUG_ONLY_THIS_PROCESS = 2
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

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
P('pid %d (tampered exe)' % PID)

IMAGE_BASE = None
MODULES = []
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
    return 'DYN?0x%x' % a

def dump_thread_stack(tid, tag):
    hT = k32.OpenThread(0x001F03FF, False, tid)
    if not hT:
        P('  thread %d open fail' % tid); return
    ctx = CONTEXT(); ctx.ContextFlags = 0x100003
    if not k32.GetThreadContext(hT, ctypes.byref(ctx)):
        P('  thread %d ctx fail' % tid); k32.CloseHandle(hT); return
    P('== THREAD %d (%s) rip=%s (%s) ==' % (tid, tag, hex(ctx.Rip), mod_of(ctx.Rip)))
    P('  regs rcx=0x%x rdx=0x%x r8=0x%x r9=0x%x rsi=0x%x rdi=0x%x' % (
        ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9, ctx.Rsi, ctx.Rdi))
    st = readmem(ctx.Rsp, 0x400)
    if st:
        words = [struct.unpack_from('<Q', st, i)[0] for i in range(0, len(st)-7, 8)]
        for i, w in enumerate(words[:40]):
            if w > 0x10000:
                P('  [rsp+0x%02x] 0x%x %s' % (i*8, w, mod_of(w)))
    # rip code dump
    cd = readmem(ctx.Rip - 0x80, 0x180)
    if cd:
        open(os.path.join(OUT, 'code_%s_%d.bin' % (tag, tid)), 'wb').write(cd)
        P('  code dumped')
    k32.CloseHandle(hT)

def dump_all_threads(tag):
    class T32E(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ThreadID", wt.DWORD),
                    ("th32OwnerProcessID", wt.DWORD), ("tpBasePri", wt.LONG), ("tpDeltaPri", wt.LONG),
                    ("dwFlags", wt.DWORD)]
    snap = k32.CreateToolhelp32Snapshot(0x4, PID)
    e = T32E(); e.dwSize = ctypes.sizeof(e)
    if k32.Thread32First(snap, ctypes.byref(e)):
        while True:
            if e.th32OwnerProcessID == PID:
                dump_thread_stack(e.th32ThreadID, tag)
            if not k32.Thread32Next(snap, ctypes.byref(e)):
                break
    k32.CloseHandle(snap)

def dump_dyn(tag):
    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                    ("AllocationProtect", wt.DWORD), ("_p", wt.DWORD), ("RegionSize", ctypes.c_uint64),
                    ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]
    m = MBI()
    addr = 0
    n = 0
    while addr < 0x7FFFFFFEFFFF and n < 80:
        r = k32.VirtualQueryEx(hProc, ctypes.c_void_p(addr), ctypes.byref(m), ctypes.sizeof(m))
        if not r: addr += 0x1000; continue
        sz = int(m.RegionSize)
        if m.State == 0x1000 and m.Type == 0x20000 and (m.Protect & 0xF0) and 0x1000 <= sz <= 0x200000:
            d = readmem(m.BaseAddress, min(sz, 0x100000))
            if d:
                open(os.path.join(OUT, 'dyn_%s_0x%x.bin' % (tag, m.BaseAddress)), 'wb').write(d)
                n += 1
        addr = int(m.BaseAddress) + (sz if sz else 0x1000)
    P('dyn dump (%s): %d' % (tag, n))

ev = DEBUG_EVENT()
t0 = time.time()
exited = False
handled = set()
while time.time() - t0 < 45 and not exited:
    if not k32.WaitForDebugEvent(ctypes.byref(ev), 1500):
        P('wait timeout (no events 1.5s)')
        continue
    code = ev.dwDebugEventCode
    cont = DBG_CONTINUE
    if code == 3:
        vals = struct.unpack_from('<4Q', ev.u.raw, 0)
        IMAGE_BASE = vals[3]
        P('image base 0x%x' % IMAGE_BASE)
        k32.CloseHandle(ctypes.c_void_p(vals[0]))
        def _late():
            time.sleep(1.0); enum_modules(); P('modules: %d' % len(MODULES))
        threading.Thread(target=_late, daemon=True).start()
    elif code == 1:
        er = ev.u.Exception
        c = er.ExceptionCode
        P('EXCEPTION code=0x%08x addr=0x%x tid=%d first=%d' % (c, er.ExceptionAddress, ev.dwThreadId, er.ExceptionInformation[0] if False else 1))
        if c not in handled:
            handled.add(c)
            enum_modules()
            if c == 0x80000003 or c == 0x04242420:
                # dump ALL large private exec regions (JIT land) and search for the pi constant
                import struct as _s
                class MBI2(ctypes.Structure):
                    _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                                ("AllocationProtect", wt.DWORD), ("_p", wt.DWORD), ("RegionSize", ctypes.c_uint64),
                                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]
                mm = MBI2()
                addr = 0
                dumped = 0
                while addr < 0x7FFFFFFEFFFF and dumped < 40:
                    r = k32.VirtualQueryEx(hProc, ctypes.c_void_p(addr), ctypes.byref(mm), ctypes.sizeof(mm))
                    if not r:
                        addr += 0x1000
                        continue
                    sz = int(mm.RegionSize)
                    if mm.State == 0x1000 and mm.Type == 0x20000 and sz >= 0x8000:
                        d = readmem(mm.BaseAddress, sz)
                        if d:
                            fn = os.path.join(OUT, 'exc%08x_exec_0x%x.bin' % (c, mm.BaseAddress))
                            open(fn, 'wb').write(d)
                            # search pi constant
                            for pat, tag in [(bytes.fromhex('27594131'), 'piLE'), (bytes.fromhex('31415927'), 'piBE'),
                                             (bytes.fromhex('20424242'), 'excLE'), (bytes.fromhex('62006200'), 'h620062'),
                                             (bytes.fromhex('d200d400'), 'hd400d2'), (bytes.fromhex('b4000802'), 'h20800b4')]:
                                i = d.find(pat)
                                while i >= 0:
                                    P('  *** %s 0x%x @ %s+0x%x' % (tag, mm.BaseAddress + i, os.path.basename(fn), i))
                                    i = d.find(pat, i + 1)
                            dumped += 1
                    addr = int(mm.BaseAddress) + (sz if sz else 0x1000)
                P('exec regions dumped: %d (exc 0x%08x)' % (dumped, c))
            hT = k32.OpenThread(0x001F03FF, False, ev.dwThreadId)
            if hT:
                ctx = CONTEXT(); ctx.ContextFlags = 0x100003
                k32.GetThreadContext(hT, ctypes.byref(ctx))
                P('== CRASH THREAD %d rip=0x%x (%s) ==' % (ev.dwThreadId, ctx.Rip, mod_of(ctx.Rip)))
                P('  regs rax=0x%x rbx=0x%x rcx=0x%x rdx=0x%x rsi=0x%x rdi=0x%x rbp=0x%x rsp=0x%x' % (
                    ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.Rbp, ctx.Rsp))
                class MBI(ctypes.Structure):
                    _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                                ("AllocationProtect", wt.DWORD), ("_p", wt.DWORD), ("RegionSize", ctypes.c_uint64),
                                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]
                m = MBI()
                for regname, regval in [('rdi', ctx.Rdi), ('rcx', ctx.Rcx), ('rsi', ctx.Rsi), ('rax', ctx.Rax), ('rdx', ctx.Rdx), ('r8', ctx.R8), ('r9', ctx.R9)]:
                    if 0x10000 < regval < 0x7FFE00000000:
                        if k32.VirtualQueryEx(hProc, ctypes.c_void_p(regval), ctypes.byref(m), ctypes.sizeof(m)):
                            base = int(m.BaseAddress) & ~0xFFF
                            sz = min(int(m.RegionSize) + (int(m.BaseAddress)-base), 0x4000000)
                            d = readmem(base, sz)
                            if len(d) > 0x1000:
                                fn = os.path.join(OUT, 'exc%08x_%s_reg_0x%x_%x.bin' % (c, regname, base, len(d)))
                                open(fn, 'wb').write(d)
                                P('  %s region 0x%x +0x%x dumped (%d B) head=%s' % (regname, base, sz, len(d), d[:24].hex()))
                st = readmem(ctx.Rsp, 0x2000)
                if st:
                    open(os.path.join(OUT, 'exc%08x_stack.bin' % c), 'wb').write(st)
                    words = [struct.unpack_from('<Q', st, i)[0] for i in range(0, len(st)-7, 8)]
                    P('  deep stack (first 60 ptrs):')
                    for i, w in enumerate(words[:60]):
                        if w > 0x10000:
                            P('    [rsp+0x%03x] 0x%x %s' % (i*8, w, mod_of(w)))
                rbp = ctx.Rbp
                P('  rbp chain:')
                for _ in range(16):
                    if not (0x10000 < rbp < 0x7FFE00000000):
                        break
                    fr = readmem(rbp, 16)
                    if len(fr) < 16:
                        break
                    nxt, ret = struct.unpack_from('<QQ', fr, 0)
                    P('    rbp=0x%x ret=0x%x %s' % (rbp, ret, mod_of(ret)))
                    if nxt <= rbp:
                        break
                    rbp = nxt
                k32.CloseHandle(hT)
            dump_all_threads('exc%08x' % c)
            dump_dyn('exc')
        # pass exception on (don't swallow) so process dies as it would
        cont = DBG_EXCEPTION_NOT_HANDLED
    elif code == 5:
        P('EXIT PROCESS')
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
        exited = True
        break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

if not exited:
    subprocess.run(['taskkill', '/F', '/PID', str(PID)], capture_output=True)
P('done')
