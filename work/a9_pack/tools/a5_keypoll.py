#!/usr/bin/env python3
# a5_keypoll.py — launch AirExplorer, poll the K/A/B tail page (RVA 0x9298A0..0x929BA4)
# at high frequency from process start; record every distinct value; then test each
# candidate (K,A) pair against the Necrobit stream (AES-256-CBC).
import ctypes, ctypes.wintypes as wt, os, sys, time, struct, subprocess, hashlib
from Crypto.Cipher import AES

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
EXEDIR = os.path.join(W, 'localapp_rt')
EXE = os.path.join(EXEDIR, 'AirExplorer.exe')
OUT = os.path.join(W, 'work_a1', 'a5_keypoll')
os.makedirs(OUT, exist_ok=True)

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
psapi = ctypes.windll.psapi

f = open(W + r'\airexplorer-reactor-handoff\exes\AirExplorer_baseline_verified.exe', 'rb').read()
K_FILE = f[0x9298C8:0x9298C8+32]
A_FILE = f[0x929A28:0x929A28+16]
B_FILE = f[0x929A38:0x929A38+32]

def module_base(h):
    LIST_MODULES_ALL = 0x03
    need = wt.DWORD(0)
    psapi.EnumProcessModulesEx(h, None, 0, ctypes.byref(need), LIST_MODULES_ALL)
    cnt = need.value // 8
    mods = (ctypes.c_uint64 * cnt)()
    got = wt.DWORD()
    psapi.EnumProcessModulesEx(h, ctypes.byref(mods), ctypes.sizeof(mods), ctypes.byref(got), LIST_MODULES_ALL)
    return mods[0]

def main():
    env = dict(os.environ)
    envd = os.path.join(OUT, 'env')
    env['APPDATA'] = envd + r'\a'
    env['LOCALAPPDATA'] = envd + r'\b'
    env['TMP'] = envd + r'\a\tmp'
    env['TEMP'] = envd + r'\a\tmp'
    for sub in ('a', 'b', r'a\tmp'):
        os.makedirs(os.path.join(envd, sub), exist_ok=True)
    p = subprocess.Popen([EXE], cwd=EXEDIR, env=env)
    print('pid', p.pid, flush=True)
    h = None
    base = None
    seen = {}
    t0 = time.time()
    buf = ctypes.create_string_buffer(0x304)
    got = ctypes.c_size_t(0)
    # RVA of tail region: file 0x9298A0 -> rva 0x9296A0
    RVA0 = 0x92A000 + (0x9298A0 - 0x927E00)  # sec2: rva 0x92a000 <- file 0x927e00 -> RVA0=0x92BAA0
    polls = 0
    while time.time() - t0 < 30:
        if h is None or base is None:
            if h is None:
                h = k32.OpenProcess(0x041F, False, p.pid)
                if not h:
                    time.sleep(0.005)
                    continue
            rc = p.poll()
            if rc is not None:
                print('early exit', hex(rc)); break
            try:
                base = module_base(h)
            except Exception:
                time.sleep(0.005)
                continue
            print('module base', hex(base), flush=True)
        ok = k32.ReadProcessMemory(h, ctypes.c_void_p(base + RVA0), buf, 0x304, ctypes.byref(got))
        if ok and got.value == 0x304:
            data = buf.raw
            polls += 1
            key = data[:0x304]
            if key not in seen:
                seen[key] = (time.time() - t0, polls)
        else:
            # process may have exited
            if p.poll() is not None:
                print('exit', hex(p.poll() & 0xFFFFFFFF), 'polls', polls); break
        time.sleep(0.004)
    print('polls=%d distinct=%d elapsed=%.1f' % (polls, len(seen), time.time() - t0), flush=True)
    alive = p.poll() is None
    if alive: p.kill()
    time.sleep(1)
    subprocess.run(['taskkill', '/F', '/IM', 'AirExplorer.exe'], capture_output=True)

    # save distinct snapshots
    snaps = []
    for i, (key, (ts, pl)) in enumerate(sorted(seen.items(), key=lambda kv: kv[1][0])):
        fn = os.path.join(OUT, 'snap_%02d.bin' % i)
        open(fn, 'wb').write(key)
        snaps.append((fn, ts, pl))
        k = key[0x28:0x28+32]
        a = key[0x188:0x188+16]
        b = key[0x198:0x198+32]
        print('snap %02d t=%.3f K=%s A=%s K==file:%s A==file:%s' % (i, ts, k.hex()[:32], a.hex(), k == K_FILE, a == A_FILE))

    # sha256 oracle verification (a6): K_orig sha256=4BED3ADC.., A_orig sha256=97E613E5..
    KO = bytes.fromhex('4BED3ADC52D4904075F6BBF279EC4ACEDE079533B95E229A29809542EA324A7B')
    AO = bytes.fromhex('97E613E5A3A47DEC76B7E50D47644B35EA4322F00D594D80D2F1C1F3644F8A4A')
    for i, (key, ts, pl) in enumerate(snaps):
        k = key[0x28:0x28+32]; a = key[0x188:0x188+16]
        if hashlib.sha256(k).hexdigest().upper() == KO.hex().upper():
            print('*** ORACLE HIT K at snap %02d t=%.3f' % (i, ts))
        if hashlib.sha256(a).hexdigest().upper() == AO.hex().upper():
            print('*** ORACLE HIT A at snap %02d t=%.3f' % (i, ts))
    # test each distinct (K,A) pair against the resource payload
    blob = f[0x6213C0:0x6213C0 + 0x30510C]
    payload = blob[4:]
    targets = [(0, 'ErrReceiver'), (0x56FEC - 4 + 4, 'EmitterRep'), (0x570F0 + 4, 'ValidatorProc'),
               (0x62C1F + 4, 'ValidatorProject'), (0x69233 + 4, 'DefinitionError'), (0x2A3B3E + 4, 'FactoryValidator')]
    def looks_good(pt):
        if pt[:2] in (b'\x78\x9c', b'\x78\xda', b'\x78\x01'): return 'zlib'
        if pt[:2] == b'MZ': return 'MZ'
        if pt[:4] == b'\xce\xca\xef\xbe': return 'BEEF'
        if (pt[0] & 3) == 2 and 0 < (pt[0] >> 2) <= 64: return 'tiny'
        return None
    hits = 0
    for i, (key, ts, pl) in enumerate(snaps):
        k = key[0x28:0x28+32]
        a = key[0x188:0x188+16]
        if k == K_FILE and a == A_FILE:
            continue
        try:
            c = AES.new(k, AES.MODE_CBC, a)
        except Exception:
            continue
        for off, nm in targets:
            try:
                pt = c.decrypt(payload[off:off+64])
            except Exception:
                continue
            g = looks_good(pt)
            if g:
                hits += 1
                print('CANDIDATE HIT snap %02d (%.3fs) %s %s: %s' % (i, ts, nm, g, pt[:24].hex(' ')))
    print('candidate hits:', hits)

if __name__ == '__main__':
    main()
