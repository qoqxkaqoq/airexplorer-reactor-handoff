#!/usr/bin/env python3
# l6_heap.py — Lead 6 (+5): heap candidate keys vs Emitter/Proc structure; key-material search everywhere
import sys, os, struct, pickle, binascii, re, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aot

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
KV = binascii.unhexlify('f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943')
KM = binascii.unhexlify('cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481')
KF = binascii.unhexlify('37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a')
KZ = bytes(32)
K_FILE = open(W + r'\work_a1\k26\K_FILE.bin', 'rb').read()
A_FILE = open(W + r'\work_a1\k26\A_FILE.bin', 'rb').read()
B_FILE = open(W + r'\work_a1\k26\B_FILE.bin', 'rb').read()

ctE = aot.res_ct('Emitter')
ctP = aot.res_ct('Proc')

def em_score(pt):
    dw = struct.unpack('<64I', pt)
    s = 0
    for v in dw:
        tb = v >> 24
        if tb in (0x04, 0x06, 0x0A, 0x4A): s += 2
        elif 0x01 <= tb <= 0x1B: s += 1
    return s

def pr_score(pt):
    dw = struct.unpack('<16I', pt)
    s = 0
    for v in dw:
        tb = v >> 24
        if tb == 0: s += 2
        elif 0x42 <= tb <= 0x47: s += 2
        elif tb <= 0x1B: s += 1
    return s

print('=== 6a: small.pkl heap candidates vs Emitter/Proc ===')
small = pickle.load(open(W + r'\work_a1\a9_incept3\small.pkl', 'rb'))
print('small arrays:', len(small))
cands = 0
bestE, bestP = [], []
for addr, cnt, data in small:
    if cnt < 32: continue
    offs = range(0, cnt - 31, 4) if cnt <= 512 else range(0, cnt - 31, 4)
    for o in offs:
        key = data[o:o+32]
        if key.count(0) >= 30: continue
        cands += 1
        pE = aot.decrypt(ctE, key)
        sE = em_score(pE)
        if sE >= 96: bestE.append((sE, addr, o, key.hex(), pE[:32].hex()))
        pP = aot.decrypt(ctP[:64], key)
        sP = pr_score(pP)
        if sP >= 30: bestP.append((sP, addr, o, key.hex(), pP[:32].hex()))
print('candidates tested:', cands)
print('Emitter score>=96/128:', len(bestE))
for b in sorted(bestE, reverse=True)[:10]: print('  E', b)
print('Proc score>=30/32:', len(bestP))
for b in sorted(bestP, reverse=True)[:10]: print('  P', b)

print('=== 6b: raw key material in memory dumps ===')
files = []
for pat in (W + r'\work_a1\a9_incept3\*.bin', W + r'\work_a1\rtdump*\*', W + r'\memdump\*', W + r'\work_a1\mapped_image.bin'):
    files += glob.glob(pat)
print('dump files:', len(files))
needles = {'KV': KV, 'KM': KM, 'KF': KF, 'K_FILE': K_FILE, 'A_FILE': A_FILE, 'B_FILE': B_FILE}
for f in files:
    try:
        if os.path.getsize(f) > 400 * 1024 * 1024: continue
        d = open(f, 'rb').read()
    except Exception:
        continue
    hits = []
    for nm, nd in needles.items():
        c = d.count(nd)
        if c: hits.append('%s x%d' % (nm, c))
    if hits:
        print(' ', os.path.basename(f), os.path.getsize(f), hits)

print('=== lead 5: key-shaped strings & byte forms in plaintexts/exe ===')
def searches(name, d):
    out = []
    for nm, k in (('KV', KV), ('KM', KM), ('KF', KF)):
        hx = k.hex().encode()
        if d.find(hx) >= 0: out.append('%s-hex-ascii' % nm)
        if d.find(hx.upper()) >= 0: out.append('%s-HEX-ascii' % nm)
        u = k.hex().encode('utf-16-le')
        if d.find(u) >= 0: out.append('%s-hex-utf16' % nm)
        if d.find(k) >= 0: out.append('%s-raw' % nm)
        # per-dword LE 4-byte sequence
        for i in range(8):
            dw = k[i*4:i*4+4]
            if d.count(dw) and d.find(dw) >= 0:
                out.append('%s-dw%d-LE4@%d' % (nm, i, d.find(dw)))
                break
        # ldc.i4 imm pattern: 0x20 + LE dword
        for i in range(8):
            pat = b'\x20' + k[i*4:i*4+4]
            j = d.find(pat)
            if j >= 0:
                out.append('%s-ldci4-dw%d@0x%x' % (nm, i, j))
                break
    return out

targets = {
    'exe': aot.exe_bytes(),
    'dec_Viewer': open(W + r'\work_a1\dec_Viewer.bin', 'rb').read(),
    'mainlib_plain': open(W + r'\work_a1\mainlib_plain.bin', 'rb').read(),
    'dec_FactoryValidator': open(W + r'\work_a1\dec_FactoryValidator.bin', 'rb').read(),
    'zdec_Project': open(W + r'\work_a1\zdec\Project.bin', 'rb').read(),
}
for p in glob.glob(W + r'\work_a1\mlres\*'):
    try: targets['mlres:' + os.path.basename(p)] = open(p, 'rb').read()
    except Exception: pass

for nm, d in targets.items():
    r = searches(nm, d)
    if r: print(nm, '->', r[:20])
print('any-64hexchar scan in dec_FactoryValidator/mainlib_plain:')
for nm in ('dec_FactoryValidator', 'mainlib_plain'):
    d = targets[nm]
    txt = d.decode('utf-16-le', 'ignore')
    hs = re.findall(r'[0-9a-fA-F]{64}', txt)
    print(' ', nm, 'utf16 64-hex runs:', hs[:10], 'count', len(hs))
    hs2 = re.findall(rb'[0-9a-fA-F]{64}', d)
    print(' ', nm, 'ascii 64-hex runs:', [h[:20] for h in hs2[:10]], 'count', len(hs2))
print('done')
