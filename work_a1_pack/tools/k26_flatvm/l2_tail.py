#!/usr/bin/env python3
# l2_tail.py — Lead 2: K_FILE/A_FILE/B_FILE transforms -> known keys / direct Proc+Emitter keys
import sys, os, struct, binascii, itertools
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aot
from Crypto.Cipher import AES

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
K_FILE = open(W + r'\work_a1\k26\K_FILE.bin', 'rb').read()
A_FILE = open(W + r'\work_a1\k26\A_FILE.bin', 'rb').read()
B_FILE = open(W + r'\work_a1\k26\B_FILE.bin', 'rb').read()

KV = binascii.unhexlify('f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943')
KM = binascii.unhexlify('cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481')
KF = binascii.unhexlify('37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a')
KNOWN = {'Viewer': KV, 'mainlib': KM, 'Factory': KF}

ctE = aot.res_ct('Emitter')
ctP = aot.res_ct('Proc')

def tokens_ok(pt):
    """Emitter-style delegate table: dwords look like metadata tokens 0xTT000000+smallrow"""
    if len(pt) < 16: return False
    dw = struct.unpack('<%dI' % (len(pt) // 4), pt[:len(pt) // 4 * 4])
    ok = 0
    for v in dw:
        tb = v >> 24
        if 0x01 <= tb <= 0x1B and (v & 0xFFFFFF) < 0x400000:
            ok += 1
    return ok >= len(dw) - 1 and ok >= 4

def proc_ok(pt):
    """Proc-style table: presence of small ints and repeated-high-family dwords"""
    if len(pt) < 32: return False
    dw = struct.unpack('<%dI' % (len(pt) // 4), pt[:len(pt) // 4 * 4])
    small = sum(1 for v in dw if v < 0x01000000)
    return small >= len(dw) // 2

def report(tag, pt):
    interesting = tokens_ok(pt) or proc_ok(pt)
    if interesting:
        print('*** STRUCT', tag, pt[:48].hex())
    return interesting

print('=== 2a: AES transforms of tail blocks ===')
cands_keys = {}
res = []
def try_aes(name, key, data):
    for mode in ('ECB', 'CBC'):
        for op in ('dec', 'enc'):
            try:
                if mode == 'ECB':
                    c = AES.new(key, AES.MODE_ECB)
                else:
                    c = AES.new(key, AES.MODE_CBC, iv=bytes(16))
                out = c.decrypt(data) if op == 'dec' else c.encrypt(data)
            except Exception:
                continue
            res.append((name, mode, op, out))
            if out[:32] in (KV, KM, KF) or out[-32:] in (KV, KM, KF):
                print('*** AES KEY HIT', name, mode, op, out.hex())
            report('aes %s %s %s -> 32B' % (name, mode, op), out[:32])

for kn, K in (('K_FILE', K_FILE), ('B_FILE', B_FILE)):
    for dn, D in (('A_FILE', A_FILE), ('B1', B_FILE[:16]), ('B2', B_FILE[16:32]), ('K1', K_FILE[:16]), ('K2', K_FILE[16:32])):
        try_aes('%s(%s)' % (kn, dn), K, D)
for an, A in (('A_FILE', A_FILE), ('A_r', A_FILE[::-1]), ('K1', K_FILE[:16]), ('K2', K_FILE[16:32])):
    try_aes('%s(K_FILE)' % an, A, K_FILE)
    try_aes('%s(B_FILE)' % an, A, B_FILE)
print('aes transforms:', len(res))

print('=== 2b: tail material as DIRECT resource keys ===')
direct = {
    'K_FILE': K_FILE, 'B_FILE': B_FILE,
    'A+A': A_FILE * 2, 'A+K16': A_FILE + K_FILE[:16], 'A+B16': A_FILE + B_FILE[:16],
    'K^B': bytes(a ^ b for a, b in zip(K_FILE, B_FILE)),
    'K^A16': bytes(a ^ b for a, b in zip(K_FILE[:16], A_FILE)) * 2,
    'K+A16': K_FILE[:16] + A_FILE + K_FILE[16:24] + A_FILE,
    'K_rev': K_FILE[::-1], 'B_rev': B_FILE[::-1],
    'K+B16': K_FILE[:16] + B_FILE[:16] + K_FILE[16:] + B_FILE[16:24],
}
for nm, key in direct.items():
    if len(key) != 32:
        continue
    pE = aot.decrypt(ctE, key)
    pP = aot.decrypt(ctP[:64], key)
    r1 = report('Emitter key=' + nm, pE)
    r2 = report('Proc64 key=' + nm, pP)
    if r1 or r2:
        print(nm, 'E:', pE[:32].hex(), ' P:', pP[:32].hex())

print('=== 2c: prng keystream from tail material ===')
ks8 = struct.pack('<8I', *aot.keystream_keyed(8, K_FILE))
print('keystream(K_FILE)[:32] =', ks8.hex(), 'known?', ks8 in (KV, KM, KF))
ks8b = struct.pack('<8I', *aot.keystream_keyed(8, B_FILE))
print('keystream(B_FILE)[:32] =', ks8b.hex(), 'known?', ks8b in (KV, KM, KF))
# A_FILE dwords through prng chain
adw = struct.unpack('<4I', A_FILE)
st = 0; outs = []
for i in range(8):
    st = aot.prng_round((st + adw[i % 4]) & 0xFFFFFFFF)
    outs.append(st)
print('A_FILE-fed chain:', struct.pack('<8I', *outs).hex(), 'known?', struct.pack('<8I', *outs) in (KV, KM, KF))
print('done')
