#!/usr/bin/env python3
# Full decrypt with conv.u8 sign/zero-extend grid; find first divergent word.
import struct
M32 = 0xFFFFFFFF
U64 = (1<<64) - 1
def i32(x): x &= M32; return x - (1<<32) if x >= (1<<31) else x
def u32(x): return x & M32

K1 = 506503628
K1B = u32(1610158714 + 1328951073 - 1267867220)
K2 = 1959015338
K3 = 854276594
K4 = 41684485

data = open('res_CollectorTransaction.ValidatorProject.bin','rb').read()
n = len(data)//4

def ext(prod, sign):
    # conv.u8 from int32
    if sign:
        s = prod - (1<<32) if prod >= (1<<31) else prod
        return s & U64
    return prod & M32

def run(sign1, sign2):
    v9 = 0
    ks = []
    for w in range(n):
        v41 = u32(v9)
        prod = i32((K1 * v41) & M32)
        v43u = ext(prod, sign1)
        if v43u == 0: v43u = U64
        k3s = i32((K3*K3) & M32)
        k3u = ext(k3s, sign2)
        v40 = u32(k3u % v43u)
        v45 = u32(u32((K2 >> 9) | ((K2 << 23) & M32)) + v9)
        v39 = u32(((v45 & 0xAAAAAAAA) >> 1) | ((v45 & 0x55555555) << 1))
        v38 = K1B
        v41x = v41 if v41 != 0 else M32
        v44 = u32((v40 // v41x) + v41x)
        v = u32(u32(u32(v40+v40) - v44) + v40)
        v45 = u32(u32(((K4 << 10) & M32) | (K4 >> 22)) + v40)
        v42 = u32(((v45 & 0xFF00FF00) >> 8) | ((v45 & 0x00FF00FF) << 8))
        v = u32(v ^ (v >> 3))
        v = u32(v + v38)
        v = u32(v ^ ((v << 7) & M32))
        v = u32(v + v)
        v = u32(v ^ (v >> 29))
        v = u32(v + v42)
        v = u32(v + u32(u32(((v39 << 4) & M32) - v40) ^ v38))
        v9 = u32(v9 + v)
        ks.append(v9)
    return ks

def pattern_ok(w, p):
    if w % 2 == 0:
        return 0x04000000 <= p < 0x05000000
    top = p >> 24
    return top in (0x06, 0x46, 0x0A, 0x4A, 0x2B, 0x6A)

for sign1 in (True, False):
    for sign2 in (True, False):
        ks = run(sign1, sign2)
        # first bad word
        bad = None
        fl = 0
        for w in range(n):
            pw = u32(ks[w] ^ struct.unpack_from('<I', data, w*4)[0])
            if w % 2 == 0 and 0x04000000 <= pw < 0x05000000: fl += 1
            if bad is None and not pattern_ok(w, pw): bad = w
        print(f'sign1={sign1} sign2={sign2}: field-like={fl}/{n//2} first-bad-word={bad}')
        if bad is not None and bad < 8:
            ks2 = ks[:bad+2]
            for w in range(min(bad+2, 8)):
                pw = u32(ks2[w] ^ struct.unpack_from('<I', data, w*4)[0])
                print(f'   w{w}: {pw:08X}')
