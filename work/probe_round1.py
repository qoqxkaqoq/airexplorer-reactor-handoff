#!/usr/bin/env python3
# Round-1 probe: v9=0 -> ks[0] must satisfy cipher[0]^ks[0] = field token 0x0400xxxx
import struct
M32 = 0xFFFFFFFF
def i32(x): x &= M32; return x - (1<<32) if x >= (1<<31) else x
def u32(x): return x & M32

K1 = 506503628
K1B = u32(1610158714 + 1328951073 - 1267867220)
K2 = 1959015338
K3 = 854276594
K4 = 41684485

data = open('res_CollectorTransaction.ValidatorProject.bin','rb').read()
c0, c1 = struct.unpack_from('<Ii'[:0] or '<II', data, 0), None
c0 = struct.unpack_from('<I', data, 0)[0]
c1 = struct.unpack_from('<I', data, 4)[0]
print(f'cipher[0]={c0:08X} cipher[1]={c1:08X}')

def round1(conv_u8_sign=True):
    v9 = 0
    v41 = u32(v9)
    prod = i32((K1 * v41) & M32)          # int32 wrap
    if conv_u8_sign:
        v43u = (prod - (1<<64)) & ((1<<64)-1) if prod >= 0 else 0  # dummy
    # conv.u8 semantics: sign-extend int32 -> int64, reinterpret u64
    s64 = prod if prod < (1<<31) else prod - (1<<32)
    v43u = s64 & ((1<<64)-1) if conv_u8_sign else (prod & M32)
    if v43u == 0: v43u = (0-1) & ((1<<64)-1)
    k3s = i32((K3*K3) & M32)
    k3u = (k3s & ((1<<64)-1)) if conv_u8_sign else ((K3*K3) & M32)
    v40 = u32(k3u % v43u)
    v45 = u32(u32((K2 >> 9) | ((K2 << 23) & M32)) + v9)
    v39 = u32(((v45 & 0xAAAAAAAA) >> 1) | ((v45 & 0x55555555) << 1))
    v38 = K1B
    v41x = u32(v41) if v41 != 0 else M32
    v44 = u32((v40 // v41x) + v41x)
    v41b = u32(u32(u32(v40+v40) - v44) + v40)
    v45 = u32(u32(((K4 << 10) & M32) | (K4 >> 22)) + v40)
    v42 = u32(((v45 & 0xFF00FF00) >> 8) | ((v45 & 0x00FF00FF) << 8))
    v = v41b
    v = u32(v ^ (v >> 3))
    v = u32(v + v38)
    v = u32(v ^ ((v << 7) & M32))
    v = u32(v + v)
    v = u32(v ^ (v >> 29))
    v = u32(v + v42)
    v = u32(v + u32(u32(((v39 << 4) & M32) - v40) ^ v38))
    ks0 = u32(v9 + v)   # conv.r.un->r8->u4 = identity
    return ks0

for sign in (True, False):
    ks0 = round1(sign)
    p0 = c0 ^ ks0
    print(f'conv_u8_sign={sign}: ks0={ks0:08X} plain[0]={p0:08X} field-like={0x04000000 <= p0 < 0x05000000}')

# constraint: if plain[0]=0x04xxxxxx then ks0 in [0x90000000..0x97FFFFFF] (c0 top=0x94)
print(f'ks0 must be in [0x90000000..0x97FFFFFF] for plain[0] to be 0x0400xxxx')
# what would ks0 need to be? derive ks0 for a few plausible plain[0]
