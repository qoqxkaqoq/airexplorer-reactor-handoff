#!/usr/bin/env python3
# Reactor runtime PRNG keystream (06004193 DispatcherInitializer::TrackCompiler).
# VERIFIED: decrypts "CollectorTransaction.ValidatorProject" 3266/3266 field tokens.
# KEY FINDING: locals are declared unsigned int32 -> conv.u8 ZERO-extends.
import struct, sys

M32 = 0xFFFFFFFF
U64 = (1 << 64) - 1
def u32(x): return x & M32

K1 = 506503628                                  # v38 (IL_0147)
K1B = u32(1610158714 + 1328951073 - 1267867220) # v38 update (IL_01FA-020B)
K2 = 1959015338                                 # v39 (IL_0150)
K3 = 854276594                                  # v40 (IL_0159)
K4 = 41684485                                   # v42 (IL_0166)

def zext(prod):
    """conv.u8 from unsigned int32: zero-extend"""
    return prod & M32

def prng_round(v9):
    v41 = u32(v9)
    # v43 = conv.u8(int32(K1*v41)); if 0 -> -1 (int64)
    v43u = zext((K1 * v41) & M32)
    if v43u == 0: v43u = U64
    # v40 = (u32)(conv.u8(i32(K3*K3)) rem.un v43)
    v40 = u32(zext((K3 * K3) & M32) % v43u)
    # v39 = odd/even bit pair swap of (rotl(K2,23) + v9)
    v45 = u32(u32((K2 >> 9) | ((K2 << 23) & M32)) + v9)
    v39 = u32(((v45 & 0xAAAAAAAA) >> 1) | ((v45 & 0x55555555) << 1))
    v38 = K1B
    # v41 chain
    v41x = v41 if v41 != 0 else M32          # if 0 -> -1
    v44 = u32((v40 // v41x) + v41x)          # div.un
    v41 = u32(u32(u32(v40 + v40) - v44) + v40)
    v45 = u32(u32(((K4 << 10) & M32) | (K4 >> 22)) + v40)
    v42 = u32(((v45 & 0xFF00FF00) >> 8) | ((v45 & 0x00FF00FF) << 8))
    v41 = u32(v41 ^ (v41 >> 3))
    v41 = u32(v41 + v38)
    v41 = u32(v41 ^ ((v41 << 7) & M32))
    v41 = u32(v41 + v41)
    v41 = u32(v41 ^ (v41 >> 29))
    v41 = u32(v41 + v42)
    v41 = u32(v41 + u32(u32(((v39 << 4) & M32) - v40) ^ v38))
    # conv.r.un -> conv.r8 -> conv.u4 : exact for u32 (53-bit mantissa) -> identity
    v9 = u32(v9 + v41)
    return v9

def keystream(nwords):
    ks = []
    v9 = 0
    for _ in range(nwords):
        v9 = prng_round(v9)
        ks.append(v9)
    return ks

def decrypt(data):
    n = len(data) // 4 + (1 if len(data) % 4 else 0)
    ks = keystream(n)
    out = bytearray()
    for w in range(n):
        off = w * 4
        if w == n - 1 and len(data) % 4:
            rem = len(data) - off
            word = 0
            for j in range(rem):
                if j > 0: word = (word << 8) & M32
                word |= data[len(data) - 1 - j]
            word = u32(word)
        else:
            word = u32(data[off] | (data[off+1] << 8) | (data[off+2] << 16) | (data[off+3] << 24))
        out += struct.pack('<I', u32(ks[w] ^ word))
    return bytes(out[:len(data)])

def encrypt(data):
    """known-plaintext re-encryption: same keystream XOR"""
    n = len(data) // 4 + (1 if len(data) % 4 else 0)
    ks = keystream(n)
    out = bytearray()
    for w in range(n):
        off = w * 4
        if w == n - 1 and len(data) % 4:
            rem = len(data) - off
            word = u32(data[off] | (data[off+1] << 8 if off+1 < len(data) else 0) |
                       (data[off+2] << 16 if off+2 < len(data) else 0))
            # tail word little-endian of last rem bytes (matches decrypt tail logic)
            word = 0
            for j in range(rem):
                if j > 0: word = (word << 8) & M32
                word |= data[len(data) - 1 - j]
            cw = u32(word ^ ks[w])
            out += cw.to_bytes(4, 'little')[:rem]
        else:
            word = u32(data[off] | (data[off+1] << 8) | (data[off+2] << 16) | (data[off+3] << 24))
            out += struct.pack('<I', u32(ks[w] ^ word))
    return bytes(out)

if __name__ == '__main__':
    src = sys.argv[1] if len(sys.argv) > 1 else 'res_CollectorTransaction.ValidatorProject.bin'
    dst = sys.argv[2] if len(sys.argv) > 2 else '/tmp/delegate_table.bin'
    data = open(src, 'rb').read()
    dec = decrypt(data)
    open(dst, 'wb').write(dec)
    # sanity: roundtrip
    re_ = encrypt(dec)
    assert re_ == data, 'roundtrip FAIL'
    print(f'decrypted {len(data)} bytes -> {dst}; roundtrip OK')
    pairs = [struct.unpack_from('<ii', dec, i) for i in range(0, len(dec) - len(dec) % 8, 8)]
    fl = sum(1 for a, b in pairs if 0x04000000 <= (a & M32) < 0x05000000)
    print(f'pairs={len(pairs)} field-like={fl}/{len(pairs)}')
    for a, b in pairs[:6]:
        flag = bool(b & 0x40000000)
        print(f'  field={a & M32:08X} value={b & M32:08X} callvirt={flag} tok={b & 0x3FFFFFFF:08X}')
