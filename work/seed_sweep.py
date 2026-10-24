#!/usr/bin/env python3
# Seed sweep for the main library streaming decryptor (RandomDecryptor ctor).
# Verifier: decrypted prefix must be a valid raw-deflate stream.
import sys, zlib, struct
sys.path.insert(0, '/workspace/airexplorer-reactor-handoff/work')
import decrypt_prng as dp
from decrypt_prng import prng_round, u32

SRC = '/workspace/airexplorer-reactor-handoff/work/res_ValidatorGenerator.DefinitionError.bin'
data = open(SRC, 'rb').read()
N = 4096  # prefix bytes to test
buf = data[:N]

def ks_for(seed, nwords):
    ks = []
    v9 = u32(seed)
    for _ in range(nwords):
        v9 = prng_round(v9)
        ks.append(v9)
    return ks

def dec_word_le(ks):
    out = bytearray()
    for w, k in enumerate(ks):
        off = w*4
        word = u32(buf[off] | (buf[off+1]<<8) | (buf[off+2]<<16) | (buf[off+3]<<24))
        out += struct.pack('<I', u32(k ^ word))
    return bytes(out)

def dec_word_be(ks):
    out = bytearray()
    for w, k in enumerate(ks):
        off = w*4
        word = struct.unpack('>I', buf[off:off+4])[0]
        out += struct.pack('>I', u32(k ^ word))
    return bytes(out)

def dec_bytes_le(ks):
    return bytes(b ^ ((ks[i//4] >> ((i%4)*8)) & 0xFF) for i, b in enumerate(buf))

def dec_bytes_be(ks):
    return bytes(b ^ ((ks[i//4] >> (24-(i%4)*8)) & 0xFF) for i, b in enumerate(buf))

DECODERS = [('wLE', dec_word_le), ('wBE', dec_word_be), ('bLE', dec_bytes_le), ('bBE', dec_bytes_be)]

def check(dec, tag):
    for wbits, label in [(-15, 'raw'), (15, 'zlib')]:
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(dec, 1 << 20)
            if len(out) > 32:
                print(f'*** HIT {tag} {label}: out={len(out)} head={out[:32].hex()}')
                open('/tmp/mainlib_hit.bin', 'wb').write(out)
                return True
        except Exception:
            pass
    # weak signal: first byte BFINAL/BTYPE valid
    b0 = dec[0]
    if b0 & 0x06 != 0x06:  # BTYPE != 3 (reserved)
        pass
    return False

# name-derived hashes
name = 'ValidatorGenerator.DefinitionError'
def fnv1a(bs, h=0x811C9DC5):
    for b in bs: h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h
def fnv1(bs, h=0x811C9DC5):
    for b in bs: h = ((h * 0x01000193) & 0xFFFFFFFF) ^ b
    return h
def djb2(bs):
    h = 5381
    for b in bs: h = (h * 33 + b) & 0xFFFFFFFF
    return h
def crc32(bs):
    import binascii
    return binascii.crc32(bs) & 0xFFFFFFFF
def adler32(bs):
    import zlib as z
    return z.adler32(bs) & 0xFFFFFFFF

u8 = name.encode('utf-8')
u16 = name.encode('utf-16-le')
L = len(data)
candidates = [
    ('zero', 0),
    ('len', L), ('~len', L ^ 0xFFFFFFFF), ('neglen', (-L) & 0xFFFFFFFF),
    ('len>>2', L >> 2), ('len<<2', (L << 2) & 0xFFFFFFFF), ('len>>9', L >> 9),
    ('state_init', 0x59D3B137), ('state_mid', 0x3A17E076), ('state_5509', 0xDA690CE),
    ('fnv1a_u8', fnv1a(u8)), ('fnv1a_u16', fnv1a(u16)), ('fnv1_u16', fnv1(u16)),
    ('djb2_u16', djb2(u16)), ('crc32_u16', crc32(u16)), ('crc32_u8', crc32(u8)),
    ('adler_u16', adler32(u16)), ('adler_u8', adler32(u8)),
    ('len_xor_fnv', L ^ fnv1a(u16)),
    ('name_len', len(name)), ('name_len_u16', len(u16)),
    ('word0_raw', u32(data[0] | (data[1]<<8) | (data[2]<<16) | (data[3]<<24))),
    ('word0_xor_len', u32((data[0] | (data[1]<<8) | (data[2]<<16) | (data[3]<<24)) ^ L)),
]
hit = False
for tag, seed in candidates:
    ks = ks_for(seed, N//4)
    for dtag, fn in DECODERS:
        dec = fn(ks)
        if check(dec, f'{tag}/{dtag}/seed=0x{seed&0xFFFFFFFF:08X}'):
            hit = True
            break
    if hit: break
print('done', 'HIT' if hit else 'no hit among', len(candidates), 'candidates x', len(DECODERS))
