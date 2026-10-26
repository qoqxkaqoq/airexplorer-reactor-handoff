#!/usr/bin/env python3
# k26/aot.py — keyed AOT PRNG decrypt/encrypt harness (verified against known keys)
# Algorithm (task spec + decrypt_prng.py): state=0; per input dword i:
#   state = (state + key_dw[i%8]) & 0xffffffff; state = prng_round(state);
#   pt_dw = LE_read(ct, i) ^ state   (tail word: last rem bytes, first byte = LSB)
import struct

M32 = 0xFFFFFFFF
U64 = (1 << 64) - 1

K1 = 506503628
K1B = (1610158714 + 1328951073 - 1267867220) & M32
K2 = 1959015338
K3 = 854276594
K4 = 41684485


def prng_round(v9):
    v41 = v9 & M32
    v43u = (K1 * v41) & M32
    if v43u == 0: v43u = U64
    v40 = ((K3 * K3) & M32) % v43u
    v45 = (((K2 >> 9) | ((K2 << 23) & M32)) + v9) & M32
    v39 = (((v45 & 0xAAAAAAAA) >> 1) | ((v45 & 0x55555555) << 1)) & M32
    v38 = K1B
    v41x = v41 if v41 != 0 else M32
    v44 = ((v40 // v41x) + v41x) & M32
    v41 = (((v40 + v40) - v44) + v40) & M32
    v45 = ((((K4 << 10) & M32) | (K4 >> 22)) + v40) & M32
    v42 = (((v45 & 0xFF00FF00) >> 8) | ((v45 & 0x00FF00FF) << 8)) & M32
    v41 = (v41 ^ (v41 >> 3)) & M32
    v41 = (v41 + v38) & M32
    v41 = (v41 ^ ((v41 << 7) & M32)) & M32
    v41 = (v41 + v41) & M32
    v41 = (v41 ^ (v41 >> 29)) & M32
    v41 = (v41 + v42) & M32
    v41 = (v41 + ((((v39 << 4) & M32) - v40) & M32 ^ v38)) & M32
    v9 = (v9 + v41) & M32
    return v9


def key_dwords(key32):
    return list(struct.unpack('<8I', key32))


def keystream_keyed(nwords, key32, state0=0):
    kdw = key_dwords(key32)
    ks = []
    st = state0 & M32
    for i in range(nwords):
        st = (st + kdw[i % 8]) & M32
        st = prng_round(st)
        ks.append(st)
    return ks


def _tail_word(data):
    rem = len(data)
    word = 0
    for j in range(rem):
        if j > 0: word = (word << 8) & M32
        word |= data[len(data) - 1 - j]
    return word & M32


def decrypt(ct, key32, state0=0):
    n = len(ct) // 4 + (1 if len(ct) % 4 else 0)
    ks = keystream_keyed(n, key32, state0)
    out = bytearray()
    for w in range(n):
        off = w * 4
        if w == n - 1 and len(ct) % 4:
            word = _tail_word(ct[off:])
        else:
            word = ct[off] | (ct[off+1] << 8) | (ct[off+2] << 16) | (ct[off+3] << 24)
        out += struct.pack('<I', (ks[w] ^ word) & M32)
    return bytes(out[:len(ct)])


def encrypt(pt, key32, state0=0):
    n = len(pt) // 4 + (1 if len(pt) % 4 else 0)
    ks = keystream_keyed(n, key32, state0)
    out = bytearray()
    for w in range(n):
        off = w * 4
        if w == n - 1 and len(pt) % 4:
            word = _tail_word(pt[off:])
            cw = (word ^ ks[w]) & M32
            out += cw.to_bytes(4, 'little')[:len(pt) - off]
        else:
            word = pt[off] | (pt[off+1] << 8) | (pt[off+2] << 16) | (pt[off+3] << 24)
            out += struct.pack('<I', (ks[w] ^ word) & M32)
    return bytes(out)


def state_after(ct_len_words, key32, state0=0):
    """state after consuming ct_len_words dwords with this key (no plaintext needed)"""
    kdw = key_dwords(key32)
    st = state0 & M32
    for i in range(ct_len_words):
        st = (st + kdw[i % 8]) & M32
        st = prng_round(st)
    return st


EXE = None
def exe_bytes():
    global EXE
    if EXE is None:
        EXE = open(r'airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe', 'rb').read()
    return EXE


RES = {
    'Viewer':  (0x6213C4, 0x56FE8, 'ErrorReceiver.ValidatorViewer'),
    'Emitter': (0x6783B0, 0x100,   'ValidatorArgument.EmitterReporter'),
    'Proc':    (0x6784B4, 0xBB2B,  'ValidatorAllocator.ValidatorProc'),
    'Project': (0x683FE3, 0x6610,  'CollectorTransaction.ValidatorProject'),
    'mainlib': (0x68A5F7, 0x23A907,'ValidatorGenerator.DefinitionError'),
    'Factory': (0x8C4F02, 0x615CA, 'GlobalValidator.FactoryValidator'),
}


def res_ct(name):
    off, ln, _ = RES[name]
    d = exe_bytes()
    return d[off:off+ln]
