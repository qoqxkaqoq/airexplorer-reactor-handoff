#!/usr/bin/env python3
# l1_names.py — Lead 1: name -> key derivation matrix, validated on 4 known pairs
import sys, os, hashlib, hmac, struct, zlib, binascii
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import aot

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
K_FILE = open(W + r'\work_a1\k26\K_FILE.bin', 'rb').read()
A_FILE = open(W + r'\work_a1\k26\A_FILE.bin', 'rb').read()
B_FILE = open(W + r'\work_a1\k26\B_FILE.bin', 'rb').read()

KNOWN = {
    'ErrorReceiver.ValidatorViewer':      binascii.unhexlify('f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943'),
    'ValidatorGenerator.DefinitionError': binascii.unhexlify('cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481'),
    'GlobalValidator.FactoryValidator':   binascii.unhexlify('37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a'),
    'CollectorTransaction.ValidatorProject': bytes(32),
}
TARGETS = ['ValidatorAllocator.ValidatorProc', 'ValidatorArgument.EmitterReporter']

def name_variants(n):
    outs = set()
    base = n
    dom, _, cls = n.rpartition('.')
    for v in (base, base.lower(), base.upper(), dom, cls, dom.lower(), cls.lower(),
              dom + cls, cls + dom, dom + '.' + cls, base + '.resources', base + '\0'):
        for enc in ('utf-8', 'utf-16-le'):
            try: outs.add(v.encode(enc))
            except Exception: pass
    return outs

def post_variants(b32):
    yield b32
    yield b32[::-1]
    # per-dword bswap
    d = struct.unpack('<8I', b32)
    yield struct.pack('>8I', *d)
    # per-dword rotate? skip; hex-string as bytes
    yield b32.hex().encode()[:32] if False else b32  # placeholder no-op

def digest_variants(msg):
    """yield candidate 32B key candidates from message bytes"""
    for hname in ('md5', 'sha1', 'sha256', 'sha384', 'sha512', 'sha3_256', 'sha3_512', 'blake2s', 'blake2b'):
        h = hashlib.new(hname, msg).digest()
        if len(h) >= 32: yield ('h_' + hname, h[:32])
        if len(h) > 32:  yield ('hT_' + hname, h[-32:])
        if len(h) == 16:
            yield ('h2x_' + hname, h + h)
            yield ('h2r_' + hname, h + h[::-1])
    # sha512/256 truncated mid
    h512 = hashlib.sha512(msg).digest()
    yield ('h_mid_sha512', h512[16:48])
    yield ('h_mid2_sha512', h512[32:64])
    # hmac with tail materials as key
    for hk in ('md5', 'sha1', 'sha256', 'sha512'):
        hmod = getattr(hashlib, hk)
        for kk, kn in ((K_FILE, 'K_FILE'), (A_FILE, 'A_FILE'), (B_FILE, 'B_FILE')):
            dg = hmac.new(kk, msg, hmod).digest()
            if len(dg) >= 32: yield ('hma_%s_%s' % (hk, kn), dg[:32])
            m2 = hmac.new(msg, kk, hmod).digest()
            if len(m2) >= 32: yield ('hmr_%s_%s' % (hk, kn), m2[:32])
    # hash chains with tail material
    for kk, kn in ((K_FILE, 'K_FILE'), (A_FILE, 'A_FILE'), (B_FILE, 'B_FILE')):
        yield ('cat_pre_' + kn, hashlib.sha256(kk + msg).digest())
        yield ('cat_post_' + kn, hashlib.sha256(msg + kk).digest())
        yield ('cat_pre_m_' + kn, hashlib.md5(kk + msg).digest() * 2)
        yield ('cat_post_m_' + kn, hashlib.md5(msg + kk).digest() * 2)
    # crc32-based 8 dwords
    c = zlib.crc32(msg) & 0xFFFFFFFF
    yield ('crc_rep', struct.pack('<8I', *([c] * 8)))

def prng_seed_variants(msg):
    """32-bit seeds from name, then key = successive prng outputs (several chain shapes)"""
    seeds = []
    # DJB2 on utf16 chars / ascii bytes
    def djb2(chars):
        h = 5381
        for c in chars: h = (((h << 5) + h) ^ c) & 0xFFFFFFFF
        return h
    def djb2x(chars):
        h = 5381
        for c in chars: h = (((h << 5) + h) ^ c) & 0xFFFFFFFF
        return h
    def fnv1a(bs):
        h = 0x811C9DC5
        for b in bs: h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
        return h
    def fnv1(bs):
        h = 0x811C9DC5
        for b in bs: h = ((h * 0x01000193) ^ b) & 0xFFFFFFFF
        return h
    def joaat(bs):
        h = 0
        for b in bs:
            h = (h + b) & 0xFFFFFFFF
            h = (h + (h << 10)) & 0xFFFFFFFF
            h ^= h >> 6
        h = (h + (h << 3)) & 0xFFFFFFFF
        h ^= h >> 11
        h = (h + (h << 15)) & 0xFFFFFFFF
        return h
    try: ch16 = list(struct.unpack('<%dH' % (len(msg) // 2), msg[:len(msg) // 2 * 2]))
    except Exception: ch16 = []
    seeds.append(('djb2_u16', djb2(ch16) if ch16 else 0))
    seeds.append(('djb2_u16_low', djb2([c | 0x20 for c in ch16]) if ch16 else 0))
    seeds.append(('djb2_asc', djb2(list(msg))))
    seeds.append(('fnv1a', fnv1a(msg)))
    seeds.append(('fnv1', fnv1(msg)))
    seeds.append(('joaat', joaat(msg)))
    seeds.append(('crc', zlib.crc32(msg) & 0xFFFFFFFF))
    out = []
    for sn, s in seeds:
        # shape A: state=seed; for i: state=prng_round(state); key[i]=state
        st = s; ks = []
        for _ in range(8):
            st = aot.prng_round(st); ks.append(st)
        out.append(('prA_' + sn, struct.pack('<8I', *ks)))
        # shape B: key[i] = prng_round(seed + i)
        ks2 = [aot.prng_round((s + i) & 0xFFFFFFFF) for i in range(8)]
        out.append(('prB_' + sn, struct.pack('<8I', *ks2)))
        # shape C: state=seed, key[i]=prng_round(state+key_prev)... like decryption with own output
        st = s; ks3 = []
        for i in range(8):
            st = aot.prng_round((st + (ks3[-1] if ks3 else 0)) & 0xFFFFFFFF); ks3.append(st)
        out.append(('prC_' + sn, struct.pack('<8I', *ks3)))
    return out

def run():
    hits = []
    names = list(KNOWN) + TARGETS
    for n in names:
        target = KNOWN.get(n)
        for nb in name_variants(n):
            for tag, k in digest_variants(nb):
                if target is not None and k == target:
                    hits.append((n, tag, nb[:40]))
                    print('*** HIT', n, tag)
            for tag, k in prng_seed_variants(nb):
                if target is not None and k == target:
                    hits.append((n, tag, nb[:40]))
                    print('*** HIT', n, tag)
    print('scan done; hits =', len(hits))
    for h in hits: print(h)

if __name__ == '__main__':
    run()
