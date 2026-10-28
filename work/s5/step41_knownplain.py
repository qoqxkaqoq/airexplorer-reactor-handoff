# -*- coding: utf-8 -*-
"""step41: known-plaintext battery on res[0]/res[5]/res[2].
H1: PRNG keystream XOR (decrypt_prng schedule) from blob start / region start
H2: raw deflate per entry (compress known bodies, search)
H3: raw-deflate decompress probe from header offsets
"""
import struct, zipfile, zlib, dnfile
import sys
sys.path.insert(0, '/workspace/repo_git/work')
import decrypt_prng

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
data = open(BASE, 'rb').read()
pe = dnfile.dnPE(BASE)
cor20 = pe.net.struct
rbase = pe.get_offset_from_rva(cor20.ResourcesRva)

RES = [(0x0, 356328), (0x56FEC, 256), (0x570F0, 47915), (0x62C1F, 26128), (0x69233, 2337031), (0x2A3B3E, 398794)]
blobs = {}
for idx, (off, sz) in enumerate(RES):
    doff = rbase + off
    blobs[idx] = data[doff+4:doff+4+sz]

z = zipfile.ZipFile(DUMP)
# known bodies: use 7 a1 targets + a few big ones
toks = [0x06002127, 0x0600212A, 0x06002133, 0x06002145, 0x06002157, 0x06000CEE, 0x0600217A]
bodies = {}
for t in toks:
    d = z.read('m_%08X.bin' % t)
    ilsz = struct.unpack('<I', d[4:8])[0]
    bodies[t] = d[24:24+ilsz]

def ks_bytes(nbytes, phase_words=0):
    nw = nbytes//4 + 2
    ks = decrypt_prng.keystream(nw + phase_words)
    ks = ks[phase_words:]
    return b''.join(struct.pack('<I', w) for w in ks)[:nbytes]

for idx in (0, 5, 2, 1):
    blob = blobs[idx]
    print('== res[%d] size=%d' % (idx, len(blob)))
    # H1: keystream XOR from blob start
    ksb = ks_bytes(len(blob))
    xr = bytes(a ^ b for a, b in zip(blob, ksb))
    hit = None
    for t, il in bodies.items():
        j = xr.find(il[:min(16, len(il))])
        if j >= 0:
            hit = (t, j)
            break
    print('   H1 xor-from-0: %s' % (('HIT %08X @0x%X' % hit) if hit else 'none'))
    # H1b: keystream XOR aligned to resources region start
    rks = ks_bytes(len(data) and (rbase + 0x570F0 + 4 + len(blob)))  # big enough
    # align: region keystream index at blob start = (rbase+off+4 - sectionraw?) use absolute file offset /4
    absoff = rbase + RES[idx][0] + 4
    ph = absoff // 4
    ksb2 = ks_bytes(len(blob), phase_words=0)[0:0]  # placeholder
    ks_full = decrypt_prng.keystream(ph + len(blob)//4 + 2)
    ksb2 = b''.join(struct.pack('<I', w) for w in ks_full[ph:ph + len(blob)//4 + 1])[:len(blob)]
    xr2 = bytes(a ^ b for a, b in zip(blob, ksb2))
    hit2 = None
    for t, il in bodies.items():
        j = xr2.find(il[:min(16, len(il))])
        if j >= 0:
            hit2 = (t, j)
            break
    print('   H1b xor-fileoff-phase: %s' % (('HIT %08X @0x%X' % hit2) if hit2 else 'none'))
    # H2: compressed known bodies search
    hit3 = None
    for t, il in bodies.items():
        for lvl in (6, 9, 1):
            c = zlib.compressobj(lvl, zlib.DEFLATED, -15)
            co = c.compress(il) + c.flush()
            j = blob.find(co)
            if j >= 0:
                hit3 = (t, lvl, j)
                break
        if hit3: break
    print('   H2 deflate-search: %s' % (('HIT %s' % (hit3,)) if hit3 else 'none'))
    # H3: decompress probe at several offsets
    dec = None
    for start in range(0, min(16, len(blob))):
        for wbits in (-15, 15, 31):
            try:
                d = zlib.decompressobj(wbits)
                out = d.decompress(blob[start:start+4096])
                if len(out) > 32:
                    dec = (start, wbits, out[:48].hex())
                    break
            except Exception:
                pass
        if dec: break
    print('   H3 deflate-probe: %s' % (dec if dec else 'none'))
