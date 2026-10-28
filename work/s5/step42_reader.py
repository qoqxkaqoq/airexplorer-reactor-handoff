# -*- coding: utf-8 -*-
"""step42: locate the reader/decryptor of res[0] ErrorReceiver.ValidatorViewer /
res[5] GlobalValidator.FactoryValidator.
A: parse #US heap of baseline, find US tokens for the resource name strings
   (and near-miss variants).
B: scan ALL baseline disk method bodies + all 16598 mt dump bodies for ldstr
   referencing those tokens (or GetManifestResourceStream caller).
C: report method(s) -> full disasm of candidate decryptor.
"""
import struct, sys, zipfile, dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
import cildasm

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
data = open(BASE, 'rb').read()
pe = dnfile.dnPE(BASE)
cor20 = pe.net.struct

# ---- A: parse #US heap ----
# locate metadata root
mroot_off = pe.get_offset_from_rva(cor20.MetaDataRva)
assert data[mroot_off:mroot_off+4] == b'BSJB'
sig, mj, mi, reserved, verlen = struct.unpack_from('<IHHII', data, mroot_off)
ver = data[mroot_off+16:mroot_off+16+verlen].rstrip(b'\0')
p = mroot_off + 16 + verlen
flags, nstreams = struct.unpack_from('<HH', data, p)
p += 4
streams = {}
for _ in range(nstreams):
    off, size = struct.unpack_from('<II', data, p)
    p += 8
    end = data.index(b'\0', p)
    name = data[p:end].decode()
    p = end + 1
    p = (p + 3) & ~3
    streams[name] = (mroot_off + off, size)
print('streams:', {k: ('0x%X' % v[0], v[1]) for k, v in streams.items()})

us_off, us_size = streams.get('#US', (0, 0))
us = data[us_off:us_off+us_size]

def us_read(tok):
    off = tok & 0xFFFFFF
    if off == 0 or off >= us_size: return None
    # compressed length
    b0 = us[off]
    if b0 & 0x80 == 0: ln, hdr = b0, 1
    elif b0 & 0xC0 == 0x80: ln, hdr = ((b0 & 0x3F) << 8) | us[off+1], 2
    else: ln, hdr = ((b0 & 0x1F) << 24) | (us[off+1] << 16) | (us[off+2] << 8) | us[off+3], 4
    raw = us[off+hdr:off+hdr+ln]
    return raw[:ln-1].decode('utf-16-le', errors='replace') if ln > 0 else ''

# walk whole US heap, collect strings of interest
targets = ['ErrorReceiver.ValidatorViewer', 'GlobalValidator.FactoryValidator',
           'ValidatorAllocator.ValidatorProc', 'ValidatorArgument.EmitterReporter']
tokens = {}
off = 1
while off < us_size:
    tok = 0x70000000 | off
    s = us_read(tok)
    if s is None: break
    for t in targets:
        if t in s:
            tokens.setdefault(t, []).append(tok)
    # advance
    b0 = us[off]
    if b0 & 0x80 == 0: ln, hdr = b0, 1
    elif b0 & 0xC0 == 0x80: ln, hdr = ((b0 & 0x3F) << 8) | us[off+1], 2
    else: ln, hdr = ((b0 & 0x1F) << 24) | (us[off+1] << 16) | (us[off+2] << 8) | us[off+3], 4
    off += hdr + max(ln, 1) if ln else hdr + 1
    if ln == 0: off = off  # empty string still has terminator? handled by max
for t, toks in tokens.items():
    print('US hit %r -> %s' % (t, ['%08X' % x for x in toks]))
if not tokens:
    print('US: NO resource-name strings found in #US heap')
    # dump strings containing 'Validator' for visibility
    off = 1
    shown = 0
    while off < us_size and shown < 40:
        tok = 0x70000000 | off
        s = us_read(tok)
        if s and ('alidator' in s or 'ErrorReceiver' in s or 'Factory' in s):
            print('   %08X %r' % (tok, s))
            shown += 1
        b0 = us[off]
        if b0 & 0x80 == 0: ln, hdr = b0, 1
        elif b0 & 0xC0 == 0x80: ln, hdr = ((b0 & 0x3F) << 8) | us[off+1], 2
        else: ln, hdr = ((b0 & 0x1F) << 24) | (us[off+1] << 16) | (us[off+2] << 8) | us[off+3], 4
        off += hdr + max(ln, 1)
        if ln == 0: off += 1

want_ldstr = set(t for v in tokens.values() for t in v)

# ---- B: scan disk bodies ----
mdt = pe.net.mdtables
hits = []
for i, row in enumerate(mdt.MethodDef.rows):
    rva = row.Rva
    if rva == 0: continue
    o = pe.get_offset_from_rva(rva)
    b0 = data[o]
    if b0 & 3 == 2:
        ilsz = b0 >> 2
        il = data[o+1:o+1+ilsz]
        base = i+1
    else:
        hs = (data[o+1] >> 4) * 4
        ilsz = struct.unpack_from('<I', data, o+4)[0]
        il = data[o+hs:o+hs+ilsz]
        base = i+1
    for j in range(len(il) - 4):
        if il[j] == 0x72:
            t = struct.unpack_from('<I', il, j+1)[0]
            if t in want_ldstr:
                hits.append((base, j, t))
print('disk ldstr hits:', [('0600%04X' % h[0], '0x%X' % h[1], '%08X' % h[2]) for h in hits])

# ---- B2: scan mt dump bodies ----
zhits = []
z = zipfile.ZipFile(DUMP)
for nm in z.namelist():
    if not nm.endswith('.bin'): continue
    d = z.read(nm)
    ilsz = struct.unpack('<I', d[4:8])[0]
    il = d[24:24+ilsz]
    tok = nm[2:10]
    for j in range(len(il) - 4):
        if il[j] == 0x72:
            t = struct.unpack_from('<I', il, j+1)[0]
            if t in want_ldstr:
                zhits.append((tok, j, t))
print('dump ldstr hits:', [(h[0], '0x%X' % h[1], '%08X' % h[2]) for h in zhits])
