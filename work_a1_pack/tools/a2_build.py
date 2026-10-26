#!/usr/bin/env python3
# a2_build.py — assemble candidate A1 patch exe via the mainlib route.
#   1. flip two ct bytes in mainlib_plain (^1 each: plaintext 0x16 -> 0x17)
#   2. raw-deflate (level 9, memLevel 9, wbits=-15)
#   3. new_res = new_stream XOR mainlib_ks.bin (zero-pad stream to 0x23A907)
#   4. write into baseline copy at file offset 0x68a5f7 (nothing else touched)
# Verifies every step; also reports whether re-deflating the UNPATCHED mainlib
# reproduces the original stream byte-for-byte (producer-settings fingerprint).
import zlib, struct, hashlib, sys

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
BASE    = W + r'\airexplorer-reactor-handoff\exes\AirExplorer_baseline_verified.exe'
OUT     = W + r'\exes\AirExplorer_baseline_verified_a1.exe'
MP      = W + r'\work_a1\mainlib_plain.bin'
KS      = W + r'\work_a1\mainlib_ks.bin'
RES_OFF = 0x68a5f7
PATCHES = [(0x194518, 0x49), (0x197AE4, 0x03)]   # (mainlib offset, expected current ct)

mp  = bytearray(open(MP,'rb').read())
ks  = open(KS,'rb').read()
base = open(BASE,'rb').read()
assert len(ks) == 0x23A907

# sanity: resource slot in baseline + its 4-byte length prefix
res = base[RES_OFF:RES_OFF+len(ks)]
plen = struct.unpack_from('<I', base, RES_OFF-4)[0]
print('resource length prefix @0x%x: 0x%x (res len 0x%x)' % (RES_OFF-4, plen, len(ks)))

# original deflate stream
orig_stream = bytes(a^b for a,b in zip(res, ks))
d = zlib.decompressobj(-15); orig_out = d.decompress(orig_stream)
assert d.eof and not d.unused_data and orig_out == bytes(mp), 'orig stream mismatch'
print('orig stream: len 0x%x, inflates to 0x%x == mainlib_plain' % (len(orig_stream), len(orig_out)))

# fingerprint: does level9/memLevel9 reproduce the original stream?
co = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_DEFAULT_STRATEGY)
re_orig = co.compress(bytes(mp)) + co.flush()
print('re-deflate(unpatched mainlib) == orig stream: %s (len 0x%x vs 0x%x)' % (re_orig == orig_stream, len(re_orig), len(orig_stream)))

# 1. flip ct bytes
for off, cur in PATCHES:
    assert mp[off] == cur, 'patch point %#x has %#x, expected %#x' % (off, mp[off], cur)
    mp[off] ^= 0x01
    print('flipped mainlib[0x%x]: 0x%02x -> 0x%02x (pt 0x16 -> 0x17)' % (off, cur, mp[off]))

# 2. deflate new mainlib
co = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_DEFAULT_STRATEGY)
new_stream = co.compress(bytes(mp)) + co.flush()
print('new stream len: 0x%x (orig 0x%x)' % (len(new_stream), len(orig_stream)))
if len(new_stream) > len(ks):
    print('FATAL: new stream larger than resource slot', file=sys.stderr); sys.exit(1)
padded = new_stream + b'\x00' * (len(ks) - len(new_stream))

# verify padded stream inflates to patched mainlib
d = zlib.decompressobj(-15); out2 = d.decompress(padded)
assert d.eof and out2 == bytes(mp), 'padded stream re-inflate mismatch'
print('padded stream re-inflates exactly to patched mainlib (0x%x), eof, no tail' % len(out2))

# 3. XOR keystream
new_res = bytes(a^b for a,b in zip(padded, ks))

# round-trip check: new_res XOR ks == padded
assert bytes(a^b for a,b in zip(new_res, ks)) == padded

# 4. write back
out = bytearray(base)
out[RES_OFF:RES_OFF+len(ks)] = new_res
assert len(out) == len(base), 'output size changed!'
diff = [i for i in range(len(base)) if out[i] != base[i]]
print('bytes differing from baseline: %d, range 0x%x..0x%x' % (len(diff), diff[0], diff[-1]))
assert all(RES_OFF <= i < RES_OFF+len(ks) for i in diff), 'diff outside resource region!'

open(OUT,'wb').write(bytes(out))
print('wrote', OUT)
print('md5:', hashlib.md5(bytes(out)).hexdigest())
