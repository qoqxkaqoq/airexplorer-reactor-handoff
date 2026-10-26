# -*- coding: utf-8 -*-
"""C线第一步：6 个 cor20 资源解密落盘 + roundtrip 校验 + manifest。
READ-ONLY on the baseline exe. Outputs -> work/c2_pack/dec/ + manifest.json.

Algorithm (ask-verified): state=0; per input dword i:
    state=(state+key_dw[i%8]) & 0xffffffff; state=prng_round(state);
    pt_dw = bswap(ct_dw) ^ state
byte convention (validated by t26 & c_route_verify): words read big-endian ==
bswap, i.e. pt_bytes = ct_bytes XOR LE(state) dwords, truncated to length.
Reference prng_round: airexplorer-reactor-handoff/work/decrypt_prng.py.
"""
import struct, hashlib, zlib, json, math, os, sys

WS  = r"C:/Users/xaxka/.zcode/workspace/draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff"
BASE = WS + "/airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe"
OUTD = WS + "/work/c2_pack/dec"
sys.path.insert(0, WS + "/airexplorer-reactor-handoff/work")
import decrypt_prng as dp            # verified reference implementation
u32 = dp.u32

os.makedirs(OUTD, exist_ok=True)
LOG = []
def P(s=""):
    print(s); LOG.append(s)

# ---------------------------------------------------------------- resources
# (name, prefix_off, ct_off, length)  — prefix = 4B LE length immediately before ct
RES = [
    ("Viewer",  0x6213C0, 0x6213C4, 0x56FE8, "dec_Viewer.bin"),
    ("Emitter", 0x6783AC, 0x6783B0, 0x100,   "dec_Emitter.bin"),
    ("Proc",    0x6784B0, 0x6784B4, 0xBB2B,   "dec_Proc.bin"),
    ("Project", 0x683FDF, 0x683FE3, 0x6610,   "dec_Project.bin"),
    ("mainlib", 0x68A5F3, 0x68A5F7, 0x23A907, "dec_mainlib.bin"),
    ("Factory", 0x8C4EFE, 0x8C4F02, 0x615CA,  "dec_Factory.bin"),
]
KEYHEX = {
    "Viewer":  "f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943",
    "mainlib": "cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481",
    "Factory": "37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a",
    "Project": "00" * 32,
}
# Proc/Emitter: no key exists (see README: k27 IL evidence + this session's triage).

# ---------------------------------------------------------------- crypto core
def keystream(nbytes, kd):
    """state chain; returns bytes = concat(LE(state_i)), truncated to nbytes."""
    n = nbytes // 4 + (1 if nbytes % 4 else 0)
    v9 = 0; out = bytearray()
    for w in range(n):
        v9 = u32(v9 + kd[w % 8]); v9 = dp.prng_round(v9)
        out += struct.pack('<I', v9)
    return bytes(out[:nbytes])

def decrypt(ct, kd):
    return bytes(a ^ b for a, b in zip(ct, keystream(len(ct), kd)))

# keystream XOR is symmetric: re-encryption == same XOR; kept explicit for clarity
def encrypt(pt, kd):
    return bytes(a ^ b for a, b in zip(pt, keystream(len(pt), kd)))

def entropy(b):
    if not b: return 0.0
    cnt = [0]*256
    for x in b: cnt[x] += 1
    n = len(b); H = 0.0
    for c in cnt:
        if c:
            p = c/n; H -= p*math.log2(p)
    return H

def sha256(b): return hashlib.sha256(b).hexdigest()

# ---------------------------------------------------------------- 0. baseline
data = open(BASE, 'rb').read()
md5 = hashlib.md5(data).hexdigest()
P("== 0. baseline ==")
P("size=%d md5=%s" % (len(data), md5))
assert len(data) == 9668976 and md5 == "a12b5c573e1b54e98cccc29351eaa066", "baseline mismatch!"

# ------------------------------------------------- 1. length prefixes & layout
P("\n== 1. resource layout (4B LE length prefix immediately before each ct) ==")
ct = {}
prev_end = None
layout_ok = True
for name, pfx, off, ln, fn in RES:
    v = struct.unpack_from('<I', data, pfx)[0]
    ok = (v == ln)
    cont = (prev_end is None) or (pfx == prev_end)
    layout_ok &= ok and cont
    P("%-8s prefix@0x%06X=%#8x ct=[0x%06X,0x%06X) len=%d  prefix:%s contiguous:%s"
      % (name, pfx, v, off, off+ln, ln, "OK" if ok else "MISMATCH", "yes" if cont else "NO"))
    ct[name] = data[off:off+ln]
    prev_end = off + ln
P("blob end 0x%X < 0x936000 (overlay untouched): %s" % (prev_end, prev_end < 0x936000))
assert layout_ok, "layout check failed"

# ------------------------------------------- 2. implementation cross-check
P("\n== 2. implementation cross-check vs reference decrypt_prng.py ==")
# key=zero chain must equal dp.keystream chain exactly (full Project block)
kd0 = [0]*8
myks = keystream(len(ct["Project"]), kd0)
refks = b''.join(struct.pack('<I', w) for w in dp.keystream(len(ct["Project"])//4))
P("my zero-key keystream == dp.keystream (Project, %d dwords): %s"
  % (len(ct["Project"])//4, myks[:len(refks)] == refks))
assert myks[:len(refks)] == refks
# regenerated mainlib keystream vs prior verified pipeline artifact
ml_kd = list(struct.unpack('<8I', bytes.fromhex(KEYHEX["mainlib"])))
mlks_mine = keystream(len(ct["mainlib"]), ml_kd)
mlks_file = open(WS + "/work_a1/mainlib_ks.bin", 'rb').read()
P("regenerated mainlib keystream == work_a1/mainlib_ks.bin (%d/%d B): %s"
  % (len(mlks_mine), len(mlks_file), mlks_mine == mlks_file))
assert mlks_mine == mlks_file

# ------------------------------------------------------------- 3. decrypt all
P("\n== 3. decrypt + roundtrip + cross-references ==")
manifest = {"generated_by": "work/c2_pack/c2_decrypt.py", "baseline_exe": BASE,
            "baseline_md5": md5, "baseline_size": len(data),
            "algorithm": "state=0; state=(state+key_dw[i%8]); state=prng_round(state); pt=bswap(ct_dw)^state (byte view: pt=ct^LE(state) stream)",
            "resources": []}

def rec(name, **kw):
    manifest["resources"].append(dict(name=name, **kw))

# --- Viewer
name = "Viewer"
pt = decrypt(ct[name], list(struct.unpack('<8I', bytes.fromhex(KEYHEX[name]))))
rt = encrypt(pt, list(struct.unpack('<8I', bytes.fromhex(KEYHEX[name])))) == ct[name]
ref = open(WS + "/work_a1/dec_Viewer.bin", 'rb').read()
open(OUTD + "/dec_Viewer.bin", 'wb').write(pt)
P("%-8s dec %dB roundtrip:%s  ==work_a1/dec_Viewer.bin:%s (ref %dB)"
  % (name, len(pt), rt, pt == ref, len(ref)))
assert rt and pt == ref
rec(name, ct_offset="0x6213C4", prefix_offset="0x6213C0", length=len(ct[name]),
    key=KEYHEX[name], key_status="known", decrypted=True, roundtrip=rt,
    file="dec/dec_Viewer.bin", sha256=sha256(pt), sha256_ct=sha256(ct[name]),
    crosscheck="byte-identical to work_a1/dec_Viewer.bin")

# --- Project (key = all zero)
name = "Project"
kd = [0]*8
pt = decrypt(ct[name], kd)
rt = encrypt(pt, kd) == ct[name]
ref = open(WS + "/work_a1/zdec/Project.bin", 'rb').read()
open(OUTD + "/dec_Project.bin", 'wb').write(pt)
P("%-8s dec %dB roundtrip:%s  ==work_a1/zdec/Project.bin:%s (ref %dB)"
  % (name, len(pt), rt, pt == ref, len(ref)))
assert rt and pt == ref
rec(name, ct_offset="0x683FE3", prefix_offset="0x683FDF", length=len(ct[name]),
    key=KEYHEX[name], key_status="known(all-zero)", decrypted=True, roundtrip=rt,
    file="dec/dec_Project.bin", sha256=sha256(pt), sha256_ct=sha256(ct[name]),
    crosscheck="byte-identical to work_a1/zdec/Project.bin (delegate binding table, 8B x 3266)")

# --- Factory
name = "Factory"
kd = list(struct.unpack('<8I', bytes.fromhex(KEYHEX[name])))
pt = decrypt(ct[name], kd)
rt = encrypt(pt, kd) == ct[name]
open(OUTD + "/dec_Factory.bin", 'wb').write(pt)
# structure check: [int32 BYTE-length][UTF-16LE string pool] header (k27 calibration pt0=0x34)
slen = struct.unpack_from('<I', pt, 0)[0]
try:
    s0 = pt[4:4+slen].decode('utf-16-le')
    hdr_ok = slen % 2 == 0 and all(31 <= ord(c) < 0xFFFD or c in '\r\n\t' for c in s0)
except Exception:
    s0, hdr_ok = "", False
ref = open(WS + "/work_a1/zdec/Factory_keyed.bin", 'rb').read()   # prior dword-truncated decrypt
P("%-8s dec %dB roundtrip:%s  header int32=%#x utf16-ok:%s first=%r  ==zdec/Factory_keyed prefix:%s"
  % (name, len(pt), rt, slen, hdr_ok, s0[:24], pt[:len(ref)] == ref))
assert rt and hdr_ok and pt[:len(ref)] == ref
rec(name, ct_offset="0x8C4F02", prefix_offset="0x8C4EFE", length=len(ct[name]),
    key=KEYHEX[name], key_status="known", decrypted=True, roundtrip=rt,
    file="dec/dec_Factory.bin", sha256=sha256(pt), sha256_ct=sha256(ct[name]),
    crosscheck="prefix == work_a1/zdec/Factory_keyed.bin (dword-truncated prior decrypt); header [int32 0x34][UTF-16 pool] verified")

# --- mainlib: decrypt -> raw-deflate stream -> inflate -> PE plain
name = "mainlib"
kd = ml_kd
stream = decrypt(ct[name], kd)
rt_stream = encrypt(stream, kd) == ct[name]
open(OUTD + "/dec_mainlib_stream.bin", 'wb').write(stream)
d = zlib.decompressobj(-15)
plain = d.decompress(stream)
tail_info = "eof=%s unused=%d" % (d.eof, len(d.unused_data))
ref = open(WS + "/work_a1/mainlib_plain.bin", 'rb').read()
open(OUTD + "/dec_mainlib.bin", 'wb').write(plain)
# full re-encryption pipeline check: deflate(plain) -> pad -> XOR ks -> vs ct
co = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_DEFAULT_STRATEGY)
redef = co.compress(plain) + co.flush()
re_ct = encrypt(redef + b'\x00'*(len(ct[name])-len(redef)), kd)
redef_matches = (redef == stream[:len(redef)]
                 and stream[len(redef):] == b'\x00' * (len(stream) - len(redef)))
rt_deflate = (re_ct == ct[name]) and len(redef) <= len(ct[name])
P("%-8s stream %dB roundtrip(stream):%s  inflate %dB %s ==mainlib_plain.bin:%s (ref %dB)"
  % (name, len(stream), rt_stream, len(plain), tail_info, plain == ref, len(ref)))
P("         re-deflate(level9,mem9): len 0x%X (slot 0x%X) reproduces-orig-stream:%s  full-reencrypt==orig ct:%s"
  % (len(redef), len(ct[name]), redef_matches, rt_deflate))
assert rt_stream and plain == ref and len(plain) == 4260864
rec(name, ct_offset="0x68A5F7", prefix_offset="0x68A5F3", length=len(ct[name]),
    key=KEYHEX[name], key_status="known", decrypted=True, roundtrip=rt_stream,
    roundtrip_note="roundtrip on decrypted deflate stream (encrypt(stream)==ct): True; "
                   "deflate-level roundtrip (re-deflate plain==orig stream): %s (zlib producer fingerprint differs; "
                   "pipeline a2_build.py writes a NEW valid stream instead — size %d <= slot %d)"
                   % (rt_deflate, len(redef), len(ct[name])),
    file="dec/dec_mainlib.bin", file_note="dec/dec_mainlib_stream.bin = decrypted raw-deflate stream (re-encryption input)",
    sha256=sha256(plain), sha256_stream=sha256(stream), sha256_ct=sha256(ct[name]),
    inflated_size=len(plain), deflate_eof=d.eof,
    crosscheck="inflated PE byte-identical to work_a1/mainlib_plain.bin (4260864B); keystream == work_a1/mainlib_ks.bin")

# --- Proc / Emitter: NO KEY (see README). Passthrough raw bytes, clearly labeled.
REASONS = {
    "Proc": ("no AOT key exists: reader m_060042AF reads resource raw (set_Position(2), ReadBytes, no decrypt call); "
             "only 4 keyed-PRNG copies in binary (Project/Viewer/mainlib/dead 0600418B), none for Proc; "
             "ct entropy ~6.18 b/B vs ~7.98 for real ciphers; no ct/pt pair captured "
             "(this session triaged all 93 leftover OUT_* files - none is a plaintext)"),
    "Emitter": ("no AOT key exists: reader m_06004192 (SHA1/RSA validator, proven conditional-dead code) reads the "
                "256B blob raw into signature check; resource never decrypted at runtime; no ct/pt pair available "
                "(this session triaged all 93 leftover OUT_* files - none is a plaintext)"),
}
for name in ("Proc", "Emitter"):
    raw = ct[name]
    fn = "dec_%s.bin" % name
    open(OUTD + "/" + fn, 'wb').write(raw)
    back = open(OUTD + "/" + fn, 'rb').read()
    P("%-8s NOT DECRYPTED (no key). raw passthrough %dB write-read-back:%s "
      "entropy=%.3f bits/B sha256=%s" % (name, len(raw), back == raw, entropy(raw), sha256(raw)[:16]))
    idx = [r[0] for r in RES].index(name)
    rec(name, ct_offset="0x%X" % RES[idx][2], prefix_offset="0x%X" % RES[idx][1],
        length=len(raw), key=None,
        key_status="missing", key_missing_reason=REASONS[name],
        decrypted=False, roundtrip=None,
        roundtrip_note="n/a - resource stored/consumed as plaintext (identity); file content = raw resource bytes",
        file="dec/" + fn, sha256=sha256(raw), sha256_ct=sha256(raw),
        passthrough=True)

# extra Proc structure evidence (own run)
proc = ct["Proc"]
u16 = struct.unpack_from('<8H', proc, 2)   # skip 2B header "3a 9c"
P("Proc head16=%s (2B header %s) u16 after skip: %s" %
  (proc[:16].hex(), proc[:2].hex(), " ".join("%04X" % x for x in u16)))
P("entropy: Viewer-ct=%.3f Project-ct=%.3f Proc=%.3f Emitter=%.3f"
  % (entropy(ct["Viewer"]), entropy(ct["Project"]), entropy(proc), entropy(ct["Emitter"])))

# ---------------------------------------------------------------- 4. write out
json.dump(manifest, open(WS + "/work/c2_pack/manifest.json", 'w'), indent=1)
open(WS + "/work/c2_pack/c2_decrypt_log.txt", 'w').write("\n".join(LOG))
P("\nmanifest -> work/c2_pack/manifest.json ; log -> work/c2_pack/c2_decrypt_log.txt")
n_ok = sum(1 for r in manifest["resources"] if r["decrypted"] and r["roundtrip"])
P("DECRYPTED+ROUNDTRIP-OK: %d/6 (missing: %s)" %
  (n_ok, ", ".join(r["name"] for r in manifest["resources"] if not r["decrypted"])))
