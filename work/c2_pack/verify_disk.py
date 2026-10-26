# -*- coding: utf-8 -*-
"""Final disk-level verification: re-read dec/*.bin from disk, re-encrypt,
compare against the untouched baseline ciphertext. Also manifest sanity + baseline md5."""
import struct, hashlib, json, zlib, sys
WS = r"C:/Users/xaxka/.zcode/workspace/draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff"
sys.path.insert(0, WS + "/airexplorer-reactor-handoff/work")
import decrypt_prng as dp

data = open(WS + "/airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe", 'rb').read()
md5 = hashlib.md5(data).hexdigest()
print("baseline md5:", md5, "size:", len(data))
assert md5 == "a12b5c573e1b54e98cccc29351eaa066" and len(data) == 9668976

def ks_bytes(n, kd):
    v9 = 0; out = bytearray()
    for w in range(n // 4 + (1 if n % 4 else 0)):
        v9 = dp.u32(v9 + kd[w % 8]); v9 = dp.prng_round(v9)
        out += struct.pack('<I', v9)
    return bytes(out[:n])

CFG = [
    ("Viewer",  0x6213C4, 0x56FE8,   "f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943", "dec_Viewer.bin"),
    ("Project", 0x683FE3, 0x6610,    "00"*32,                                                             "dec_Project.bin"),
    ("Factory", 0x8C4F02, 0x615CA,   "37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a",  "dec_Factory.bin"),
    ("mainlib", 0x68A5F7, 0x23A907,  "cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481",  "dec_mainlib_stream.bin"),
]
ok = 0
for name, off, ln, kh, fn in CFG:
    pt = open(WS + "/work/c2_pack/dec/" + fn, 'rb').read()
    kd = list(struct.unpack('<8I', bytes.fromhex(kh)))
    ct = data[off:off+ln]
    assert len(pt) == ln, (fn, len(pt), ln)
    re_ct = bytes(a ^ b for a, b in zip(pt, ks_bytes(ln, kd)))
    passed = re_ct == ct
    print("%-8s %-24s disk-file re-encrypt == original ct: %s  (sha256 %s)" %
          (name, fn, passed, hashlib.sha256(pt).hexdigest()[:16]))
    assert passed; ok += 1

# mainlib delivered file: inflate from its own stream file must equal it
stream = open(WS + "/work/c2_pack/dec/dec_mainlib_stream.bin", 'rb').read()
plain = open(WS + "/work/c2_pack/dec/dec_mainlib.bin", 'rb').read()
d = zlib.decompressobj(-15); out = d.decompress(stream)
print("dec_mainlib.bin == inflate(dec_mainlib_stream.bin): %s (eof=%s, %dB)" % (out == plain, d.eof, len(plain)))
assert out == plain and d.eof

# passthrough files must equal their resource bytes exactly
for name, off, ln, fn in (("Proc", 0x6784B4, 0xBB2B, "dec_Proc.bin"),
                          ("Emitter", 0x6783B0, 0x100, "dec_Emitter.bin")):
    b = open(WS + "/work/c2_pack/dec/" + fn, 'rb').read()
    eq = b == data[off:off+ln]
    print("%-8s %-18s passthrough == resource bytes: %s" % (name, fn, eq)); assert eq

m = json.load(open(WS + "/work/c2_pack/manifest.json"))
print("manifest resources:", len(m["resources"]),
      "| decrypted:", [r["name"] for r in m["resources"] if r["decrypted"]],
      "| missing:", [r["name"] for r in m["resources"] if not r["decrypted"]])
print("DISK VERIFY: %d/4 keyed roundtrip PASS + mainlib inflate PASS + 2 passthrough exact" % ok)
