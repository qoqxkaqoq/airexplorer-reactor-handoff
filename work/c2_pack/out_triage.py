# -*- coding: utf-8 -*-
"""Triage the leftover t26 runtime-capture files OUT_<Res>_<addr>.bin.
Question: does ANY of them contain a Proc/Emitter plaintext (ct/pt pair)?
Method:
  - load baseline, take the 6 resource ct blocks;
  - for every OUT_* file: length, equality/prefix-relation to the resource ct,
    and (for the 4 keyed resources) equality/prefix to OUR keyed decryption
    (positive control: if OUT_Viewer were a runtime pt it must equal dec_Viewer).
  - Proc/Emitter files that differ from ct get a keystream-plausibility probe:
    derive ks = ct^cand for first 8 dwords and check the 9th dword prediction
    requires no key assumption -> impossible without key; instead we only report
    head bytes so a human/agent can judge garbage vs structure.
Read-only; writes work/c2_pack/out_triage_report.txt.
"""
import os, glob, hashlib, struct, sys

WS = r"C:/Users/xaxka/.zcode/workspace/draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff"
BASE = WS + "/airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe"
sys.path.insert(0, WS + "/airexplorer-reactor-handoff/work")
import decrypt_prng as dp

data = open(BASE, 'rb').read()
assert len(data) == 9668976 and hashlib.md5(data).hexdigest() == "a12b5c573e1b54e98cccc29351eaa066"

RES = {
    'Viewer':  (0x6213C4, 0x56FE8),
    'Emitter': (0x6783B0, 0x100),
    'Proc':    (0x6784B4, 0xBB2B),
    'Project': (0x683FE3, 0x6610),
    'mainlib': (0x68A5F7, 0x23A907),
    'Factory': (0x8C4F02, 0x615CA),
}
KEYHEX = {
    'Viewer':  "f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943",
    'mainlib': "cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481",
    'Factory': "37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a",
    'Project': "00" * 32,
}

def decrypt_keyed(blob, kd):
    n = len(blob)//4 + (1 if len(blob) % 4 else 0)
    out = bytearray(); v9 = 0
    for w in range(n):
        v9 = dp.u32(v9 + kd[w % 8]); v9 = dp.prng_round(v9)
        off = w*4
        if w == n-1 and len(blob) % 4:
            rem = len(blob)-off; word = 0
            for j in range(rem):
                if j > 0: word = (word << 8) & 0xFFFFFFFF
                word |= blob[len(blob)-1-j]
            word = dp.u32(word)
        else:
            word = dp.u32(blob[off] | (blob[off+1] << 8) | (blob[off+2] << 16) | (blob[off+3] << 24))
        out += struct.pack('<I', dp.u32(v9 ^ word))
    return bytes(out[:len(blob)])

ct = {k: data[o:o+l] for k, (o, l) in RES.items()}
pt = {k: decrypt_keyed(ct[k], list(struct.unpack('<8I', bytes.fromhex(h)))) for k, h in KEYHEX.items()}

lines = []
def P(s=""): lines.append(s); print(s)

P("== OUT_* triage (baseline md5 verified) ==")
files = sorted(glob.glob(WS + "/work_a1/t26_*/OUT_*.bin"))
P(f"files found: {len(files)}")
for f in files:
    name = os.path.basename(f)
    res = name.split('_')[1]
    b = open(f, 'rb').read()
    c = ct.get(res)
    if c is None:
        P(f"{name:42s} len={len(b):8d}  ?? unknown resource tag"); continue
    tag = []
    if b == c: tag.append("==ct(copy)")
    elif len(b) <= len(c) and c[:len(b)] == b: tag.append("==ct[:len] prefix")
    elif len(b) >= len(c) and b[:len(c)] == c: tag.append("ct+extra")
    else:
        n = min(len(b), len(c))
        i = 0
        while i < n and b[i] == c[i]: i += 1
        tag.append(f"DIFF-from-ct@{i}")
        if res in pt:
            p = pt[res]; m = min(len(b), len(p)); j = 0
            while j < m and b[j] == p[j]: j += 1
            tag.append(f"vs-pt-prefix{j}")
    if res in pt and b == pt[res][:len(b)] and len(b) == len(pt[res]):
        tag.append("*** FULL-PT MATCH ***")
    P(f"{name:42s} len={len(b):8d} reslen={len(c):8d} {' '.join(tag)}  head={b[:16].hex()}")

open(WS + "/work/c2_pack/out_triage_report.txt", 'w').write("\n".join(lines))
print("\nreport -> work/c2_pack/out_triage_report.txt")
