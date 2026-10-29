#!/usr/bin/env python3
# step236: a19b = baseline + P1/P2 (file-level) + P3/P4/P5 (res0 DB record-hijack CBC surgery) + sentinel re-sign
# 无需 KEY/IV：CBC 明文块 P_j 由 C_{j-1} 异或控制（P'_j = P_j ^ Δ），代价 = 前驱块 P_{j-1} 变随机（祭品块）
# 劫持语义：祭品记录 S（16B 对齐、n 不变）改 rva:=目标RVA、data[0:3]:=0a 17 2a(tiny ldc.i4.1;ret)
#   DB 顺序回填 → 后写覆盖先写 → 目标方法体 = tiny return-true；S 自身与前驱块方法均为探针环境已损坏类型（零边际损害）
import struct, hashlib, subprocess, dnfile

BASE = '/root/repo_git/exes/AirExplorer_baseline_verified.exe'
PRIV = '/root/work/step194/newkey1024.pem'
SIG_OFF = 0x927C88
PT = open('/root/work/step231/res0_plain_full.bin', 'rb').read()
OUT = PT[8:]

pe = dnfile.dnPE(BASE)
exe0 = open(BASE, 'rb').read()
res_rva = pe.net.struct.ResourcesRva
secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
def rva2off(rva):
    for va, vsz, praw, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return praw + (rva - va)
base = rva2off(res_rva)
res_off = {}
for r in pe.net.mdtables.ManifestResource.rows:
    o = base + r.Offset
    ln = struct.unpack_from('<I', exe0, o)[0]
    res_off[str(r.Name)] = o + 4
R0 = res_off['ErrorReceiver.ValidatorViewer']
assert exe0[R0:R0+356328] == open('/root/work/step194/res_ext/res0_356328.bin','rb').read(), 'res0 in exe != extracted'

# ---- parse DB ----
off = 16
recs = []
while off < len(OUT):
    rva, n = struct.unpack_from('<II', OUT, off)
    if rva == 0 and n == 0: break
    recs.append((rva, n, off))
    off += 8 + 4*n
assert off == len(OUT) and len(recs) == 14407
db = {ho: (rva, n) for rva, n, ho in recs}

# ---- P1/P2 file-level (IL+0x290 / IL+0x120, DB 覆盖区外) ----
tok2rva = {}
for i, row in enumerate(pe.net.mdtables.MethodDef.rows):
    tok2rva[0x06000001 + i] = row.Rva
exe = bytearray(exe0)
for tok, deep, want_off in ((0x06002133, 0x290, 0x194524), (0x06002145, 0x120, 0x197af0)):
    rva = tok2rva[tok]
    fo = rva2off(rva)
    p = fo + 12 + deep   # fat header 12B + IL offset
    assert p == want_off, (hex(tok), hex(p), hex(want_off))
    assert exe[p] == 0x16, (hex(tok), hex(exe[p]))
    exe[p] = 0x17
    print('P-file %s @0x%x: 0x16 -> 0x17' % (hex(tok), p))

# ---- P3/P4/P5 record hijack ----
# (name, target_rva, min_hdr_off, S_hdr_off)  S 均为 broken-type(LocalObjectTree/LoggerBridge)，前驱块 data-only 且 owner 亦 broken
HIJACKS = [
    ('P5_06002127', 0x195CD4, 254032),  # S tok 060038BA LocalObjectTree  n=5
    ('P3_0600212A', 0x195D18, 254144),  # S tok 060038BE LocalObjectTree  n=5
    ('P4_06002157', 0x19A510, 257296),  # S tok 0600396B LoggerBridge     n=2
]
ct = bytearray(exe[R0:R0+356328])   # = res0 file bytes (8B head + 356320B ct)
for name, trva, sho in HIJACKS:
    srva, n = db[sho]
    assert sho % 16 == 0 and n >= 1
    j = sho // 16
    old_pt = OUT[16*j:16*j+16]                     # 明文块 P_j = S 记录头+data[0:8]
    assert old_pt[:4] == struct.pack('<I', srva) and old_pt[4:8] == struct.pack('<I', n)
    new = bytearray(old_pt)
    struct.pack_into('<I', new, 0, trva)          # rva := target
    assert bytes(new[4:8]) == old_pt[4:8]         # n unchanged (walk safe)
    new[8] = 0x0A; new[9] = 0x17; new[10] = 0x2A  # tiny hdr(codesize 2) + ldc.i4.1 + ret
    delta = bytes(a ^ b for a, b in zip(new, old_pt))
    # XOR delta into C_{j-1} = ct[8+16*(j-1) : 8+16*j]  (密文从 8B 头之后开始！)
    #   -> P'_j = P_j ^ Δ controlled; P_{j-1} garbled (sacrificial data-only block)
    for i in range(16):
        ct[8 + 16*(j-1) + i] ^= delta[i]
    print('%s: target rva=%s via S@out[%d] blk=%d n=%d  dC=%s' % (name, hex(trva), sho, j, n, delta.hex()))
exe[R0:R0+356328] = ct

# ---- a18 pubkey replacement (new RSA-1024 pubkey XML -> AES re-encrypt -> res1 region) ----
import base64, os
KEY = bytes.fromhex('d8f47a2592dd52540fa7d978fc90ce2acd3929d7c56520bcc89d1c26edcb810e')
IV  = bytes.fromhex('fc7ae2e62b0fdf486fc6230410a90b78')
RES_OFF = rva2off(base + 0) if False else None
# resource data offset for 'ValidatorArgument.EmitterReporter' (== 0x6783B0)
RES_OFF = res_off['ValidatorArgument.EmitterReporter']
assert RES_OFF == 0x6783B0, hex(RES_OFF)
mod_hex = subprocess.run(['openssl','rsa','-in',PRIV,'-noout','-modulus'],
                         capture_output=True, text=True).stdout.strip().split('=')[1]
mod = bytes.fromhex(mod_hex); assert len(mod) == 128
mod_b64 = base64.b64encode(mod).decode()
xml_plain = ('<RSAKeyValue><Modulus>%s</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>' % mod_b64).encode()
pad = 256 - len(xml_plain); assert 1 <= pad <= 16
open('/tmp/px19c.bin','wb').write(xml_plain + bytes([pad])*pad)
subprocess.run(['openssl','enc','-aes-256-cbc','-K',KEY.hex(),'-iv',IV.hex(),
                '-in','/tmp/px19c.bin','-out','/tmp/cx19c.bin','-nopad'], check=True)
cipher = open('/tmp/cx19c.bin','rb').read(); assert len(cipher) == 256
exe[RES_OFF:RES_OFF+256] = cipher
print('pubkey resource replaced @0x%x (xml %dB pad %d)' % (RES_OFF, len(xml_plain), pad))

# ---- sentinel re-sign (a18 pipeline: sign DigestInfo||H, NOT bare H) ----
def sentinel_sha1(buf):
    h = hashlib.sha1()
    h.update(buf[0:0x98])
    b = bytearray(buf[0x98:0xF8]); b[64:68] = b'\0'*4; h.update(bytes(b))
    b = bytearray(buf[0xF8:0x178]); b[32:40] = b'\0'*8; h.update(bytes(b))
    h.update(buf[0x178:0x1F0])
    h.update(buf[0x200:SIG_OFF]); h.update(buf[SIG_OFF+128:0x927E00])
    h.update(buf[0x927E00:0x935E00])
    h.update(buf[0x935E00:0x936000])
    return h.digest()
H = sentinel_sha1(exe)
print('H(a19c) =', H.hex())
DI = bytes.fromhex('3021300906052b0e03021a05000414')
open('/tmp/di19c.bin','wb').write(DI + H)
subprocess.run(['openssl','rsautl','-sign','-inkey',PRIV,'-in','/tmp/di19c.bin','-out','/tmp/sig19c.bin'], check=True)
sig = open('/tmp/sig19c.bin','rb').read()
assert len(sig) == 128
exe[SIG_OFF:SIG_OFF+128] = sig[::-1]

# ---- full sentinel simulation (a18 style) ----
n = int.from_bytes(mod, 'big'); e = 65537
xml_back = subprocess.run(['openssl','enc','-d','-aes-256-cbc','-K',KEY.hex(),'-iv',IV.hex(),
                '-in','/dev/stdin','-out','/dev/stdout','-nopad'],
                input=bytes(exe[RES_OFF:RES_OFF+256]), capture_output=True).stdout
xml_rt = xml_back[:-xml_back[-1]]
assert xml_rt == xml_plain
H2 = sentinel_sha1(exe); assert H2 == H
v24 = bytes(exe[SIG_OFF:SIG_OFF+128])[::-1]
m = pow(int.from_bytes(v24,'big'), e, n).to_bytes(128,'big')
z = m.find(b'\x00', 2)
assert m[:2] == b'\x00\x01' and m[z+1:] == DI + H2, 'PKCS1 structure mismatch'
print('FULL SENTINEL SIMULATION: PASS (decrypt->xml->VerifyHash structure)')

outp = '/root/repo_git/exes/AirExplorer_a19c.exe'
open(outp,'wb').write(bytes(exe))
import hashlib as hh
print('written:', outp, 'md5=', hh.md5(bytes(exe)).hexdigest().upper())
