#!/usr/bin/env python3
# step238: a19f = baseline + 06004231 DisableBuilder stub + 06002127 stub-fix + a18 sentinel
# PATH E 实证链 (mem run 41032166900/41036543078 + lic 40977519875/40978814317):
#  1) 运行时方法体 ≠ .text 文件 (0600212A: 运行时 7B getter vs .text 桩 120000172a) → 回填器写"影子区"并运行时重定向 MethodDef RVA
#  2) .text 官方桩本身: P3 0600212A = 12 00 00 17 2a (nop nop ldc.i4.1 ret = return true!), P4 同构;
#     P5 06002127 桩 = 22 00 14 a5... (initobj null 坏桩, 需修为 return true)
#  3) DisableBuilder(06004231) = Marshal.WriteInt32 薄包装 (15B tiny: nop ldarg.0 ldarg.1 call 0x0A000A24 ret),
#     全 exe 仅 419C 两处调用 (file 0x402acc/0x4046e1 = 走库循环) — a19b AV @ DisableBuilder = 走库写入器实锤
#  → stub DisableBuilder = 影子写入 + MethodDef RVA 重定向 (同为 WriteInt32) 全部消失 → .text 桩全量生效 → P3/P4 return true = 激活
import struct, hashlib, subprocess, dnfile

BASE = '/root/repo_git/exes/AirExplorer_baseline_verified.exe'
PRIV = '/root/work/step194/newkey1024.pem'
SIG_OFF = 0x927C88

pe = dnfile.dnPE(BASE)
exe0 = open(BASE, 'rb').read()
secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
def rva2off(rva):
    for va, vsz, praw, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return praw + (rva - va)
res_rva = pe.net.struct.ResourcesRva
base = rva2off(res_rva)
res_off = {}
for r in pe.net.mdtables.ManifestResource.rows:
    o = base + r.Offset
    ln = struct.unpack_from('<I', exe0, o)[0]
    res_off[str(r.Name)] = o + 4
R0 = res_off['ErrorReceiver.ValidatorViewer']
tok2rva = {}
for i, row in enumerate(pe.net.mdtables.MethodDef.rows):
    tok2rva[0x06000001 + i] = row.Rva
exe = bytearray(exe0)

# ---- patch 1: 06004231 DisableBuilder stub (tiny 15B IL -> nop*14 + ret) ----
fo = rva2off(tok2rva[0x06004231])
h = exe[fo]
assert (h & 3) == 2 and (h >> 2) == 15, hex(h)
old = bytes(exe[fo+1:fo+1+15])
assert old == bytes.fromhex('00fe090000fe09010028240a000a2a'), old.hex()
new_il = bytes([0x00]*14 + [0x2A])   # nop*14; ret (等长, void 签名, caller 清栈)
exe[fo+1:fo+1+15] = new_il
print('DisableBuilder 06004231 stubbed @file 0x%x: %s -> %s' % (fo, old.hex(), new_il.hex()))

# ---- patch 2: 06002127 (P5) stub-fix: initobj-null 坏桩 -> return true (等长 tiny 8B IL) ----
fo = rva2off(tok2rva[0x06002127])
h = exe[fo]
assert (h & 3) == 2 and (h >> 2) == 8, hex(h)
old = bytes(exe[fo+1:fo+1+8])
assert old == bytes.fromhex('0014a58b0500022a'), old.hex()
new_il = bytes([0x17, 0x2A] + [0x00]*6)   # ldc.i4.1; ret; nop*6 (等长)
exe[fo+1:fo+1+8] = new_il
print('P5 06002127 stub fixed @file 0x%x: %s -> %s' % (fo, old.hex(), new_il.hex()))

# ---- patch 3: verify P3/P4 stubs are already return-true (no touch) ----
for tok in (0x0600212A, 0x06002157):
    fo = rva2off(tok2rva[tok])
    il = bytes(exe[fo+1:fo+1+4])
    assert il == bytes.fromhex('0000172a'), (hex(tok), il.hex())
    print('P3/P4 0600%04X stub verified as nop nop ldc.i4.1 ret (untouched)' % (tok & 0xFFFF))

# ---- res0 untouched assertion ----
assert bytes(exe[R0:R0+356328]) == exe0[R0:R0+356328], 'res0 must be untouched'
print('res0 region: 0 bytes changed')

# ---- a18 pubkey replacement ----
import base64
KEY = bytes.fromhex('d8f47a2592dd52540fa7d978fc90ce2acd3929d7c56520bcc89d1c26edcb810e')
IV  = bytes.fromhex('fc7ae2e62b0fdf486fc6230410a90b78')
RES_OFF = res_off['ValidatorArgument.EmitterReporter']
assert RES_OFF == 0x6783B0, hex(RES_OFF)
mod_hex = subprocess.run(['openssl','rsa','-in',PRIV,'-noout','-modulus'],
                         capture_output=True, text=True).stdout.strip().split('=')[1]
mod = bytes.fromhex(mod_hex); assert len(mod) == 128
mod_b64 = base64.b64encode(mod).decode()
xml_plain = ('<RSAKeyValue><Modulus>%s</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>' % mod_b64).encode()
pad = 256 - len(xml_plain); assert 1 <= pad <= 16
open('/tmp/px19f.bin','wb').write(xml_plain + bytes([pad])*pad)
subprocess.run(['openssl','enc','-aes-256-cbc','-K',KEY.hex(),'-iv',IV.hex(),
                '-in','/tmp/px19f.bin','-out','/tmp/cx19f.bin','-nopad'], check=True)
cipher = open('/tmp/cx19f.bin','rb').read(); assert len(cipher) == 256
exe[RES_OFF:RES_OFF+256] = cipher
print('pubkey resource replaced @0x%x (xml %dB pad %d)' % (RES_OFF, len(xml_plain), pad))

# ---- sentinel re-sign (a18 pipeline: DigestInfo||H) ----
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
print('H(a19f) =', H.hex())
DI = bytes.fromhex('3021300906052b0e03021a05000414')
open('/tmp/di19f.bin','wb').write(DI + H)
subprocess.run(['openssl','rsautl','-sign','-inkey',PRIV,'-in','/tmp/di19f.bin','-out','/tmp/sig19f.bin'], check=True)
sig = open('/tmp/sig19f.bin','rb').read()
assert len(sig) == 128
exe[SIG_OFF:SIG_OFF+128] = sig[::-1]

# ---- full sentinel simulation ----
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

# ---- expected lic verdicts ----
print('lic expectations: P3 rva 0x195D18 b0b1b2=00 00 17 | P4 0x19A510=00 00 17 | P5 0x195CD4+1: 17 2a | DisableBuilder: stubbed')
print('mem expectations (mode=mem C): 0600212A len=4 head=0000172a | 06002157 len=4 head=0000172a | 06002127 head=172a')

outp = '/root/repo_git/exes/AirExplorer_a19f.exe'
open(outp,'wb').write(bytes(exe))
import hashlib as hh
print('written:', outp, 'md5=', hh.md5(bytes(exe)).hexdigest().upper())
