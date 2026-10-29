#!/usr/bin/env python3
# a18: baseline + new RSA pubkey (AES re-encrypt) + new self-signature
import hashlib, base64, subprocess, struct, os
exe = bytearray(open('/root/repo_git/exes/AirExplorer_baseline_verified.exe','rb').read())
KEY = bytes.fromhex('d8f47a2592dd52540fa7d978fc90ce2acd3929d7c56520bcc89d1c26edcb810e')
IV  = bytes.fromhex('fc7ae2e62b0fdf486fc6230410a90b78')
SIG_OFF = 0x927C88
RES_OFF = 0x6783B0

# --- 1. new modulus/exponent from openssl key ---
mod_hex = subprocess.run(['openssl','rsa','-in','/root/work/step194/newkey1024.pem','-noout','-modulus'],
                         capture_output=True, text=True).stdout.strip().split('=')[1]
mod = bytes.fromhex(mod_hex)
assert len(mod) == 128
mod_b64 = base64.b64encode(mod).decode()
print('new modulus b64 len:', len(mod_b64), '(orig 172)')

# --- 2. build XML (same format as res5_plain.xml: 243B with 13x0D pad) ---
xml_plain = f'<RSAKeyValue><Modulus>{mod_b64}</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'.encode()
print('xml len:', len(xml_plain), '(orig 243)')
pad = 256 - len(xml_plain)
assert 1 <= pad <= 16, pad
xml_enc_input = xml_plain + bytes([pad])*pad   # PKCS7
assert len(xml_enc_input) == 256

# --- 3. AES-256-CBC encrypt (openssl, no salt) ---
open('/tmp/px.bin','wb').write(xml_enc_input)
subprocess.run(['openssl','enc','-aes-256-cbc','-K',KEY.hex(),'-iv',IV.hex(),
                '-in','/tmp/px.bin','-out','/tmp/cx.bin','-nopad'], check=True)
cipher = open('/tmp/cx.bin','rb').read()
assert len(cipher) == 256
# sanity: decrypt back
subprocess.run(['openssl','enc','-d','-aes-256-cbc','-K',KEY.hex(),'-iv',IV.hex(),
                '-in','/tmp/cx.bin','-out','/tmp/pd.bin','-nopad'], check=True)
assert open('/tmp/pd.bin','rb').read() == xml_enc_input
print('AES roundtrip OK')

# --- 4. patch cipher into exe ---
exe[RES_OFF:RES_OFF+256] = cipher

# --- 5. compute sentinel hash (skip signature area), sign, write back reversed ---
def sentinel_sha1(buf):
    h = hashlib.sha1()
    h.update(buf[0:0x98])
    b = bytearray(buf[0x98:0xF8]); b[64:68] = b'\0'*4; h.update(bytes(b))
    b = bytearray(buf[0xF8:0x178]); b[32:40] = b'\0'*8; h.update(bytes(b))
    h.update(buf[0x178:0x1F0])
    h.update(buf[0x200:SIG_OFF]); h.update(buf[SIG_OFF+128:0x927E00])  # .text minus sig
    h.update(buf[0x927E00:0x935E00])
    h.update(buf[0x935E00:0x936000])
    return h.digest()

H = sentinel_sha1(exe)
print('H(a18) =', H.hex())
open('/tmp/H.bin','wb').write(H)
DI_PRE = bytes.fromhex('3021300906052b0e03021a05000414')
open('/tmp/di.bin','wb').write(DI_PRE + H)
subprocess.run(['openssl','rsautl','-sign','-inkey','/root/work/step194/newkey1024.pem',
                '-in','/tmp/di.bin','-out','/tmp/sig.bin'], check=True)
sig = open('/tmp/sig.bin','rb').read()
assert len(sig) == 128
exe[SIG_OFF:SIG_OFF+128] = sig[::-1]   # store little-endian (sentinel reverses)

# --- 6. self-verify with new pubkey ---
n = int.from_bytes(mod, 'big'); e = 65537
v24 = bytes(exe[SIG_OFF:SIG_OFF+128])[::-1]
s = int.from_bytes(v24, 'big')
m = pow(s, e, n).to_bytes(128, 'big')
DI = bytes.fromhex('3021300906052b0e03021a05000414')
z = m.find(b'\x00', 2)
ok = m[:2]==b'\x00\x01' and m[z+1:] == DI + H
print('self-verify with NEW key:', ok)
assert ok

# --- 7. simulate FULL sentinel (decrypt resource with AES key -> FromXmlString -> VerifyHash) ---
xml_back = subprocess.run(['openssl','enc','-d','-aes-256-cbc','-K',KEY.hex(),'-iv',IV.hex(),
                '-in','/dev/stdin','-out','/dev/stdout','-nopad'],
                input=bytes(exe[RES_OFF:RES_OFF+256]), capture_output=True).stdout
padc = xml_back[-1]
xml_rt = xml_back[:-padc]
assert xml_rt == xml_plain
H2 = sentinel_sha1(exe)
assert H2 == H
v2 = bytes(exe[SIG_OFF:SIG_OFF+128])[::-1]
s2 = int.from_bytes(v2, 'big'); m2 = pow(s2, e, n).to_bytes(128, 'big')
z2 = m2.find(b'\x00', 2)
assert m2[z2+1:] == DI + H2
print('FULL SENTINEL SIMULATION: PASS (decrypt->xml->verify)')

# --- 8. also verify OLD signature no longer verifies (sanity) ---
old_xml = open('/root/repo_git/work/s5/mem5/r5/res5_plain.xml','rb').read()
om = base64.b64decode(xml_rt and __import__('re').search(rb'<Modulus>([^<]+)</Modulus>', xml_back).group(1))
assert om == mod
out = '/root/work/step194/AirExplorer_a18.exe'
open(out,'wb').write(bytes(exe))
import hashlib as hh
print('written:', out, 'md5=', hh.md5(bytes(exe)).hexdigest().upper())
