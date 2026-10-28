# -*- coding: utf-8 -*-
"""step59: verify candidate AES-256 keys against res5 known plaintext pair.
C = res5 ciphertext, P = res5 plaintext (from runtime static _ExtractorVisitors).
CBC relation (no IV needed): D_K(C_i) ^ C_{i-1} == P_i  for i>=1.
"""
import sys, glob, os
from Crypto.Cipher import AES

C = open('/workspace/repo_git/work/s5/res5_FactoryValidator.bin', 'rb').read()
P = open('/tmp/v2art/app/dump/stat2__ExtractorVisitors.bin', 'rb').read()
assert len(C) == len(P), (len(C), len(P))
print('pair len=%d  C[0:16]=%s  P[0:16]=%s' % (len(C), C[:16].hex(), P[:16].hex()))

def test_key(k):
    """return fraction of tested blocks matching CBC relation"""
    aes = AES.new(k, AES.MODE_ECB)
    hits = 0; tot = 0
    for i in range(1, 9):
        ci = C[16*i:16*i+16]; cim1 = C[16*(i-1):16*i]; pi = P[16*i:16*i+16]
        if len(ci) < 16: break
        d = aes.decrypt(ci)
        if bytes(x ^ y for x, y in zip(d, cim1)) == pi: hits += 1
        tot += 1
    return hits, tot

def test_key_ecb(k):
    aes = AES.new(k, AES.MODE_ECB)
    hits = 0; tot = 0
    for i in range(0, 8):
        ci = C[16*i:16*i+16]; pi = P[16*i:16*i+16]
        if len(ci) < 16: break
        if aes.decrypt(ci) == pi: hits += 1
        tot += 1
    return hits, tot

def recover_iv(k):
    aes = AES.new(k, AES.MODE_ECB)
    return bytes(x ^ y for x, y in zip(aes.decrypt(C[:16]), P[:16]))

def scan(cands, label):
    print('--- scanning %d %s candidates ---' % (len(cands), label))
    found = []
    for j, k in enumerate(cands):
        if len(k) != 32: continue
        h, t = test_key(k)
        if h:
            he, te = test_key_ecb(k)
            print('CAND key#%d CBC %d/%d  ECB %d/%d  k=%s' % (j, h, t, he, te, k.hex()))
            found.append((k, h, t))
    return found

if __name__ == '__main__':
    cands = []
    # 1) from cens dump files: data offset 16, len 32 files
    pat = sys.argv[1] if len(sys.argv) > 1 else '/tmp/v3art/app/dump'
    for f in glob.glob(os.path.join(pat, '*cens32_*.bin')) + glob.glob(os.path.join(pat, '*_arr32.bin')):
        b = open(f, 'rb').read()
        if len(b) >= 48: cands.append(b[16:48])
    # 2) raw hex keys passed on cmdline
    for hx in sys.argv[2:]:
        cands.append(bytes.fromhex(hx))
    f = scan(cands, 'key')
    for k, h, t in f:
        if h == t:
            iv = recover_iv(k)
            print('FULL MATCH key=%s IV=%s' % (k.hex(), iv.hex()))
