#!/usr/bin/env python3
# step235: v27 快照精确判据 KEY 暴破（step232 零值/文本门限判据有漏检风险，换精确匹配）
# 判据（2^-256 假阳性）: D_K(B1)^B0 == out[16:32] && D_K(B2)^B1 == out[32:48]
#   B0/B1/B2 = res0[8:56]（密文块 C0/C1/C2）; out = res0 明文（mtk6b PT[8:] 实证 14407 记录闭合）
# 附 IV 推导: IV = out[0:16] ^ D_K(B0)（P0 已知）
# 扫描: 8B 步进, A256(32B 窗) + A128(16B 窗); 对象 = v27 inv_snap_0-49 + mtk6b snap_all_3-11
import sys, os, glob, struct, multiprocessing as mp

RES0 = open('/root/work/step194/res_ext/res0_356328.bin', 'rb').read()
PT = open('/root/work/step231/res0_plain_full.bin', 'rb').read()
OUT = PT[8:]
B0 = RES0[8:24]; B1 = RES0[24:40]; B2 = RES0[40:56]
P2E = OUT[16:32]; P3E = OUT[32:48]; P0E = OUT[0:16]
assert len(P2E) == 16 and len(P3E) == 16

_G = {}
def init_worker():
    from Crypto.Cipher import AES
    _G['AES'] = AES

def scan256(args):
    lo, hi, bts = args
    AES = _G['AES']; new = AES.new; ecb = AES.MODE_ECB
    hits = []
    for off in range(lo, hi, 8):
        key = bts[off:off+32]
        if len(key) < 32: break
        d = new(key, ecb)
        p2 = bytes(a ^ b for a, b in zip(d.decrypt(B1), B0))
        if p2 == P2E:
            p3 = bytes(a ^ b for a, b in zip(d.decrypt(B2), B1))
            if p3 == P3E:
                iv = bytes(a ^ b for a, b in zip(d.decrypt(B0), P0E))
                hits.append((off, key.hex(), iv.hex(), 'A256'))
                print('*** KEY FOUND @%d key=%s iv=%s' % (off, key.hex(), iv.hex()), flush=True)
    return hits

def scan128(args):
    lo, hi, bts = args
    AES = _G['AES']; new = AES.new; ecb = AES.MODE_ECB
    hits = []
    for off in range(lo, hi, 8):
        key = bts[off:off+16]
        if len(key) < 16: break
        d = new(key, ecb)
        p2 = bytes(a ^ b for a, b in zip(d.decrypt(B1), B0))
        if p2 == P2E:
            p3 = bytes(a ^ b for a, b in zip(d.decrypt(B2), B1))
            if p3 == P3E:
                iv = bytes(a ^ b for a, b in zip(d.decrypt(B0), P0E))
                hits.append((off, key.hex(), iv.hex(), 'A128'))
                print('*** KEY FOUND @%d key=%s iv=%s' % (off, key.hex(), iv.hex()), flush=True)
    return hits

def run_one(path, nw):
    bts = open(path, 'rb').read()
    print('== %s bytes=%d' % (os.path.basename(path), len(bts)), flush=True)
    allhits = []
    n = len(bts) - 32
    chunk = max(1 << 20, (n // nw) // 16 * 8 or 8)
    jobs = [(a, min(a + chunk, n), bts) for a in range(0, n, chunk)]
    with mp.Pool(nw, initializer=init_worker) as pool:
        for hits in pool.imap_unordered(scan256, jobs):
            allhits.extend(hits)
    n16 = len(bts) - 16
    chunk16 = max(1 << 20, (n16 // nw) // 16 * 8 or 8)
    jobs16 = [(a, min(a + chunk16, n16), bts) for a in range(0, n16, chunk16)]
    with mp.Pool(nw, initializer=init_worker) as pool:
        for hits in pool.imap_unordered(scan128, jobs16):
            allhits.extend(hits)
    print('   done hits=%d' % len(allhits), flush=True)
    if allhits:
        with open(path + '.exact.txt', 'w') as f:
            for off, k, iv, tag in allhits:
                f.write('off=%d key=%s iv=%s tag=%s\n' % (off, k, iv, tag))
    return allhits

def main():
    targets = sorted(glob.glob('/root/work/step231/snaps/inv_snap_*.bin'),
                     key=lambda p: int(p.rsplit('_', 1)[1].split('.')[0]))
    targets += sorted(glob.glob('/tmp/mtk6b/s5probe-baseline_verified/app/dump/snap_all_*.bin'),
                      key=lambda p: int(''.join(c for c in os.path.basename(p) if c.isdigit())))
    nw = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    tot = []
    for path in targets:
        tot += run_one(path, nw)
    print('ALL DONE total hits =', len(tot), flush=True)
    return 0

if __name__ == '__main__':
    sys.exit(main())
