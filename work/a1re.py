#!/usr/bin/env python3
# a1re.py — A1 两字节补丁: 在 exe 资源区定位条目 ct → known-plaintext 重加密 → 原位回写
# 用法: python3 work/a1re.py <exe> <v8ent_json或内联>
# 数据源:
#   dump 库 m_06002133.bin/m_06002145.bin = 纯 body 明文
#   v8 [V8] ENT 行 = rbx + ct hex (CTBASE+rbx 起 0x400B)
# 补丁语义:
#   06002133 body[0x290] 0x16→0x17 (ldc.i4.0→1, 写 _IsDecoratorProvider=false 降级点)
#   06002145 body[0x120] 0x16→0x17 (同款)
import struct, sys, json, re

PATCHES = [
    {"tok": "06002133", "body_off": 0x290, "old": 0x16, "new": 0x17, "fat": True},
    {"tok": "06002145", "body_off": 0x120, "old": 0x16, "new": 0x17, "fat": True},
]

def rva2off(d, rva):
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    st = pe + 24 + optsz
    for i in range(nsec):
        o = st + i * 40
        vsz, va, rsz, pr = struct.unpack_from('<4I', d, o + 8)
        if va <= rva < va + max(vsz, rsz):
            return rva - va + pr
    raise SystemExit('rva2off fail 0x%x' % rva)

def cor20_off(d):
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    magic = struct.unpack_from('<H', d, pe + 24)[0]
    dd = pe + 24 + (96 if magic == 0x10B else 112)
    rva, size = struct.unpack_from('<2I', d, dd + 14 * 8)
    return rva

def resource_entries(d):
    """cor20 资源区逐条 (名字, 数据文件偏移, 大小) — 与 reslist.py 同格式"""
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    cli_rva = struct.unpack_from('<I', d, pe + 24 + 96 + 14 * 8)[0]  # DD[14] → CLI header
    co = rva2off(d, cli_rva)
    res_rva, res_size = struct.unpack_from('<II', d, co + 24)  # CLI头: cb(4) ver(4) Meta(8) Flags(4) EP(4) → ResRVA@24
    base = rva2off(d, res_rva)
    end = base + res_size
    out = []
    p = base
    while p < end - 8:
        off, size = struct.unpack_from('<II', d, p)
        if off == 0 and size == 0:
            break
        q = p + 8
        nlen = struct.unpack_from('<I', d, q)[0]
        name = d[q + 4:q + 4 + nlen].decode('utf-8', 'replace')
        out.append((name, base + off, size))
        p = q + 4 + nlen
        p = (p + 3) & ~3
    return out, base

def main():
    exe = sys.argv[1]
    ent_json = sys.argv[2] if len(sys.argv) > 2 else None
    d = bytearray(open(exe, 'rb').read())
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    cli_rva = struct.unpack_from('<I', d, pe + 24 + 96 + 14 * 8)[0]
    secs = []
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    for i in range(nsec):
        o = pe + 24 + optsz + 40 * i
        vsz, va, rsz, ro = struct.unpack_from('<4I', d, o + 8)
        secs.append((va, vsz, ro, rsz))
    co = None
    for va, vsz, ro, rsz in secs:
        if va <= cli_rva < va + max(vsz, rsz):
            co = ro + cli_rva - va
    res_rva, res_size = struct.unpack_from('<II', d, co + 24)
    res_base = None
    for va, vsz, ro, rsz in secs:
        if va <= res_rva < va + max(vsz, rsz):
            res_base = ro + res_rva - va
    print('cor20 resources @0x%x size=0x%x' % (res_base, res_size))

    # res_*.bin 内容指纹定位 (目录格式被 Reactor 改过, 不解析)
    import glob, hashlib, os
    wd = os.path.dirname(os.path.abspath(__file__))
    resfiles = sorted(glob.glob(os.path.join(wd, 'res_*.bin')))
    viewer = None
    for rf in resfiles:
        rd = open(rf, 'rb').read()
        frag = rd[:32]
        pos = d.find(frag, res_base - 0x1000)
        if pos < 0:
            pos = d.find(frag)
        print('  %-46s size=0x%06x exe@%s md5=%s' % (os.path.basename(rf), len(rd),
              ('0x%x (res+0x%x)' % (pos, pos - res_base)) if pos >= 0 else '<NOT FOUND>',
              hashlib.md5(rd).hexdigest()[:8]))
        if 'ValidatorViewer' in rf:
            viewer = (rf, pos, len(rd))
    if not viewer:
        raise SystemExit('Viewer resource not found')
    rf, voff, vsz = viewer
    vdata = bytearray(d[voff:voff + vsz])
    if len(vdata) != vsz:
        raise SystemExit('viewer slice size mismatch')

    # v8 ENT 数据解析
    if ent_json:
        ents8 = json.load(open(ent_json))
    else:
        raw = sys.stdin.read().strip() if not sys.stdin.isatty() else ''
        if not raw:
            raise SystemExit('无 ENT 数据。用法: python3 work/a1re.py <exe> ent.json\n'
                             'ent.json 格式: {"06002133":{"rbx":"0x..","ct":"<hex>"},"06002145":{...}}\n'
                             '(无 ENT 时本脚本仅做资源指纹定位打印, 已验证 6 资源全部可定位)')
        ents8 = json.loads(raw)
    for p in PATCHES:
        e = ents8.get(p['tok'])
        if not e:
            print('%s: no v8 ENT data, SKIP' % p['tok'])
            continue
        rbx = int(e['rbx'], 16)
        ct = bytes.fromhex(e['ct'])
        body = open('/tmp/dumps/m_%s.bin' % p['tok'], 'rb').read()[24:]
        # 定位 ct[0:16] 在 Viewer 资源内的偏移 (校准: 应 == rbx)
        frag = ct[:16]
        rel = vdata.find(frag)
        print('%s: rbx=0x%x ct[:16]=%s res-rel=%s %s' % (p['tok'], rbx, frag.hex(),
              ('0x%x' % rel) if rel >= 0 else '<not found>',
              'OK' if rel == rbx else ('SHIFT=%d' % (rel - rbx) if rel >= 0 else '')))
        if rel < 0:
            print('  ct 不在 Viewer 资源原文 → 驱动器缓冲是变换后的, 需 v7 反汇编; SKIP')
            continue
        base = rel
        # patch 位置: 条目头 10B? + fat hdr 12B + body_off —— 需确定 ct 起点.
        # 假设 H_a: ct = 加密(fat hdr + body), ct 起点 = 条目+0xA
        # (由 v6: r10 初值 = rbx+0xA, 首写 = fat hdr dword0 → ct[0:4] 解密为 hdr dword0)
        il_off = p['body_off'] + 12  # fat hdr 12B
        # ct 从条目 0xA 起 → patch 位置 = base(条目起点) + 0xA + il_off
        ctpos = base + 0xA + il_off
        cur = vdata[ctpos]
        exp_ks = cur ^ p['old']
        newc = exp_ks ^ p['new']
        print('  H_a: ctpos=0x%x cur=%02x (expect %02x) ks=%02x new_ct=%02x' % (ctpos, cur, p['old'], exp_ks, newc))
        if cur != p['old']:
            print('  !! cur != old — 假设偏移有误, 打印邻域人工核对:')
            print('  ctx[-8:+8] =', vdata[ctpos - 8:ctpos].hex(), '|', vdata[ctpos:ctpos + 8].hex())
            continue
        vdata[ctpos] = newc
        # 回写 exe
        d[voff:voff + vsz] = vdata
        outp = exe.replace('.exe', '_a1.exe')
        open(outp, 'wb').write(d)
        print('  PATCHED %s body[%#x] %02x→%02x; wrote %s' % (p['tok'], p['body_off'], p['old'], p['new'], outp))

if __name__ == '__main__':
    main()
