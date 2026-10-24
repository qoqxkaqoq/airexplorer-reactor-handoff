#!/usr/bin/env python3
# mdrva.py — 纯解析 PE/CLI 元数据, 打印 MethodDef RVA
# 用法: python3 mdrva.py <exe> <tokhex> [tokhex...]
import struct, sys

def main():
    exe = sys.argv[1]
    toks = [int(t, 16) for t in sys.argv[2:]]
    d = open(exe, 'rb').read()
    e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
    coff = e_lfanew + 4
    nsec, = struct.unpack_from('<H', d, coff + 2)
    optsz, = struct.unpack_from('<H', d, coff + 16)
    opt = coff + 20
    magic, = struct.unpack_from('<H', d, opt)
    ddoff = opt + (0x60 if magic == 0x10B else 0x70)
    clr_rva, clr_sz = struct.unpack_from('<II', d, ddoff + 14 * 8)
    # sections
    sec0 = opt + optsz
    secs = []
    for i in range(nsec):
        o = sec0 + i * 40
        va, vsz = struct.unpack_from('<I', d, o + 12)[0], struct.unpack_from('<I', d, o + 8)[0]
        raw, rawsz = struct.unpack_from('<I', d, o + 20)[0], struct.unpack_from('<I', d, o + 16)[0]
        secs.append((va, vsz, raw, rawsz))
    def rva2off(rva):
        for va, vsz, raw, rawsz in secs:
            if va <= rva < va + max(vsz, rawsz):
                return raw + (rva - va)
        raise ValueError('rva %x' % rva)
    cor = rva2off(clr_rva)
    md_rva, md_sz = struct.unpack_from('<II', d, cor + 8)
    mo = rva2off(md_rva)
    assert struct.unpack_from('<I', d, mo)[0] == 0x424A5342
    vlen, = struct.unpack_from('<I', d, mo + 12)
    p = mo + 16 + vlen
    nstr, = struct.unpack_from('<H', d, p + 2)
    p += 4
    streams = {}
    for i in range(nstr):
        so, ssz = struct.unpack_from('<II', d, p)
        nm = d[p + 8:d.index(b'\0', p + 8)].decode()
        streams[nm] = (mo + so, ssz)
        p += 8 + len(nm) + 1
        p = (p + 3) & ~3
    tto, tsz = streams['#~']
    hs = d[tto + 6]
    si = 4 if hs & 1 else 2
    gi = 4 if hs & 2 else 2
    bi = 4 if hs & 4 else 2
    valid, = struct.unpack_from('<Q', d, tto + 8)
    rows = {}
    p = tto + 24
    for b in range(64):
        if valid & (1 << b):
            rows[b], = struct.unpack_from('<I', d, p)
            p += 4
    # coded index sizes
    def ci_size(tables):
        return 4 if any(rows.get(t, 0) > 0xFFFF for t in tables) else 2
    RS = ci_size([0x00, 0x1A, 0x23, 0x01])          # ResolutionScope
    TDOR = ci_size([0x02, 0x01, 0x1B])              # TypeDefOrRef
    RSZ, GSZ, BSZ = si, gi, bi
    fsz = {
        0x00: 2 + RSZ + 3 * GSZ,                    # Module
        0x01: RS + RSZ + RSZ,                       # TypeRef
        0x02: 4 + RSZ + RSZ + TDOR + ci_size([0x04]) + ci_size([0x06]),  # TypeDef
        0x03: ci_size([0x04]),                      # FieldPtr
        0x04: 2 + RSZ + BSZ,                        # Field
        0x05: ci_size([0x06]),                      # MethodPtr
        0x06: 4 + 2 + 2 + RSZ + BSZ + ci_size([0x08]),  # MethodDef
    }
    # 定位 MethodDef 行区
    off = p
    for b in sorted(fsz):
        if b >= 0x06:
            break
        if b in rows:
            off += fsz[b] * rows[b]
    mrow = fsz[0x06]
    n = rows.get(0x06, 0)
    for tok in toks:
        rid = tok & 0xFFFFFF
        if 1 <= rid <= n:
            ro = off + (rid - 1) * mrow
            rva, = struct.unpack_from('<I', d, ro)
            namei, = struct.unpack_from('<I' if RSZ == 4 else '<H', d, ro + 8)
            # #Strings 名字
            so, _ = streams['#Strings']
            nm = d[so + namei:d.index(b'\0', so + namei)]
            print('0600%06X rva=0x%08X sizeHintRva=0x%08X name=%s' % (rid, rva, rva, nm.decode('utf8', 'replace')))
        else:
            print('0600%06X out of range (n=%d)' % (rid, n))

main()
