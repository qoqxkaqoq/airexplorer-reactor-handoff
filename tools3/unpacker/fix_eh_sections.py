#!/usr/bin/env python3
"""
fix_eh_sections.py — S1 写出后处理（修复19）：
扫描产物全部 MoreSects 方法体，修复 dnlib 写出的畸形 EH 段头
（flags=0x01 缺 EHTable 位 0x40 + DataSize=4+12n 的 small 子句）。
用法: python3 fix_eh_sections.py <in.exe> <out.exe> <allrva.tsv>
  allrva.tsv 由 `dumpall <exe> <out>` 生成（tok\\trva 两列）
"""
import struct, sys

def main():
    inp, outp, rvaList = sys.argv[1], sys.argv[2], sys.argv[3]
    pe = bytearray(open(inp, 'rb').read())
    e = struct.unpack_from('<I', pe, 0x3C)[0]; opt = e+4+20
    nsec = struct.unpack_from('<H', pe, e+6)[0]; optsz = struct.unpack_from('<H', pe, e+20)[0]
    ss = []
    for i in range(nsec):
        o = opt+optsz+i*40
        vs, va, rs, rp = struct.unpack_from('<IIII', pe, o+8)
        ss.append((va, vs, rp, rs))
    def r2o(rva):
        for va, vs, rp, rs in ss:
            if va <= rva < va+max(vs, rs): return rp+rva-va
    fixed = scanned = skipped = 0
    for line in open(rvaList):
        parts = line.split()
        if len(parts) < 2: continue
        rva = int(parts[1], 16)
        if rva == 0: continue
        fo = r2o(rva)
        if fo is None or fo+9 > len(pe): continue
        f16 = pe[fo] | (pe[fo+1] << 8)
        if (f16 & 8) == 0: continue  # 无 MoreSects
        hsz = ((pe[fo+1] >> 4) & 0xF) * 4
        cs = struct.unpack_from('<I', pe, fo+4)[0]
        if cs <= 0 or cs > 0x100000 or fo+hsz+cs+40 > len(pe): skipped += 1; continue
        scanned += 1
        eh = (fo + hsz + cs + 3) & ~3
        if eh+20 > len(pe): skipped += 1; continue
        hdr = pe[eh]
        if (hdr & 1) and not (hdr & 0x40):  # FatFormat 但缺 EHTable = 畸形
            dsize = pe[eh+1] | (pe[eh+2] << 8) | (pe[eh+3] << 16)
            if dsize < 16 or dsize > 0x10000: skipped += 1; continue
            nc = (dsize - 4) // 12
            if eh+4+12*nc > len(pe): skipped += 1; continue
            clause = bytes(pe[eh+4:eh+4+12*nc])
            pe[eh] = 0x40 | (dsize >> 2)  # small 段头: EHTable + size/4
            pe[eh+1:eh+1+len(clause)] = clause
            tail = 1 + len(clause)
            for k in range(((eh+tail+3)&~3) - (eh+tail)): pe[eh+tail+k] = 0
            fixed += 1
    print(f"[fix19] MoreSects={scanned} fixed={fixed} skipped={skipped}")
    open(outp, 'wb').write(bytes(pe))

if __name__ == '__main__':
    main()
