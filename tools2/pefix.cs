using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.MD;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Reflection.Metadata.Ecma335;
using System.IO;

// pefix <in.exe> <out.exe>
// 文件级修复: MemberRef/Field 的签名 blob 里官方用 MVAR(0x13) 编码类级泛型参数(畸形, CLR JIT 拒绝)
// → 把 blob 字节 13 → 1E (VAR 类级)。同 blob 共享(所有 List<T>::Add 同 sig)一次全修。
// 逐 blob 做"类型位置"扫描, 避免误伤压缩整数/名字长度。
class Pefix {
    static void Main(string[] a) {
        byte[] data = System.IO.File.ReadAllBytes(a[0]);
        var mod = (ModuleDefMD)ModuleDefMD.Load(a[0]);
        var blobStream = mod.BlobStream;
        long blobFileOff = (long)blobStream.StartOffset;   // #Blob 流在文件里的起始 offset

        int fixedBlobs = 0, mrefs = 0, flds = 0;
        var patched = new HashSet<uint>();           // 已改的 blob offset

        // SRM 遍历 MemberRef / Field 表, 拿 sig blob heap offset
        using (var fs = new FileStream(a[0], FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var pe = new PEReader(fs)) {
            var md = pe.GetMetadataReader();
            foreach (var h in md.MemberReferences) {
                var mr = md.GetMemberReference(h);
                uint off = (uint)MetadataTokens.GetHeapOffset(mr.Signature);
                if (patched.Contains(off)) continue;
                if (FixBlob(data, blobFileOff, off, patched)) { fixedBlobs++; mrefs++; }
            }
            foreach (var h in md.FieldDefinitions) {
                var fd = md.GetFieldDefinition(h);
                uint off = (uint)MetadataTokens.GetHeapOffset(fd.Signature);
                if (patched.Contains(off)) continue;
                if (FixBlob(data, blobFileOff, off, patched)) { fixedBlobs++; flds++; }
            }
        }
        Console.WriteLine("[pefix] fixedBlobs=" + fixedBlobs + " (memberRef-sig=" + mrefs + " field-sig=" + flds + ")");
        Console.WriteLine("[pefix] fixedBlobs=" + fixedBlobs + " (memberRef-sig=" + mrefs + " field-sig=" + flds + ")");
        System.IO.File.WriteAllBytes(a[1], data);
        Console.WriteLine("[pefix] wrote " + a[1]);
    }

    // 在 blob 的"类型位置"把 0x13(MVAR) 改为 0x1E(VAR)。成功返回 true
    static bool FixBlob(byte[] data, long blobFileOff, uint off, HashSet<uint> patched) {
        // 读 blob 长度头(compressed uint)
        long fo = blobFileOff + off;
        uint len;
        int hdr;
        byte b0 = data[fo];
        if (b0 < 0x80) { len = b0; hdr = 1; }
        else if ((b0 & 0xC0) == 0x80) { len = (uint)(((b0 & 0x3F) << 8) | data[fo + 1]); hdr = 2; }
        else if ((b0 & 0xE0) == 0xC0) { len = (uint)(((b0 & 0x1F) << 24) | (data[fo+1] << 16) | (data[fo+2] << 8) | data[fo+3]); hdr = 4; }
        else return false;
        int sigStart = (int)(off + (uint)hdr);
        long sigFile = blobFileOff + sigStart;
        var ctx = new Ctx { data = data, sigFile = sigFile, end = (int)len, patched = patched, off = off, changed = false };
        try {
            // MethodSig/FieldSig: 第一字节 callconv
            byte cc = data[sigFile];
            int p = 1;
            if ((cc & 0x10) != 0) p += CompLen(data, sigFile + p);          // generic: genParamCount
            // retType
            if (!SkipType(ctx, ref p)) return ctx.changed;                   // 解析失败则保留已改字节(安全: 类型位置才改)
            if ((cc & 0x0F) != 0x06) {                                       // 0x06=field sig(无参数)
                // property? MemberRef 不含; 跳过参数列表: MethodSig 的参数个数是压缩数
                if ((cc & 0x0F) == 0x00 || (cc & 0x0F) == 0x05 || (cc & 0x0F) == 0x01) {
                    int nParams = CompVal(data, sigFile + p, out int adv); p += adv;
                    for (int i = 0; i < nParams; i++) if (!SkipType(ctx, ref p)) return ctx.changed;
                }
            }
        } catch { }
        return ctx.changed;
    }

    class Ctx { public byte[] data; public long sigFile; public int end; public HashSet<uint> patched; public uint off; public bool changed; }

    // 解析一个"类型编码", 在 MVAR 位置改 1E。失败返回 false(停止后续)
    static bool SkipType(Ctx c, ref int p) {
        if (p >= c.end) return false;
        byte op = c.data[c.sigFile + p];
        p++;
        switch (op) {
            case 0x13: // MVAR → VAR(类级) — 官方畸形编码, CLR JIT 拒绝
                c.data[c.sigFile + p - 1] = 0x1E;
                c.changed = true;
                c.patched.Add(c.off);
                p += CompLen(c.data, c.sigFile + p); // num
                return true;
            case 0x1E: p += CompLen(c.data, c.sigFile + p); return true;      // VAR
            case 0x1D: return SkipType(c, ref p);                              // SZARRAY
            case 0x0F: case 0x0E: return SkipType(c, ref p);                   // BYREF/PTR
            case 0x45: { // GENERICINST
                p += 1;                                                        // CLASS/VALUETYPE 字节
                p += CompLen(c.data, c.sigFile + p);                           // TypeRef/TypeSpec token (4B compressed)
                int n = CompVal(c.data, c.sigFile + p, out int adv); p += adv;
                for (int i = 0; i < n; i++) if (!SkipType(c, ref p)) return false;
                return true;
            }
            case 0x11: case 0x12:                                             // VALUETYPE/CLASS
                p += CompLen(c.data, c.sigFile + p);
                return true;
            case 0x1F: { // FNPTR: 完整 method sig
                byte cc2 = c.data[c.sigFile + p]; p++;
                if ((cc2 & 0x10) != 0) p += CompLen(c.data, c.sigFile + p);
                if (!SkipType(c, ref p)) return false;
                int n2 = CompVal(c.data, c.sigFile + p, out int adv2); p += adv2;
                for (int i = 0; i < n2; i++) if (!SkipType(c, ref p)) return false;
                return true;
            }
            case 0x16: case 0x17: case 0x18:
            case 0x1C: case 0x0D: case 0x0C: case 0x0B: case 0x0A:            // CMOD/内建
            case 0x09: case 0x08: case 0x07: case 0x06: case 0x05:
            case 0x04: case 0x03: case 0x02: case 0x01:
            case 0x19: case 0x1B: case 0x22: case 0x24: case 0x25:
            case 0x28: case 0x2D:
                if (op == 0x14 || op == 0x15) { p += CompLen(c.data, c.sigFile + p); return SkipType(c, ref p); } // CMOD 后跟类型
                return true;                                                   // 单字节原语
            default:
                return op <= 0x25 || op == 0x28 || op == 0x2D;                 // 未知则放弃
        }
    }
    static int CompLen(byte[] d, long p) { return d[p] < 0x80 ? 1 : ((d[p] & 0xC0) == 0x80 ? 2 : 4); }
    static int CompVal(byte[] d, long p, out int adv) {
        byte b = d[p];
        if (b < 0x80) { adv = 1; return b; }
        if ((b & 0xC0) == 0x80) { adv = 2; return ((b & 0x3F) << 8) | d[p + 1]; }
        adv = 4; return ((b & 0x1F) << 24) | (d[p+1] << 16) | (d[p+2] << 8) | d[p+3];
    }
}
