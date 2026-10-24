using System;
using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;

// a1inplace <in.exe> <out.exe>
// A1 激活补丁 —— PE 原位字节补丁版（布局保持型，零破坏）。
// 背景（rootcause 2026-10-22 BROADCAST）：任何 dnlib 全量重写都会把 .text 尾部
// ~3.2MB Reactor 加密负载当空隙丢掉（resave 阴性对照也崩 InvalidProgram）。
// 所以这里 dnlib 只读（定位 MethodDef RVA），改动直接写原文件字节：
//   P1 06002133 @IL 0x290  ldc.i4.0(0x16) -> ldc.i4.1(0x17)  (_IsDecoratorProvider 降级点)
//   P2 06002145 @IL 0x120  同上
//   P3 0600212A  原位体覆写 {17 2A}   (SendFlexibleAttribute => true, 7B tiny)
//   P4 06002157  同上                 (PlanRandomTag => true, 7B tiny)
//   P5 06002127  同上                 (TestCollector => 1, 20B tiny)
// 体覆写 = tiny 头改 size=2 (0x0A) + {17 2A} + 0x00 垫到原长（0x00 是 nop，尾部 nop 无害）。
// 前提（dscan 已验证）：这 5 个方法在 baseline_verified(A12B5C57) 里静态 IL 与
// JIT dump 一致（原位明文，不是 5808 个空壳成员）。
class A1Inplace {
    struct T { public string tok; public int off; public string mode; public string why; }
    static void Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: a1inplace <in.exe> <out.exe>"); return; }
        var mod = ModuleDefMD.Load(a[0]);
        var bytes = File.ReadAllBytes(a[0]);

        var targets = new List<T> {
            new T { tok="06002133", off=0x290, mode="byte16to17", why="P1 downgrade->true" },
            new T { tok="06002145", off=0x120, mode="byte16to17", why="P2 downgrade->true" },
            new T { tok="0600212A", off=-1, mode="body17ret", why="P3 SendFlexibleAttribute=>true" },
            new T { tok="06002157", off=-1, mode="body17ret", why="P4 PlanRandomTag=>true" },
            new T { tok="06002127", off=-1, mode="body17ret", why="P5 TestCollector=>1" },
        };

        int ok = 0, fail = 0;
        foreach (var t in targets) {
            var m = mod.ResolveToken(uint.Parse(t.tok, System.Globalization.NumberStyles.HexNumber)) as MethodDef;
            if (m == null) { Console.WriteLine("[FAIL] " + t.tok + " resolve"); fail++; continue; }
            uint rva = (uint)m.RVA;
            if (rva == 0) { Console.WriteLine("[FAIL] " + t.tok + " rva=0"); fail++; continue; }
            int fo = RvaToOff(bytes, rva);
            if (fo < 0) { Console.WriteLine("[FAIL] " + t.tok + " rva->off"); fail++; continue; }
            byte h = bytes[fo];
            int hdr, ilLen;
            if ((h & 3) == 2) { hdr = 1; ilLen = h >> 2; }
            else { hdr = 4 * (h >> 4); ilLen = BitConverter.ToInt16(bytes, fo + 4); }
            int ilStart = fo + hdr;

            if (t.mode == "byte16to17") {
                if (bytes[ilStart + t.off] != 0x16) {
                    Console.WriteLine("[MISMATCH] " + t.tok + " +" + t.off.ToString("X") + " got " +
                        bytes[ilStart + t.off].ToString("X2") + " (" + t.why + ")"); fail++; continue;
                }
                bytes[ilStart + t.off] = 0x17;
                Console.WriteLine("[OK] " + t.tok + " +" + t.off.ToString("X") + " 16->17 (" + t.why + ")");
            } else {
                // body17ret: tiny 头 size=2, {17 2A}, 0x00 垫满原长
                if ((h & 3) != 2 || ilLen > 63) {
                    Console.WriteLine("[SKIP] " + t.tok + " not-tiny hdr=" + h.ToString("X2") + " ilLen=" + ilLen); fail++; continue;
                }
                bytes[fo] = (byte)((2 << 2) | 2);
                for (int i = 0; i < ilLen; i++) bytes[ilStart + i] = i < 2 ? new byte[]{0x17, 0x2A}[i] : (byte)0;
                Console.WriteLine("[OK] " + t.tok + " body " + ilLen + "B -> {17 2A} (" + t.why + ")");
            }
            ok++;
        }
        Console.WriteLine("[a1inplace] ok=" + ok + " fail=" + fail);
        if (fail == 0) { File.WriteAllBytes(a[1], bytes); Console.WriteLine("[out] " + a[1]); }
    }

    static int RvaToOff(byte[] d, uint rva) {
        uint pe = BitConverter.ToUInt32(d, 0x3C);
        int nsec = BitConverter.ToUInt16(d, (int)pe + 6);
        int optsz = BitConverter.ToUInt16(d, (int)pe + 20);
        int secs = (int)pe + 24 + optsz;
        for (int i = 0; i < nsec; i++) {
            int s = secs + i * 40;
            uint vsz = BitConverter.ToUInt32(d, s + 8), va = BitConverter.ToUInt32(d, s + 12);
            uint rsz = BitConverter.ToUInt32(d, s + 16), ro = BitConverter.ToUInt32(d, s + 20);
            if (rva >= va && rva < va + vsz) {
                if (rva - va >= rsz) return -1; // 在未映射尾部
                return (int)(ro + (rva - va));
            }
        }
        return -1;
    }
}
