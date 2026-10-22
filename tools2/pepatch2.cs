using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;

// pepatch2: 只在字节层面替换方法体, **不重写元数据表**。
//
// 为什么不用 dnlib 的 Write: 它会把"当前没被引用"的 MemberRef 行整批丢掉
// (实测 5818 -> 2242), 而 Reactor 的 TrackCompiler 用写死在字段 RVA 数据里的
// metadata token 去 ResolveMethod, 行号一变就是
//   ArgumentOutOfRangeException: Token 0x0a000996 is not valid.
//
// 这个工具只做三件事:
//   1) 把新方法体追加到文件末尾(顺带扩展最后一个节的 VirtualSize/SizeOfRawData);
//   2) 改 MethodDef 表的 RVA 列(定长列, 原地 4 字节);
//   3) 丢掉文件尾的 Authenticode 签名(改过就不可能再有效)。
//
// 用法:
//   pepatch2 <in.exe> <out.exe> --ret Type::Method [--ret ...]
//   方法体统一替换成 "ret"(tiny header: 0x06 0x2A)。
class PePatch2 {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: pepatch2 <in> <out> --ret Type::Method ..."); return; }
        string inPath = a[0], outPath = a[1];
        var targets = new List<string>();
        for (int i = 2; i < a.Length; i++)
            if (a[i] == "--ret" && i + 1 < a.Length) targets.Add(a[++i]);

        // 只读加载, 用来把 Type::Method 解析成 rid
        var mod = ModuleDefMD.Load(inPath);
        var rids = new List<KeyValuePair<int, string>>();
        foreach (var spec in targets) {
            var p = spec.Split(new[] { "::" }, StringSplitOptions.None);
            if (p.Length != 2) { Console.WriteLine("[skip] " + spec); continue; }
            var t = mod.Find(p[0], false);
            if (t == null) { Console.WriteLine("[miss] 类型 " + p[0]); continue; }
            var cands = t.Methods.Where(x => x.Name == p[1]).ToList();
            if (cands.Count == 0) { Console.WriteLine("[miss] 方法 " + spec); continue; }
            foreach (var m in cands) rids.Add(new KeyValuePair<int, string>((int)m.MDToken.Rid, spec));
        }

        var tab = mod.TablesStream.MethodTable;
        Console.WriteLine("[pe] MethodTable off=0x" + tab.StartOffset.ToString("X") + " rowSize=" + tab.RowSize + " rows=" + tab.Rows);

        var data = File.ReadAllBytes(inPath);
        var pe = new Pe(data);
        var last = pe.Sections.OrderBy(x => x.PointerToRawData).Last();
        long baseLen = (long)last.PointerToRawData + last.SizeOfRawData;
        Console.WriteLine("[pe] last section=" + last.Name + " rawEnd=" + baseLen + " fileLen=" + data.Length
                          + (data.Length > baseLen ? ("  (丢弃尾部 " + (data.Length - baseLen) + " 字节, 多半是签名)") : ""));

        var ms = new MemoryStream();
        ms.Write(data, 0, (int)baseLen);

        // 追加 ret 体
        var patches = new List<KeyValuePair<int, uint>>();
        foreach (var kv in rids) {
            long pos = (ms.Length + 3) & ~3L;
            while (ms.Length < pos) ms.WriteByte(0);
            long rva = last.VirtualAddress + (pos - last.PointerToRawData);
            ms.WriteByte((1 << 2) | 2);   // tiny header, codeSize=1
            ms.WriteByte(0x2A);           // ret
            patches.Add(new KeyValuePair<int, uint>(kv.Key, (uint)rva));
            Console.WriteLine("[pe] " + kv.Value + "  rid=" + kv.Key + "  -> RVA 0x" + rva.ToString("X"));
        }

        // 文件长度必须覆盖 SizeOfRawData, 否则节区尾部是"截断"的
        long want = (long)last.PointerToRawData + Align((uint)(ms.Length - last.PointerToRawData), pe.FileAlignment);
        while (ms.Length < want) ms.WriteByte(0);
        var outBytes = ms.ToArray();
        // 扩展最后一个节
        uint newRaw = Align((uint)(outBytes.Length - last.PointerToRawData), pe.FileAlignment);
        uint newVirt = (uint)(outBytes.Length - last.PointerToRawData);
        BitConverter.GetBytes(newVirt).CopyTo(outBytes, last.HeaderOff + 8);   // VirtualSize
        BitConverter.GetBytes(newRaw).CopyTo(outBytes, last.HeaderOff + 16);   // SizeOfRawData
        uint newImage = Align(last.VirtualAddress + newVirt, pe.SectionAlignment);
        int peOff = BitConverter.ToInt32(outBytes, 0x3C);
        BitConverter.GetBytes(newImage).CopyTo(outBytes, peOff + 24 + 56);     // SizeOfImage
        uint chars = BitConverter.ToUInt32(outBytes, last.HeaderOff + 36);
        BitConverter.GetBytes(chars | 0x40000000u).CopyTo(outBytes, last.HeaderOff + 36); // readable+

        // 回填 RVA 列
        foreach (var kv in patches) {
            long off = (long)tab.StartOffset + (long)(kv.Key - 1) * tab.RowSize;
            BitConverter.GetBytes(kv.Value).CopyTo(outBytes, (int)off);
        }

        File.WriteAllBytes(outPath, outBytes);
        Console.WriteLine("[pe] 写出 " + outPath + " size=" + outBytes.Length + "  补丁 " + patches.Count + " 处");
    }

    static uint Align(uint v, uint a) { return (v + a - 1) / a * a; }

    class Section { public string Name; public int HeaderOff; public uint VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData; }

    class Pe {
        public List<Section> Sections = new List<Section>();
        public uint SectionAlignment, FileAlignment;
        public Pe(byte[] d) {
            int peOff = BitConverter.ToInt32(d, 0x3C);
            int n = BitConverter.ToUInt16(d, peOff + 6);
            int optSize = BitConverter.ToUInt16(d, peOff + 20);
            int opt = peOff + 24;
            SectionAlignment = BitConverter.ToUInt32(d, opt + 32);
            FileAlignment = BitConverter.ToUInt32(d, opt + 36);
            for (int i = 0; i < n; i++) {
                int o = opt + optSize + i * 40;
                Sections.Add(new Section {
                    Name = System.Text.Encoding.ASCII.GetString(d, o, 8).TrimEnd('\0'),
                    HeaderOff = o,
                    VirtualSize = BitConverter.ToUInt32(d, o + 8),
                    VirtualAddress = BitConverter.ToUInt32(d, o + 12),
                    SizeOfRawData = BitConverter.ToUInt32(d, o + 16),
                    PointerToRawData = BitConverter.ToUInt32(d, o + 20)
                });
            }
        }
    }
}
