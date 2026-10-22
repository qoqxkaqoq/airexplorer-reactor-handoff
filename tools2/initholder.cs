using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// initholder: 把 hostdump 导出的 holder 单例字段值，写成一段"硬编码构造"的 IL，
// 替换掉原来那个调用 InstantiateStatelessUser 解释器的初始化方法。
//
// 为什么必须字节级: v9 的元数据表被反篡改数据(token 写死在 FieldRVA 里)绑定,
// dnlib 的 Write 会重排/丢行, 所以只追加代码 + 改 MethodDef.RVA 列。
//
// 用法: initholder <in.exe> <out.exe> <holder.tsv> [holderTypeSubstr]
class InitHolder {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: initholder <in.exe> <out.exe> <holder.tsv> [holderSubstr]"); return; }
        string inPath = a[0], outPath = a[1], tsv = a[2];
        string holderSub = a.Length > 3 ? a[3] : "<Module>{a8c2e9b2";

        // 1) 读 TSV
        var vals = new Dictionary<string, int>();
        foreach (var l in File.ReadAllLines(tsv)) {
            var p = l.Split('|');
            if (p.Length < 6) continue;
            if (p[0] != "I") continue;
            if (p[1].IndexOf(holderSub, StringComparison.Ordinal) < 0) continue;
            if (p[4] != "Int32") continue;
            if (!p[2].StartsWith("m_0d0b145b", StringComparison.Ordinal)) continue;   // 只取单例那一层
            int v;
            if (!int.TryParse(p[5], out v)) continue;
            vals[p[3]] = v;
        }
        Console.WriteLine("[tsv] holder int fields = " + vals.Count);
        if (vals.Count == 0) { Console.WriteLine("[err] no values"); return; }

        // 2) 解析模块
        var mod = ModuleDefMD.Load(inPath);
        TypeDef holder = null;
        foreach (var t in mod.GetTypes())
            if (t.FullName.IndexOf(holderSub, StringComparison.Ordinal) >= 0) { holder = t; break; }
        if (holder == null) { Console.WriteLine("[err] holder type not found"); return; }

        var ctor = holder.FindDefaultConstructor();
        if (ctor == null) { Console.WriteLine("[err] .ctor not found"); return; }

        FieldDef singleton = null;
        if (holder.HasFields)
            foreach (var f in holder.Fields)
                if (f.FieldType.FullName == holder.FullName) { singleton = f; break; }
        if (singleton == null) { Console.WriteLine("[err] singleton field not found"); return; }
        Console.WriteLine("[type] " + holder.FullName + "  ctor=0x" + ctor.MDToken.Raw.ToString("X8")
                          + "  singleton=" + singleton.Name);

        // 3) 找要被替换的初始化方法: holder 的 .cctor 里最后一个 call 的目标
        MethodDef init = null;
        var cc = holder.FindStaticConstructor();
        if (cc != null && cc.HasBody) {
            for (int i = cc.Body.Instructions.Count - 1; i >= 0; i--) {
                var ins = cc.Body.Instructions[i];
                if (ins.OpCode.Code == Code.Call || ins.OpCode.Code == Code.Callvirt) {
                    var m = ins.Operand as IMethod;
                    if (m != null && m.DeclaringType == holder && m.Name != ".cctor") { init = m.ResolveMethodDef(); break; }
                }
            }
        }
        if (init == null) { Console.WriteLine("[err] init method not found"); return; }
        Console.WriteLine("[target] " + init.Name + "  oldBody=" + (init.HasBody ? init.Body.Instructions.Count + " insn" : "none"));

        // 4) 生成 IL
        var il = new List<byte>();
        void Emit(byte b) { il.Add(b); }
        void EmitTok(byte op, uint tok) { il.Add(op); il.Add((byte)tok); il.Add((byte)(tok >> 8)); il.Add((byte)(tok >> 16)); il.Add((byte)(tok >> 24)); }
        void EmitI4(int v) {
            if (v >= -1 && v <= 8) { Emit((byte)(0x16 + v)); return; }
            if (v >= sbyte.MinValue && v <= sbyte.MaxValue) { Emit(0x1F); Emit((byte)(sbyte)v); return; }
            Emit(0x20); Emit((byte)v); Emit((byte)(v >> 8)); Emit((byte)(v >> 16)); Emit((byte)(v >> 24));
        }

        EmitTok(0x73, ctor.MDToken.Raw);           // newobj holder::.ctor
        int emitted = 0;
        var missing = new List<string>();
        foreach (var kv in vals) {
            var f = holder.Fields.FirstOrDefault(x => x.Name == kv.Key);
            if (f == null) { missing.Add(kv.Key); continue; }
            Emit(0x25);                             // dup
            EmitI4(kv.Value);                       // ldc.i4 value
            EmitTok(0x7D, f.MDToken.Raw);           // stfld
            emitted++;
        }
        EmitTok(0x80, singleton.MDToken.Raw);       // stsfld singleton
        Emit(0x2A);                                 // ret

        Console.WriteLine("[il] stfld emitted = " + emitted + "  missing=" + missing.Count
                          + "  ilBytes=" + il.Count + "  maxstack=3");
        if (missing.Count > 0) Console.WriteLine("[warn] missing fields: " + string.Join(",", missing.Take(5)));

        // 5) 追加到文件末尾 (fat header, maxstack=3, locals=0, eh=0)
        var data = File.ReadAllBytes(inPath);
        var pe = new Pe(data);
        var last = pe.Sections.OrderBy(x => x.PointerToRawData).Last();
        long baseLen = (long)last.PointerToRawData + last.SizeOfRawData;
        if (data.Length != baseLen && data.Length > baseLen)
            Console.WriteLine("[pe] 丢弃尾部 " + (data.Length - baseLen) + " 字节(签名)");

        var ms = new MemoryStream();
        ms.Write(data, 0, (int)baseLen);
        long pos = (ms.Length + 3) & ~3L;
        while (ms.Length < pos) ms.WriteByte(0);
        long rva = last.VirtualAddress + (pos - last.PointerToRawData);

        // fat header: flags = 0x3 | (3 << 12) = 0x3003
        ushort flags = (ushort)(0x3 | (3 << 12));
        WriteU16(ms, flags);
        WriteU16(ms, 3);                            // maxstack
        WriteU32(ms, (uint)il.Count);               // codeSize
        WriteU32(ms, 0);                            // localVarSigTok
        ms.Write(il.ToArray(), 0, il.Count);
        while ((ms.Length & 3) != 0) ms.WriteByte(0);

        long want = (long)last.PointerToRawData + Align((uint)(ms.Length - last.PointerToRawData), pe.FileAlignment);
        while (ms.Length < want) ms.WriteByte(0);
        var outBytes = ms.ToArray();

        uint newRaw = Align((uint)(outBytes.Length - last.PointerToRawData), pe.FileAlignment);
        uint newVirt = (uint)(outBytes.Length - last.PointerToRawData);
        BitConverter.GetBytes(newVirt).CopyTo(outBytes, last.HeaderOff + 8);
        BitConverter.GetBytes(newRaw).CopyTo(outBytes, last.HeaderOff + 16);
        uint newImage = Align(last.VirtualAddress + newVirt, pe.SectionAlignment);
        int peOff = BitConverter.ToInt32(outBytes, 0x3C);
        BitConverter.GetBytes(newImage).CopyTo(outBytes, peOff + 24 + 56);
        uint chars = BitConverter.ToUInt32(outBytes, last.HeaderOff + 36);
        BitConverter.GetBytes(chars | 0x40000000u | 0x20000000u).CopyTo(outBytes, last.HeaderOff + 36); // readable+exec

        // 6) 改 MethodDef.RVA 列
        var tab = mod.TablesStream.MethodTable;
        long off = (long)tab.StartOffset + (long)((int)init.MDToken.Rid - 1) * tab.RowSize;
        BitConverter.GetBytes((uint)rva).CopyTo(outBytes, (int)off);
        Console.WriteLine("[pe] " + init.Name + " rid=" + init.MDToken.Rid + " RVA=0x" + rva.ToString("X")
                          + "  (MethodTable off=0x" + tab.StartOffset.ToString("X") + " rowSize=" + tab.RowSize + ")");

        File.WriteAllBytes(outPath, outBytes);
        Console.WriteLine("[out] " + outPath + " size=" + outBytes.Length);
    }

    static void WriteU16(Stream s, ushort v) { s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8)); }
    static void WriteU32(Stream s, uint v) { s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8)); s.WriteByte((byte)(v >> 16)); s.WriteByte((byte)(v >> 24)); }
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
