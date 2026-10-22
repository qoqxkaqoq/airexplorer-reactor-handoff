using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// injectstr: 把 398KB 的 _ExtractorVisitors 字节表追加到 exe 尾部, 并把
// DispatcherInitializer::SearchStrategy(Stream,int) 的方法体替换成"从自身文件读这段字节"。
//
// 为什么走文件而不是 FieldRVA: v10 的元数据表被 Reactor 的 TrackCompiler 用写死的
// token 绑定, 任何表重排都会炸; 而字节级补丁只动 MethodDef.RVA 列, 表行号零变化。
//
// 生成 IL (maxstack=5, 无局部变量):
//   ldsfld automatedError ; callvirt get_Location
//   ldc.i4 3 ; ldc.i4 1 ; newobj FileStream(string,FileMode,FileAccess)
//   ldc.i4 LEN ; newarr byte ; dup ; stsfld _ExtractorVisitors
//   ldc.i4 0 ; ldc.i4 LEN ; callvirt Stream::Read(byte[],int,int) ; pop ; pop ; ret
//
// 用法: injectstr <in.exe> <out.exe> <extractor.bin> [typeName] [methodName]
class InjectStr {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: injectstr <in.exe> <out.exe> <extractor.bin> [type] [method]"); return; }
        string inPath = a[0], outPath = a[1], binPath = a[2];
        string typeName = a.Length > 3 ? a[3] : "CloudClient.Templating.DispatcherInitializer";
        string methName = a.Length > 4 ? a[4] : "SearchStrategy";

        var blob = File.ReadAllBytes(binPath);
        Console.WriteLine("[bin] " + blob.Length + " bytes");

        var mod = ModuleDefMD.Load(inPath);
        var t = mod.Find(typeName, false);
        if (t == null) { Console.WriteLine("[err] type not found: " + typeName); return; }
        var m = t.Methods.FirstOrDefault(x => x.Name == methName);
        if (m == null) { Console.WriteLine("[err] method not found: " + methName); return; }

        var fExtractor = t.Fields.FirstOrDefault(x => x.Name == "_ExtractorVisitors");
        var fAsm = t.Fields.FirstOrDefault(x => x.Name == "automatedError");
        if (fExtractor == null || fAsm == null) { Console.WriteLine("[err] fields not found"); return; }

        // 找 token: Assembly::get_Location / FileStream::.ctor / Stream::Read / byte TypeRef
        uint tokLocation = 0, tokCtor = 0, tokRead = 0, tokByte = 0;
        foreach (var mr in mod.GetMemberRefs()) {
            var s = mr.FullName;
            if (s == "System.String System.Reflection.Assembly::get_Location()") tokLocation = mr.MDToken.Raw;
            if (s == "System.Void System.IO.FileStream::.ctor(System.String,System.IO.FileMode,System.IO.FileAccess)") tokCtor = mr.MDToken.Raw;
            if (s == "System.Int32 System.IO.Stream::Read(System.Byte[],System.Int32,System.Int32)") tokRead = mr.MDToken.Raw;
        }
        foreach (var tr in mod.GetTypeRefs())
            if (tr.FullName == "System.Byte") { tokByte = tr.MDToken.Raw; break; }
        Console.WriteLine("[tok] get_Location=0x" + tokLocation.ToString("X8") + " FileStream=" + tokCtor.ToString("X8")
                          + " Stream.Read=" + tokRead.ToString("X8") + " Byte=" + tokByte.ToString("X8"));
        if (tokLocation == 0 || tokCtor == 0 || tokRead == 0 || tokByte == 0) { Console.WriteLine("[err] token missing"); return; }

        var tab = mod.TablesStream.MethodTable;
        Console.WriteLine("[target] " + typeName + "::" + methName + " rid=" + m.MDToken.Rid
                          + " oldInsn=" + (m.HasBody ? m.Body.Instructions.Count : 0));

        // 1) 读文件, 截到 last section 末尾 (丢签名)
        var data = File.ReadAllBytes(inPath);
        var pe = new Pe(data);
        var last = pe.Sections.OrderBy(x => x.PointerToRawData).Last();
        long baseLen = (long)last.PointerToRawData + last.SizeOfRawData;
        if (data.Length > baseLen) Console.WriteLine("[pe] 丢弃尾部 " + (data.Length - baseLen) + " 字节(签名)");
        var ms = new MemoryStream();
        ms.Write(data, 0, (int)baseLen);

        // 2) 追加 blob (4 字节对齐)
        while ((ms.Length & 3) != 0) ms.WriteByte(0);
        long blobOff = ms.Length;
        ms.Write(blob, 0, blob.Length);
        Console.WriteLine("[pe] blob @ fileOff=0x" + blobOff.ToString("X") + " len=" + blob.Length);

        // 3) 生成 IL
        var il = new List<byte>();
        void E(byte b) { il.Add(b); }
        void T(byte op, uint tok) { il.Add(op); il.Add((byte)tok); il.Add((byte)(tok >> 8)); il.Add((byte)(tok >> 16)); il.Add((byte)(tok >> 24)); }
        void I4(int v) { il.Add(0x20); il.Add((byte)v); il.Add((byte)(v >> 8)); il.Add((byte)(v >> 16)); il.Add((byte)(v >> 24)); }

        T(0x7E, fAsm.MDToken.Raw);            // ldsfld automatedError
        T(0x6F, tokLocation);                 // callvirt Assembly::get_Location
        E(0x19);                              // ldc.i4.3  FileMode.Open
        E(0x17);                              // ldc.i4.1  FileAccess.Read
        T(0x73, tokCtor);                     // newobj FileStream
        I4(blob.Length);                      // ldc.i4 len
        T(0x8D, tokByte);                     // newarr byte
        E(0x25);                              // dup
        T(0x80, fExtractor.MDToken.Raw);      // stsfld _ExtractorVisitors
        E(0x16);                              // ldc.i4.0
        I4(blob.Length);                      // ldc.i4 len
        T(0x6F, tokRead);                     // callvirt Stream::Read
        E(0x26);                              // pop
        E(0x26);                              // pop
        E(0x2A);                              // ret
        Console.WriteLine("[il] " + il.Count + " bytes  maxstack=5");

        // 4) 追加方法体 (fat header)
        while ((ms.Length & 3) != 0) ms.WriteByte(0);
        long bodyOff = ms.Length;
        long rva = last.VirtualAddress + (bodyOff - last.PointerToRawData);
        ushort flags = (ushort)(0x3 | (3 << 12));
        W16(ms, flags); W16(ms, 5); W32(ms, (uint)il.Count); W32(ms, 0);
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
        BitConverter.GetBytes(chars | 0x40000000u | 0x20000000u).CopyTo(outBytes, last.HeaderOff + 36);

        // 5) 改 MethodDef.RVA
        long off = (long)tab.StartOffset + (long)((int)m.MDToken.Rid - 1) * tab.RowSize;
        BitConverter.GetBytes((uint)rva).CopyTo(outBytes, (int)off);
        Console.WriteLine("[pe] new body RVA=0x" + rva.ToString("X") + "  MethodTable off=0x" + tab.StartOffset.ToString("X"));

        File.WriteAllBytes(outPath, outBytes);
        Console.WriteLine("[out] " + outPath + " size=" + outBytes.Length);
    }

    static void W16(Stream s, ushort v) { s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8)); }
    static void W32(Stream s, uint v) { s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8)); s.WriteByte((byte)(v >> 16)); s.WriteByte((byte)(v >> 24)); }
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
