using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

// pepatch: 只改方法体字节与 MethodDef.RVA 列, **绝不重写元数据表**。
//
// 为什么必须这么做:
//   Reactor 给类型静态字段做初始化的 TrackCompiler(RuntimeTypeHandle), 会在字段 RVA 数据里
//   写死 metadata token, 再 Module.ResolveMethod(token) 解析。任何"整模块重写"(dnlib Write)
//   都会让 MemberRef/MethodSpec 表重排, 这些 token 立刻失效 ->
//   ArgumentOutOfRangeException: Token 0x0a000996 is not valid.
//
//   而 JIT 收割到的 IL 本来就是**同一个模块**的字节, token 天然一致 —— 所以只要把它们
//   原样放回文件、只改 RVA, 就完全不需要重映射, 也不会破坏任何表。
//
// 用法:
//   pepatch <orig.exe> <dumpdir> <out.exe> [--ret Type::Method ...]
//     --ret  把指定方法体替换成单条 ret (用于中和 Reactor 引导)
class PePatch {
    static void Main(string[] a) {
        string origPath = a[0], dumpDir = a[1], outPath = a[2];
        var rets = new HashSet<string>();
        for (int i = 3; i < a.Length; i++)
            if (a[i] == "--ret" && i + 1 < a.Length) rets.Add(a[++i]);

        var pe = new Pe(origPath);
        Console.WriteLine("[pe] sections=" + pe.Sections.Count + "  fileSize=" + pe.Data.Length);

        int mdOff = pe.RvaToOff(pe.CliMetadataRva);
        var md = new Metadata(pe.Data, mdOff);
        Console.WriteLine("[md] version=" + md.Version + "  streams=" + string.Join(",", md.Streams.Keys));
        Console.WriteLine("[md] MethodDef rows=" + md.MethodRows + "  rowSize=" + md.MethodRowSize
                          + "  tableOff=0x" + md.MethodTableOff.ToString("X"));

        var bodies = new List<byte[]>();
        long cursor = pe.Data.Length;
        // 对齐到 4
        cursor = (cursor + 3) & ~3L;

        var ms = new MemoryStream();
        ms.Write(pe.Data, 0, pe.Data.Length);
        while (ms.Length < cursor) ms.WriteByte(0);

        int written = 0, skipped = 0, retCount = 0;
        var rvaPatches = new List<KeyValuePair<int, uint>>();   // rowIndex -> newRva

        foreach (var file in Directory.GetFiles(dumpDir, "m_*.bin")) {
            var raw = File.ReadAllBytes(file);
            if (raw.Length < 25) { skipped++; continue; }
            uint token = BitConverter.ToUInt32(raw, 0);
            uint ilSize = BitConverter.ToUInt32(raw, 4);
            ushort maxStack = BitConverter.ToUInt16(raw, 8);
            uint ehCount = BitConverter.ToUInt32(raw, 12);
            uint localsTok = BitConverter.ToUInt32(raw, 20);
            if ((token >> 24) != 0x06) { skipped++; continue; }
            int rid = (int)(token & 0xFFFFFF);
            if (rid < 1 || rid > md.MethodRows) { skipped++; continue; }
            if (24 + ilSize > raw.Length) { skipped++; continue; }

            byte[] il = new byte[ilSize];
            Array.Copy(raw, 24, il, 0, ilSize);

            byte[] eh = null;
            string ehFile = Path.ChangeExtension(file, ".eh");
            if (File.Exists(ehFile)) eh = File.ReadAllBytes(ehFile);

            long bodyPos = (ms.Length + 3) & ~3L;
            while (ms.Length < bodyPos) ms.WriteByte(0);
            long bodyRva = pe.NewRva(bodyPos);

            var enc = Encode(il, maxStack, localsTok, eh);
            ms.Write(enc, 0, enc.Length);

            rvaPatches.Add(new KeyValuePair<int, uint>(rid, (uint)bodyRva));
            written++;
        }

        // --ret: 中和指定方法
        foreach (var spec in rets) {
            var parts = spec.Split(new[] { "::" }, StringSplitOptions.None);
            if (parts.Length != 2) { Console.WriteLine("[ret] 跳过非法 " + spec); continue; }
            int rid = md.FindMethod(parts[0], parts[1]);
            if (rid <= 0) { Console.WriteLine("[ret] 未找到 " + spec); continue; }
            long bodyPos = (ms.Length + 3) & ~3L;
            while (ms.Length < bodyPos) ms.WriteByte(0);
            long bodyRva = pe.NewRva(bodyPos);
            // tiny header: (codeSize<<2)|2, code=ret(0x2A)
            ms.WriteByte((1 << 2) | 2);
            ms.WriteByte(0x2A);
            rvaPatches.Add(new KeyValuePair<int, uint>(rid, (uint)bodyRva));
            retCount++;
        }

        var outBytes = ms.ToArray();
        // 扩展最后一个节, 让新 body 落在合法 RVA 区间
        pe.ExtendLastSection(outBytes);
        // 回填 RVA 列
        foreach (var kv in rvaPatches) {
            int off = md.MethodTableOff + (kv.Key - 1) * md.MethodRowSize;
            BitConverter.GetBytes(kv.Value).CopyTo(outBytes, off);
        }

        File.WriteAllBytes(outPath, outBytes);
        Console.WriteLine("[pe] 写回 " + written + " 个方法体, 中和 " + retCount + " 个, 跳过 " + skipped);
        Console.WriteLine("[pe] wrote " + outPath + "  size=" + outBytes.Length);
    }

    // ---------------- 方法体编码 ----------------
    static byte[] Encode(byte[] il, ushort maxStack, uint localsTok, byte[] eh) {
        int clauseCount = 0, clauseSize = 0;
        if (eh != null && eh.Length >= 4) {
            clauseCount = (int)BitConverter.ToUInt32(eh, 0);
            if (clauseCount > 0) clauseSize = (eh.Length - 4) / clauseCount;
        }

        bool tiny = il.Length < 64 && clauseCount == 0 && localsTok == 0 && maxStack <= 8;

        using (var ms = new MemoryStream()) {
            if (tiny) {
                ms.WriteByte((il.Length << 2) | 2);
                ms.Write(il, 0, il.Length);
                return ms.ToArray();
            }

            // fat header: 12 bytes
            ushort flags = (ushort)(0x3000 | 3 | (localsTok != 0 ? 0x10 : 0));  // fat, size=3 dwords, initlocals?
            ms.Write(BitConverter.GetBytes(flags), 0, 2);
            ms.Write(BitConverter.GetBytes(maxStack), 0, 2);
            ms.Write(BitConverter.GetBytes((uint)il.Length), 0, 4);
            ms.Write(BitConverter.GetBytes(localsTok), 0, 4);
            ms.Write(il, 0, il.Length);

            // 4 字节对齐后再放 EH
            while ((ms.Length & 3) != 0) ms.WriteByte(0);

            if (clauseCount > 0) {
                ms.WriteByte(0x41);                       // kind: fat EH
                int dataSize = 4 + clauseCount * 24;
                ms.WriteByte((byte)(dataSize & 0xFF));
                ms.WriteByte((byte)((dataSize >> 8) & 0xFF));
                ms.WriteByte((byte)((dataSize >> 16) & 0xFF));
                ms.WriteByte(0);                          // padding
                for (int i = 0; i < clauseCount; i++) {
                    int b = 4 + i * clauseSize;
                    uint flags2 = BitConverter.ToUInt32(eh, b + 0);
                    uint tryOff = BitConverter.ToUInt32(eh, b + 4);
                    uint tryLen = BitConverter.ToUInt32(eh, b + 8);
                    uint hOff = BitConverter.ToUInt32(eh, b + 12);
                    uint hLen = BitConverter.ToUInt32(eh, b + 16);
                    uint cls = BitConverter.ToUInt32(eh, b + 20);
                    ms.Write(BitConverter.GetBytes(flags2), 0, 4);
                    ms.Write(BitConverter.GetBytes(tryOff), 0, 4);
                    ms.Write(BitConverter.GetBytes(tryLen), 0, 4);
                    ms.Write(BitConverter.GetBytes(hOff), 0, 4);
                    ms.Write(BitConverter.GetBytes(hLen), 0, 4);
                    ms.Write(BitConverter.GetBytes(cls), 0, 4);
                }
            }
            return ms.ToArray();
        }
    }

    // ---------------- PE ----------------
    class Section { public string Name; public uint VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData; public int HeaderOff; }

    class Pe {
        public byte[] Data;
        public List<Section> Sections = new List<Section>();
        public uint SectionAlignment, FileAlignment, SizeOfImage;
        public int SectionTableOff, NumSections, SizeOfOptHeader;
        public uint CliMetadataRva;

        public Pe(string path) {
            Data = File.ReadAllBytes(path);
            int peOff = BitConverter.ToInt32(Data, 0x3C);
            NumSections = BitConverter.ToUInt16(Data, peOff + 6);
            SizeOfOptHeader = BitConverter.ToUInt16(Data, peOff + 20);
            SectionTableOff = peOff + 24 + SizeOfOptHeader;
            var opt = peOff + 24;
            SectionAlignment = BitConverter.ToUInt32(Data, opt + 32);
            FileAlignment = BitConverter.ToUInt32(Data, opt + 36);
            SizeOfImage = BitConverter.ToUInt32(Data, opt + 56);
            for (int i = 0; i < NumSections; i++) {
                int o = SectionTableOff + i * 40;
                var s = new Section {
                    Name = Encoding.ASCII.GetString(Data, o, 8).TrimEnd('\0'),
                    VirtualSize = BitConverter.ToUInt32(Data, o + 8),
                    VirtualAddress = BitConverter.ToUInt32(Data, o + 12),
                    SizeOfRawData = BitConverter.ToUInt32(Data, o + 16),
                    PointerToRawData = BitConverter.ToUInt32(Data, o + 20),
                    HeaderOff = o
                };
                Sections.Add(s);
            }
            // CLI header = DataDirectory[14]
            int dd = opt + 96 + 14 * 8;
            CliMetadataRva = BitConverter.ToUInt32(Data, dd);
        }

        public int RvaToOff(uint rva) {
            foreach (var s in Sections)
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData))
                    return (int)(s.PointerToRawData + (rva - s.VirtualAddress));
            return -1;
        }

        /// 新字节从 Data.Length 起; 把它们映射进最后一个节
        public long NewRva(long fileOffset) {
            var last = Sections.Last();
            return last.VirtualAddress + (fileOffset - last.PointerToRawData);
        }

        public void ExtendLastSection(byte[] outBytes) {
            var last = Sections.Last();
            uint newRawSize = (uint)(outBytes.Length - last.PointerToRawData);
            newRawSize = Align(newRawSize, FileAlignment);
            uint newVirtSize = (uint)(outBytes.Length - last.PointerToRawData);
            BitConverter.GetBytes(newRawSize).CopyTo(outBytes, last.HeaderOff + 16);
            BitConverter.GetBytes(newVirtSize).CopyTo(outBytes, last.HeaderOff + 8);
            uint newImage = Align(last.VirtualAddress + newVirtSize, SectionAlignment);
            int peOff = BitConverter.ToInt32(outBytes, 0x3C);
            BitConverter.GetBytes(newImage).CopyTo(outBytes, peOff + 24 + 56);
            uint chars = BitConverter.ToUInt32(outBytes, last.HeaderOff + 36);
            BitConverter.GetBytes(chars | 0x40000000u).CopyTo(outBytes, last.HeaderOff + 36); // readable
        }

        static uint Align(uint v, uint a) { return (v + a - 1) / a * a; }
    }

    // ---------------- 元数据表 ----------------
    class Metadata {
        public string Version;
        public Dictionary<string, int> Streams = new Dictionary<string, int>();
        public int MethodRows, MethodRowSize, MethodTableOff;
        byte[] d;
        int stringsIdx, guidIdx, blobIdx;      // 2 or 4
        int typeDefRows, typeRefRows, typeSpecRows, moduleRows, fieldRows, paramRows;

        public Metadata(byte[] data, int mdOff) {
            d = data;
            int verLen = BitConverter.ToInt32(d, mdOff + 12);
            Version = Encoding.ASCII.GetString(d, mdOff + 16, verLen).TrimEnd('\0');
            int p = mdOff + 16 + verLen;
            p += 2;                                                    // flags
            int nStreams = BitConverter.ToUInt16(d, mdOff + 2 + 12 - 12 + 2 + 0 + 0); // placeholder, 下面重算
            nStreams = BitConverter.ToUInt16(d, mdOff + 2 + 12 - 2 + 0);  // 简化: 用固定偏移
            nStreams = BitConverter.ToUInt16(d, mdOff + 16 + verLen - 2 - 0 - 0 - 0); // 同上
            // 正确偏移: MD root: Sig(4) Major(2) Minor(2) Reserved(4) VerLen(4) Version VerLen Flags(2) Streams(2)
            nStreams = BitConverter.ToUInt16(d, mdOff + 16 + verLen + 2);

            int so = mdOff + 16 + verLen + 4;
            for (int i = 0; i < nStreams; i++) {
                int off = BitConverter.ToInt32(d, so);
                int size = BitConverter.ToInt32(d, so + 4);
                var sb = new StringBuilder();
                int q = so + 8;
                while (d[q] != 0) sb.Append((char)d[q++]);
                q++;
                q = (q + 3) & ~3;
                Streams[sb.ToString()] = mdOff + off;
                so = q;
            }

            int tables = Streams.ContainsKey("#~") ? Streams["#~"] : Streams["#-"];
            byte heapSizes = d[tables + 6];
            stringsIdx = (heapSizes & 1) != 0 ? 4 : 2;
            guidIdx = (heapSizes & 2) != 0 ? 4 : 2;
            blobIdx = (heapSizes & 4) != 0 ? 4 : 2;

            int valid = BitConverter.ToInt32(d, tables + 8);
            int q2 = tables + 24;
            var rows = new int[64];
            for (int i = 0; i < 64; i++) {
                if ((valid & (1 << i)) == 0) continue;
                rows[i] = BitConverter.ToInt32(d, q2);
                q2 += 4;
            }
            moduleRows = rows[0]; typeRefRows = rows[1]; typeDefRows = rows[2];
            fieldRows = rows[4]; paramRows = rows[8]; typeSpecRows = rows[0x1B];
            MethodRows = rows[6];

            int typeDefOrRefSize = Coded(typeDefRows, typeRefRows, typeSpecRows);
            int resolutionScopeSize = Coded(moduleRows, rows[0x1A], rows[0x23], typeRefRows);
            int simpleParam = paramRows < 65536 ? 2 : 4;
            int simpleField = fieldRows < 65536 ? 2 : 4;
            int simpleMethod = MethodRows < 65536 ? 2 : 4;

            int moduleSize = 2 + stringsIdx + guidIdx * 3;
            int typeRefSize = resolutionScopeSize + stringsIdx * 2;
            int typeDefSize = 4 + stringsIdx * 2 + typeDefOrRefSize + simpleField + simpleMethod;
            int fieldSize = 2 + stringsIdx + blobIdx;
            MethodRowSize = 4 + 2 + 2 + stringsIdx + blobIdx + simpleParam;

            int off2 = tables + 24 + CountSet(valid) * 4;
            off2 += moduleRows * moduleSize;
            off2 += typeRefRows * typeRefSize;
            off2 += typeDefRows * typeDefSize;
            off2 += rows[3] * simpleField;            // FieldPtr
            off2 += fieldRows * fieldSize;
            off2 += rows[5] * simpleMethod;           // MethodPtr
            MethodTableOff = off2;
        }

        static int CountSet(int v) { int n = 0; while (v != 0) { n += v & 1; v >>= 1; } return n; }
        static int Coded(params int[] rows) {
            int max = rows.Max();
            return max < (1 << 14) ? 2 : 4;
        }

        public int FindMethod(string typeFull, string methodName) {
            // 遍历 MethodDef 表反查: 需要 TypeDef.MethodList。这里用简化办法: 由调用方给出 rid 更好,
            // 但为方便, 扫描 #Strings 不可行 —— 改用 dnlib 在外部解析(见 PePatch 调用处的说明)。
            return -1;
        }
    }
}
