using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace AirExplorerUnpacker;

/// <summary>
/// S1 体注入 — 把运行时方法体（module_text 快照的 fat 头 + IL）写回 Slayed 骨架每个方法。
///
/// 数据源（全部实证, 见 PROGRESS.md）:
///   module_text.bin : 运行时模块 dump, 方法布局偏移 = RVA - 0x2000。
///                     每 manifest 方法的运行时方法头 (maxstack/locals/initlocals/EH 标志)
///                     与运行时 IL (与 JIT dump 16598 条逐字节全等) 都在此, 22930/22930 覆盖。
///   dump_official_16598.zip 的 m_&lt;tok&gt;.eh : CORINFO EH clause (28B/条 = 4B count + [flags][tryOff][tryLen]
///                     [hOff][hLen][cls]), Necrobit 方法运行时真实 EH (mt 的 EH 区是磁盘票据, 不可用)。
///   磁盘明文槽 (slot_plaintext, EH 段首字节 0x41) 的 EH 段为标准 fat clause, 亦可解析兜底。
///
/// 用法: s1 &lt;slayed.exe&gt; &lt;module_text.bin&gt; &lt;manifest.tsv&gt; &lt;dump_zip&gt; &lt;out.exe&gt;
///          [--only &lt;tokfile&gt;] [--exclude &lt;tokfile&gt;] [--limit N] [--skip-partial] [--no-write]
/// </summary>
public static class CmdS1
{
    const int MT_SHIFT = 0x2000;

    public static int Run(string[] args)
    {
        // s1 <exe> <mt> <manifest> <zip> <out> [opts...]
        if (args.Length < 6) { Console.WriteLine("usage: s1 <slayed.exe> <module_text.bin> <bodies_manifest.tsv> <dump_zip> <out.exe> [--only f] [--exclude f] [--limit N] [--no-write]"); return 2; }
        string exePath = args[1], mtPath = args[2], manifestPath = args[3], zipPath = args[4], outPath = args[5];

        var only = new HashSet<string>();
        var exclude = new HashSet<string>();
        int limit = int.MaxValue;
        bool noWrite = false;
        for (int i = 6; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--only":
                    foreach (var l in File.ReadAllLines(args[++i]))
                        if (!string.IsNullOrWhiteSpace(l)) only.Add(l.Trim().ToUpperInvariant());
                    break;
                case "--exclude":
                    foreach (var l in File.ReadAllLines(args[++i]))
                        if (!string.IsNullOrWhiteSpace(l)) exclude.Add(l.Trim().ToUpperInvariant());
                    break;
                case "--limit": limit = int.Parse(args[++i]); break;
                case "--no-write": noWrite = true; break;
                default: Console.WriteLine("unknown opt " + args[i]); return 2;
            }
        }

        var mt = File.ReadAllBytes(mtPath);
        var mod = (ModuleDefMD)ModuleDefMD.Load(exePath);
        Console.WriteLine("[s1] module loaded: " + mod.Name);

        // token -> MethodDef (跳过 NRS dummy 类型的方法: NRS rem-junks 可能改过它们的签名,
        // 注入基线真体会参数越界 — 保持 NRS stub, 记账)
        var byTok = new Dictionary<string, MethodDef>();
        int nDummySkip = 0;
        foreach (var t in mod.GetTypes())
        {
            bool dummy = t.FullName.Contains("dummy");
            foreach (var m in t.Methods)
            {
                if (dummy) { nDummySkip++; continue; }
                byTok[m.MDToken.Raw.ToString("X8")] = m;
            }
        }
        Console.WriteLine("[s1] token index: {0} methods ({1} in NRS-dummy types skipped)", byTok.Count, nDummySkip);

        // manifest
        var man = new List<(string rva, string tok, string name, string src)>();
        foreach (var ln in File.ReadLines(manifestPath).Skip(1))
        {
            var p = ln.Split('\t');
            if (p.Length >= 4) man.Add((p[0], p[1], p[2], p[3]));
        }
        Console.WriteLine("[s1] manifest rows: " + man.Count);

        // zip: maxStack/ehCount + CORINFO EH
        var zipMax = new Dictionary<string, int>();
        var zipEh = new Dictionary<string, byte[]>();
        using (var fs = File.OpenRead(zipPath))
        using (var z = new System.IO.Compression.ZipArchive(fs, System.IO.Compression.ZipArchiveMode.Read))
        {
            foreach (var e in z.Entries)
            {
                if (e.Name.EndsWith(".bin") && e.Name.StartsWith("m_"))
                {
                    using var s = e.Open();
                    var d = new byte[24];
                    ReadFull(s, d);
                    zipMax[e.Name.Substring(2, 8)] = BitConverter.ToInt32(d, 8);
                }
                else if (e.Name.EndsWith(".eh") && e.Name.StartsWith("m_"))
                {
                    using var s = e.Open();
                    var ms = new MemoryStream();
                    s.CopyTo(ms);
                    zipEh[e.Name.Substring(2, 8)] = ms.ToArray();
                }
            }
        }
        Console.WriteLine("[s1] zip maxstack entries: {0}, eh entries: {1}", zipMax.Count, zipEh.Count);

        int ok = 0, fail = 0, skipNoTok = 0, skipNoBody = 0, ehDropped = 0;
        int tokenMiss = 0;
        var failReasons = new Dictionary<string, int>();
        var failed = new List<string>();
        var ehNoSource = new List<string>();
        int done = 0;

        foreach (var (rva, tok, name, src) in man)
        {
            if (done >= limit) break;
            if (only.Count > 0 && !only.Contains(tok)) continue;
            if (exclude.Contains(tok)) continue;
            done++;

            if (!byTok.TryGetValue(tok, out var md)) { skipNoTok++; continue; }
            int r = int.Parse(rva, System.Globalization.NumberStyles.HexNumber);
            int off = r - MT_SHIFT;
            if (off < 0 || off + 12 > mt.Length) { skipNoBody++; continue; }

            byte b0 = mt[off];
            int kind = b0 & 3;
            int hsz, codeSize, maxStack, ehFlag;
            uint localsTok, flags;

            if (kind == 2)
            {
                // tiny: 无 locals/无 EH, maxstack 规范 8 (JIT dump 头可复核)
                codeSize = b0 >> 2;
                hsz = 1; maxStack = 8; localsTok = 0; flags = 0; ehFlag = 0;
                var zmax = zipMax.GetValueOrDefault(tok, -1);
                if (zmax > 0) maxStack = Math.Max(1, zmax);
            }
            else if (kind == 3)
            {
                hsz = ((mt[off + 1] >> 4) & 0xF) * 4;
                flags = BitConverter.ToUInt16(mt, off + 2);
                maxStack = (int)(flags >> 12);
                flags &= 0xFFF;
                codeSize = BitConverter.ToInt32(mt, off + 4);
                localsTok = BitConverter.ToUInt32(mt, off + 8);
                ehFlag = (int)(flags & 8);
                flags &= 0xFFFF;
            }
            else { skipNoBody++; continue; }

            if (codeSize <= 0 || codeSize > 0x100000 || off + hsz + codeSize > mt.Length)
            { skipNoBody++; continue; }

            var il = new byte[codeSize];
            Array.Copy(mt, off + hsz, il, 0, codeSize);

            // EH 数据: 优先 zip CORINFO -> 转 CLI fat clause; 兜底 mt 磁盘段(仅 0x41 类)
            byte[] ehData = null;
            if (ehFlag != 0)
            {
                if (zipEh.TryGetValue(tok, out var corEh))
                {
                    ehData = CorInfoToCliEh(corEh);
                    if (ehData == null) ehDropped++;
                }
                else
                {
                    // mt/磁盘兜底: 段头 u32, byte0&0x40 == small-flag(但数据是 fat clause)
                    int sect = (off + hsz + codeSize + 3) & ~3;
                    if (sect + 4 <= mt.Length && (mt[sect] & 0x40) != 0)
                    {
                        int dsize = (int)((BitConverter.ToUInt32(mt, sect) >> 8) & 0xFFFFFF);
                        if (dsize >= 4 && dsize <= 0x10000 && sect + dsize <= mt.Length && (dsize - 4) % 24 == 0)
                        {
                            ehData = new byte[dsize];
                            Array.Copy(mt, sect, ehData, 0, dsize);
                            ehData[0] = 0x20; // 强制 fat 段标志
                        }
                    }
                    if (ehData == null)
                    {
                        ehDropped++;
                        ehNoSource.Add(tok);
                    }
                }
            }

            var bodyFlags = (ushort)(3 | (ehData != null ? 8 : 0) | ((flags & 0x10) != 0 ? 0x10 : 0));
            try
            {
                var gp = new GenericParamContext();
                var body = MethodBodyReader.CreateCilBody(mod, il, ehData, md.Parameters, bodyFlags,
                    (ushort)maxStack, (uint)codeSize, localsTok, gp);
                if (body == null) throw new Exception("CreateCilBody null");
                body.MaxStack = (ushort)maxStack;
                body.KeepOldMaxStack = true;
                // 兼容性校验: 参数/局部变量绑定必须完整, 否则写出阶段崩
                bool bad = false;
                foreach (var ins in body.Instructions)
                {
                    switch (ins.OpCode.OperandType)
                    {
                        case OperandType.InlineVar:
                        case OperandType.ShortInlineVar:
                            if (ins.Operand == null) { bad = true; }
                            break;
                    }
                    if (bad) break;
                }
                if (bad) throw new Exception("unbound arg/local operand (sig mismatch)");
                md.Body = body;
                ok++;
            }
            catch (Exception ex)
            {
                fail++;
                tokenMiss++;
                failed.Add(tok);
                var key = ex.Message.Length > 80 ? ex.Message.Substring(0, 80) : ex.Message;
                failReasons[key] = failReasons.GetValueOrDefault(key) + 1;
            }
        }

        Console.WriteLine("[s1] injected={0} fail={1} no-tok={2} bad-body={3} eh-dropped={4}", ok, fail, skipNoTok, skipNoBody, ehDropped);
        Console.WriteLine("[s1] eh-no-source: {0} (first: {1})", ehNoSource.Count, string.Join(",", ehNoSource.Take(8)));
        if (fail > 0)
        {
            Console.WriteLine("[s1] fail reasons:");
            foreach (var kv in failReasons.OrderByDescending(x => x.Value).Take(12))
                Console.WriteLine("    x{0}  {1}", kv.Value, kv.Key);
            File.WriteAllLines(Path.Combine(Path.GetDirectoryName(outPath) ?? ".", "s1_failed_tokens.txt"),
                failed);
        }

        var rep = new StringBuilder();
        rep.AppendLine("S1 report " + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss'Z'"));
        rep.AppendLine("in=" + exePath);
        rep.AppendLine("injected=" + ok);
        rep.AppendLine("fail=" + fail);
        rep.AppendLine("skipNoTok=" + skipNoTok);
        rep.AppendLine("skipNoBody=" + skipNoBody);
        rep.AppendLine("ehDropped=" + ehDropped);
        rep.AppendLine("ehNoSource=" + string.Join(",", ehNoSource));
        foreach (var kv in failReasons.OrderByDescending(x => x.Value))
            rep.AppendLine("fail x" + kv.Value + " " + kv.Key);
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(outPath) ?? ".", "s1_report.txt"), rep.ToString());

        if (noWrite) { Console.WriteLine("[s1] --no-write, not writing"); return ok > 0 ? 0 : 1; }

        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, opts);
        Console.WriteLine("[s1] written: " + outPath);
        return fail == 0 ? 0 : 1;
    }

    /// <summary>CORINFO EH dump (4B count + 28B/条) -> CLI fat EH 段 (4B 头 + 24B/条)。</summary>
    static byte[] CorInfoToCliEh(byte[] cor)
    {
        if (cor.Length < 4) return null;
        int cnt = BitConverter.ToInt32(cor, 0);
        if (cnt <= 0 || cor.Length < 4 + cnt * 28) return null;
        int dsize = 4 + cnt * 24;
        var outp = new byte[dsize];
        // 段头: u32 = (dsize << 8) | 0x20 (fat EH 段)
        BitConverter.GetBytes((uint)((dsize << 8) | 0x20)).CopyTo(outp, 0);
        for (int i = 0; i < cnt; i++)
        {
            int b = 4 + i * 28;
            uint f = BitConverter.ToUInt32(cor, b);
            uint tryOff = BitConverter.ToUInt32(cor, b + 4);
            uint tryLen = BitConverter.ToUInt32(cor, b + 8);
            uint hOff = BitConverter.ToUInt32(cor, b + 12);
            uint hLen = BitConverter.ToUInt32(cor, b + 16);
            uint cls = BitConverter.ToUInt32(cor, b + 20);
            uint cliFlags = f; // 0=catch 1=filter 2=finally 3/4=fault (CORINFO 与 CLI 同值)
            int o = 4 + i * 24;
            BitConverter.GetBytes(cliFlags).CopyTo(outp, o);
            BitConverter.GetBytes(tryOff).CopyTo(outp, o + 4);
            BitConverter.GetBytes(tryLen).CopyTo(outp, o + 8);
            BitConverter.GetBytes(hOff).CopyTo(outp, o + 12);
            BitConverter.GetBytes(hLen).CopyTo(outp, o + 16);
            BitConverter.GetBytes(cls).CopyTo(outp, o + 20);
        }
        return outp;
    }

    static void ReadFull(Stream s, byte[] buf)
    {
        int o = 0;
        while (o < buf.Length)
        {
            int n = s.Read(buf, o, buf.Length - o);
            if (n <= 0) break;
            o += n;
        }
    }
}
