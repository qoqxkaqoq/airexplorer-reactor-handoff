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
    static ModuleDefMD s_mod;
    static Dictionary<string, TypeDef> s_tdByFull;
    static Dictionary<string, TypeRef> s_trByFull;

    public static int Run(string[] args)
    {
        // s1 <exe> <mt> <manifest> <zip> <out> [opts...]
        if (args.Length < 6) { Console.WriteLine("usage: s1 <slayed.exe> <module_text.bin> <bodies_manifest.tsv> <dump_zip> <out.exe> [--only f] [--exclude f] [--limit N] [--no-write]"); return 2; }
        string exePath = args[1], mtPath = args[2], manifestPath = args[3], zipPath = args[4], outPath = args[5];
        string baselinePath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(exePath)) ?? ".",
            "AirExplorer_baseline_verified.exe");

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
                case "--baseline": baselinePath = args[++i]; break;
                default: Console.WriteLine("unknown opt " + args[i]); return 2;
            }
        }

        var mt = File.ReadAllBytes(mtPath);
        var mod = (ModuleDefMD)ModuleDefMD.Load(exePath);
        s_mod = mod;
        Console.WriteLine("[s1] module loaded: " + mod.Name);

        // 基线 exe (只读): NRS rem-junks 会把"未引用"方法 dummy 化(签名改 void() 非 static + 无体)
        // 并删除调用点; 我们注入运行时真体恢复调用点后必须同步恢复基线签名, 否则
        // call 非 static 方法缺 this -> InvalidProgramException。
        Dictionary<string, (MethodSig sig, MethodAttributes attrs)> baseSigs = null;
        Importer? sigImporter = null;
        if (File.Exists(baselinePath))
        {
            var bmod = (ModuleDefMD)ModuleDefMD.Load(baselinePath);
            baseSigs = new Dictionary<string, (MethodSig, MethodAttributes)>();
            foreach (var t in bmod.GetTypes())
                foreach (var m in t.Methods)
                    if (m.MethodSig != null)
                        baseSigs[m.MDToken.Raw.ToString("X8")] = (m.MethodSig, m.Attributes);
            sigImporter = new Importer(mod);
            // NRS rem-junks 也会删类型行 -> TypeDef rid 可能错位, 按 FullName 建映射
            s_tdByFull = new Dictionary<string, TypeDef>();
            foreach (var t in mod.GetTypes())
                if (!s_tdByFull.ContainsKey(t.FullName)) s_tdByFull[t.FullName] = t;
            s_trByFull = new Dictionary<string, TypeRef>();
            foreach (var tr in mod.GetTypeRefs())
                if (!s_trByFull.ContainsKey(tr.FullName)) s_trByFull[tr.FullName] = tr;
            Console.WriteLine("[s1] baseline signatures loaded: {0}, type map: {1}", baseSigs.Count, s_tdByFull.Count);
        }

        // token -> MethodDef (dummy 类型方法不再跳过: 签名将由基线恢复)
        var byTok = new Dictionary<string, MethodDef>();
        int nDummy = 0;
        foreach (var t in mod.GetTypes())
        {
            bool dummy = t.FullName.Contains("dummy");
            foreach (var m in t.Methods)
            {
                if (dummy) nDummy++;
                byTok[m.MDToken.Raw.ToString("X8")] = m;
            }
        }
        Console.WriteLine("[s1] token index: {0} methods ({1} in NRS-dummy types, will restore baseline sig)", byTok.Count, nDummy);

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
        int tokenMiss = 0, sigFixedTotal = 0, attrFixedTotal = 0;
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
            bool initLocals;
            uint localsTok;

            if (kind == 2)
            {
                // tiny: 无 locals/无 EH, maxstack 规范 8 (JIT dump 头可复核)
                codeSize = b0 >> 2;
                hsz = 1; maxStack = 8; localsTok = 0; ehFlag = 0; initLocals = true;
                var zmax = zipMax.GetValueOrDefault(tok, -1);
                if (zmax > 0) maxStack = Math.Max(1, zmax);
            }
            else if (kind == 3)
            {
                // ECMA II.25.4.4 fat 头: byte0=flags低8位(bit0-2=fat3,bit3=moreSects,bit4=initLocals),
                // byte1 高4位=hdrsize(以4B计), byte2-3=maxstack(完整16位), [4:8]=codesize, [8:12]=localsTok
                hsz = ((mt[off + 1] >> 4) & 0xF) * 4;
                ehFlag = b0 & 0x08;
                initLocals = (b0 & 0x10) != 0;
                maxStack = BitConverter.ToUInt16(mt, off + 2);
                codeSize = BitConverter.ToInt32(mt, off + 4);
                localsTok = BitConverter.ToUInt32(mt, off + 8);
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

            var bodyFlags = (ushort)(3 | (ehData != null ? 8 : 0) | (initLocals ? 0x10 : 0));
            try
            {
                // 签名/flags 恢复: 只针对 NRS dummy 化的方法(签名必被改坏)。
                // 非 dummy 方法签名是原版好的, 一律不碰(Importer 边角会弄坏复杂签名)。
                // Attributes 则全量恢复(否则 NRS 的 abstract 位残留 + 注入体 ->
                // TypeLoadException: Abstract method with non-zero RVA)。
                if (baseSigs != null && baseSigs.TryGetValue(tok, out var bsigT))
                {
                    var bsig = bsigT.sig;
                    var cur = md.MethodSig;
                    bool isDummy = md.DeclaringType != null && md.DeclaringType.FullName.Contains("dummy");
                    if (isDummy)
                    {
                        bool sigSame = cur != null && cur.ToString() == bsig.ToString()
                                       && cur.HasThis == bsig.HasThis && cur.ExplicitThis == bsig.ExplicitThis
                                       && cur.GenParamCount == bsig.GenParamCount;
                        if (!sigSame)
                        {
                            // 手工克隆: 保留调用约定与 token (基线/Slayed token 空间一致),
                            // 每个 TypeDefOrRef 节点按 token 解析回本模块。
                            // Importer.Import 的两个坑: (1)跨模块 TypeDef 转成自引用 TypeRef
                            // (2)丢调用约定位 —— 都会产出坏签名/坏引用。
                            var ns = CloneSigInto(bsig);
                            md.Signature = ns;
                            sigFixedTotal++;
                        }
                    }
                }

                var gp = new GenericParamContext();
                // 不用 md.Parameters: dnlib 的 Parameters 列表是懒缓存, 签名恢复前若已被物化
                // 就不会反映新签名。手工按恢复后的签名构建参数绑定列表 (index0 = this 若实例方法)。
                var curSig = md.MethodSig;
                IList<Parameter> pbind;
                if (curSig != null && curSig.HasThis)
                {
                    var pl = new List<Parameter>(curSig.Params.Count + 1) { new Parameter(0, Parameter.HIDDEN_THIS_METHOD_SIG_INDEX) };
                    for (int pi = 0; pi < curSig.Params.Count; pi++)
                        pl.Add(new Parameter(pi + 1, pi + 1));
                    pbind = pl;
                }
                else if (curSig != null)
                {
                    var pl = new List<Parameter>(curSig.Params.Count);
                    for (int pi = 0; pi < curSig.Params.Count; pi++)
                        pl.Add(new Parameter(pi, pi + 1));
                    pbind = pl;
                }
                else
                    pbind = md.Parameters;
                var body = MethodBodyReader.CreateCilBody(mod, il, ehData, pbind, bodyFlags,
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
                // Attributes 恢复必须在注入成功后: 若注入失败保持 NRS 的 abstract+无体组合
                // (合法), 否则变成 非 abstract+无体(RVA=0) 的非法状态
                if (baseSigs != null && baseSigs.TryGetValue(tok, out var battr) && md.Attributes != battr.attrs)
                {
                    md.Attributes = battr.attrs;
                    attrFixedTotal++;
                }
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

        Console.WriteLine("[s1] injected={0} fail={1} no-tok={2} bad-body={3} eh-dropped={4} sig-restored={5} attr-restored={6}",
            ok, fail, skipNoTok, skipNoBody, ehDropped, sigFixedTotal, attrFixedTotal);
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
        rep.AppendLine("sigRestored=" + sigFixedTotal);
        rep.AppendLine("attrRestored=" + attrFixedTotal);
        rep.AppendLine("ehNoSource=" + string.Join(",", ehNoSource));
        foreach (var kv in failReasons.OrderByDescending(x => x.Value))
            rep.AppendLine("fail x" + kv.Value + " " + kv.Key);
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(outPath) ?? ".", "s1_report.txt"), rep.ToString());

        if (noWrite) { Console.WriteLine("[s1] --no-write, not writing"); return ok > 0 ? 0 : 1; }

        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, opts);
        Console.WriteLine("[s1] written: " + outPath);
        // fail>0 = 安全降级(保持 NRS 原状), 不是硬失败; 硬门禁在 probe
        return 0;
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

    /// <summary>把基线模块的签名克隆进当前模块: TypeDefOrRef 按 token 解析, 保留调用约定。</summary>
    static MethodSig CloneSigInto(MethodSig src)
    {
        var ret = CloneTypeInto(src.RetType);
        var ms = new MethodSig(src.CallingConvention, src.GenParamCount, ret);
        ms.Params.Clear();
        foreach (var p in src.Params) ms.Params.Add(CloneTypeInto(p));
        if (src.ParamsAfterSentinel != null && src.ParamsAfterSentinel.Count > 0)
        {
            var pas = new List<TypeSig>();
            foreach (var p in src.ParamsAfterSentinel) pas.Add(CloneTypeInto(p));
            ms.ParamsAfterSentinel = pas;
        }
        return ms;
    }

    /// <summary>按 FullName 把基线类型映射到本模块; TypeSpec 递归重建。</summary>
    static ITypeDefOrRef MapTdor(ITypeDefOrRef src)
    {
        if (src == null) return null;
        var td = src as TypeDef;
        if (td != null)
        {
            if (s_tdByFull.TryGetValue(td.FullName, out var hit)) return hit;
            throw new Exception("sig clone: typedef not in map: " + td.FullName);
        }
        var tr = src as TypeRef;
        if (tr != null)
        {
            // token 解析后必须全名一致(NRS 删行导致 rid 错位, 盲 resolve 会拿到错误类型)
            var resolved = s_mod.ResolveToken(src.MDToken.Raw) as TypeRef;
            if (resolved != null && resolved.FullName == tr.FullName) return resolved;
            if (s_trByFull.TryGetValue(tr.FullName, out var hitR)) return hitR;
            if (s_tdByFull.TryGetValue(tr.FullName, out var hit2)) return hit2;
            // corlib fallback
            if (tr.ResolutionScope is AssemblyRef ar && ar.Name == s_mod.CorLibTypes.AssemblyRef.Name)
                return new TypeRefUser(s_mod, tr.Namespace, tr.Name, s_mod.CorLibTypes.AssemblyRef);
            throw new Exception("sig clone: typeref not mapped: " + tr.FullName);
        }
        var ts = src as TypeSpec;
        if (ts != null)
        {
            // 递归重建签名内容, 生成新 TypeSpec
            var inner = ts.TypeSig;
            if (inner != null) return new TypeSpecUser(CloneTypeInto(inner));
            var resolved2 = s_mod.ResolveToken(src.MDToken.Raw) as TypeSpec;
            if (resolved2 != null) return resolved2;
            throw new Exception("sig clone: typespec unmapped: " + src.MDToken.Raw.ToString("X8"));
        }
        throw new Exception("sig clone: unknown tdor " + src.GetType().Name);
    }

    static TypeSig CloneTypeInto(TypeSig t)
    {
        if (t == null) return null;
        switch (t)
        {
            case TypeDefOrRefSig r:
            {
                var mapped = MapTdor(r.TypeDefOrRef);
                return r.IsValueType ? (TypeSig)new ValueTypeSig(mapped) : new ClassSig(mapped);
            }
            case SZArraySig a: return new SZArraySig(CloneTypeInto(a.Next));
            case GenericInstSig g:
            {
                var gen = CloneTypeInto(g.GenericType) as ClassOrValueTypeSig
                    ?? throw new Exception("sig clone: bad generic base");
                var list = new List<TypeSig>();
                foreach (var x in g.GenericArguments) list.Add(CloneTypeInto(x));
                return new GenericInstSig(gen, list);
            }
            case ByRefSig b: return new ByRefSig(CloneTypeInto(b.Next));
            case PtrSig p: return new PtrSig(CloneTypeInto(p.Next));
            case GenericVar gv: return new GenericVar(gv.Number);
            case GenericMVar mv: return new GenericMVar(mv.Number);
            case CModReqdSig cm:
                return new CModReqdSig(ResolveTdor(cm.Modifier), CloneTypeInto(cm.Next));
            case CModOptSig co:
                return new CModOptSig(ResolveTdor(co.Modifier), CloneTypeInto(co.Next));
            case PinnedSig ps: return new PinnedSig(CloneTypeInto(ps.Next));
            default:
                throw new Exception("sig clone: unsupported node " + t.GetType().Name);
        }
    }

    static ITypeDefOrRef ResolveTdor(ITypeDefOrRef t) => MapTdor(t);

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
