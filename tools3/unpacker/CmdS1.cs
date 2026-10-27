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
        ModuleDefMD bmodKeep = null;
        Dictionary<string, TypeRef> trMapAll = null;
        if (File.Exists(baselinePath))
        {
            var bmod = (ModuleDefMD)ModuleDefMD.Load(baselinePath);
            bmodKeep = bmod;
            trMapAll = new Dictionary<string, TypeRef>();
            foreach (var tr in bmod.GetTypeRefs())
                if (!trMapAll.ContainsKey(tr.FullName)) trMapAll[tr.FullName] = tr;
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
            // NRS rem-junks 删了基线的部分类型, 而恢复的方法签名会引用它们 -> 类型加载失败
            // (Could not load type)。补空类型壳(仅 ns/name/基类), 让签名引用可解析;
            // 其成员级恢复(字段/方法)留待 M2+。
            int shellAdded = 0;
            // 必须用 GetTypes() 全集(含嵌套类型): mod.Types 只含顶层, 若只用它会把
            // 所有嵌套类型误判为"被删"而建壳, 且 s_tdByFull[FullName]=shell 无条件覆盖
            // 真 Slayed 类型的映射 -> box/castclass 重映射指向壳, locals 签名指向真类型,
            // 同一类型双身份 -> mono/CLR 验证 box(class壳) vs struct栈值 不匹配拒载。
            var modTypeNames = new HashSet<string>(mod.GetTypes().Select(x => x.FullName));
            foreach (var bt in bmod.GetTypes())
            {
                if (modTypeNames.Contains(bt.FullName)) continue;
                if (bt.FullName.Contains("dummy")) continue;
                // 修复18: 非特殊类型(非 enum/delegate/abstract/interface)用真名+真基类重建 ——
                // 这些类型的字段/方法被 Slayed 移入 __ReactorRemoved 扁平壳, 方法 rid 保持不变,
                // 但注入体 IL 的 call token 解析到的类型必须是官方真名(否则 JIT 拒)。
                // 特殊类型照旧用扁平 Object 壳: enum(须实例字段)/delegate(须 sealed)/
                // abstract(须实现抽象成员) 照抄会 TypeLoad。
                bool special = bt.IsEnum || bt.IsDelegate || bt.IsAbstract || bt.IsInterface || bt.DeclaringType != null;
                TypeDef shell;
                if (!special)
                {
                    ITypeDefOrRef baseSig = mod.CorLibTypes.Object.TypeDefOrRef;
                    if (bt.BaseType != null)
                    {
                        try
                        {
                            if (mod.ResolveToken(bt.BaseType.MDToken.Raw) is ITypeDefOrRef r
                                && (r is TypeRef || (r is TypeDef rd && !rd.IsAbstract && !rd.IsInterface)))
                                baseSig = r;
                        }
                        catch { }
                    }
                    shell = new TypeDefUser(bt.Namespace, bt.Name, baseSig);
                    shell.Attributes = TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.BeforeFieldInit
                        | (bt.Attributes & TypeAttributes.Sealed);
                    if (bt.HasGenericParameters)
                        foreach (var gp in bt.GenericParameters)
                        {
                            var ng = new GenericParamUser(gp.Number, gp.Flags, gp.Name);
                            shell.GenericParameters.Add(ng);
                        }
                }
                else
                {
                    shell = new TypeDefUser("__ReactorRemoved",
                        bt.FullName.Replace('.', '_').Replace('/', '_'), mod.CorLibTypes.Object.TypeDefOrRef);
                    shell.Attributes = TypeAttributes.Public | TypeAttributes.Class | TypeAttributes.Sealed
                        | TypeAttributes.BeforeFieldInit;
                }
                mod.Types.Add(shell);
                s_tdByFull[bt.FullName] = shell;
                shellAdded++;
            }
            Console.WriteLine("[s1] baseline signatures loaded: {0}, type map: {1}, type shells added: {2}",
                baseSigs.Count, s_tdByFull.Count, shellAdded);
        }
        RemapResolver remapResolver = null;
        if (baseSigs != null && bmodKeep != null)
        {
            var slayedMr = new Dictionary<string, MemberRef>();
            foreach (var mref in mod.GetMemberRefs())
                if (!slayedMr.ContainsKey(RemapResolver.MemberKey(mref))) slayedMr[RemapResolver.MemberKey(mref)] = mref;
            remapResolver = new RemapResolver(mod, bmodKeep, s_tdByFull, s_trByFull ?? trMapAll, slayedMr);
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
        int tokenMiss = 0, sigFixedTotal = 0, attrFixedTotal = 0, ldcFixed = 0, excludedStubbed = 0;
        var failReasons = new Dictionary<string, int>();
        var failed = new List<string>();
        var ehNoSource = new List<string>();
        int done = 0;

        foreach (var (rva, tok, name, src) in man)
        {
            if (done >= limit) break;
            if (only.Count > 0 && !only.Contains(tok)) continue;
            if (exclude.Contains(tok))
            {
                // exclude = 不注入 mt 体, 但仍恢复签名/attrs 并补 stub 体
                // (rid 复用恢复的方法若保持 abstract+无体且已搬回真类型 -> TypeLoad)
                if (byTok.TryGetValue(tok, out var mdEx) && baseSigs != null && baseSigs.TryGetValue(tok, out var bsigEx))
                {
                    var curSigEx = mdEx.MethodSig;
                    bool isDummyEx = mdEx.DeclaringType != null && mdEx.DeclaringType.FullName.Contains("dummy");
                    if (isDummyEx)
                    {
                        var nsEx = CloneSigInto(bsigEx.sig);
                        mdEx.Signature = nsEx;
                        mdEx.Attributes = bsigEx.attrs;
                        mdEx.ParamDefs.Clear();
                        for (int pi = 0; pi < nsEx.Params.Count; pi++)
                            mdEx.ParamDefs.Add(new ParamDefUser(string.Empty, (ushort)(pi + 1)));
                    }
                    mdEx.Attributes &= ~MethodAttributes.Abstract;
                    if (!mdEx.HasBody)
                    {
                        var stubBody = new CilBody(true, new List<Instruction>(), new List<ExceptionHandler>(), new List<Local>());
                        var retE = mdEx.MethodSig?.RetType;
                        if (retE != null && retE.FullName != "System.Void")
                        {
                            switch (retE.ElementType)
                            {
                                case ElementType.Boolean: case ElementType.Char:
                                case ElementType.I1: case ElementType.U1: case ElementType.I2: case ElementType.U2:
                                case ElementType.I4: case ElementType.U4: case ElementType.I8: case ElementType.U8:
                                case ElementType.R4: case ElementType.R8: case ElementType.I: case ElementType.U:
                                    stubBody.Instructions.Add(Instruction.CreateLdcI4(0)); break;
                                default: stubBody.Instructions.Add(Instruction.Create(OpCodes.Ldnull)); break;
                            }
                        }
                        stubBody.Instructions.Add(Instruction.Create(OpCodes.Ret));
                        mdEx.Body = stubBody;
                        mdEx.Body.MaxStack = 8;
                    }
                }
                excludedStubbed++;
                continue;
            }
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
                    // mt/磁盘兜底 EH 段: 两种格式
                    // (a) fat: u32=(dsize<<8)|0x41, dsize 含头, 24B/子句
                    // (b) 紧凑(dump 工具格式): flags byte=0x01, dsize=(u32>>8), 12B/子句:
                    //     flags(2B) tryOff(2B) tryLen(1B) hOff(2B) hLen(1B) cls(4B=完整token)
                    //     (三方法实证: 06000288/0600034F/060003AB 的 try/handler 边界与 cls=Exception 全吻合)
                    int sect = (off + hsz + codeSize + 3) & ~3;
                    if (sect + 4 <= mt.Length)
                    {
                        uint hdr32 = BitConverter.ToUInt32(mt, sect);
                        byte fl0 = mt[sect];
                        int dsize = (int)((hdr32 >> 8) & 0xFFFFFF);
                        if ((fl0 & 0x41) == 0x41 && dsize >= 4 && dsize <= 0x10000 && sect + dsize <= mt.Length && (dsize - 4) % 24 == 0)
                        {
                            int ncl = (dsize - 4) / 24;
                            var cls2 = new List<EhClause>(ncl);
                            for (int ci = 0; ci < ncl; ci++)
                            {
                                int b = sect + 4 + ci * 24;
                                uint f = BitConverter.ToUInt32(mt, b);
                                // CORINFO: 3=fault -> CLI 4
                                uint cf = f == 3 ? 4u : (f <= 2 ? f : 0u);
                                cls2.Add(new EhClause(cf,
                                    BitConverter.ToUInt32(mt, b + 4),
                                    BitConverter.ToUInt32(mt, b + 8),
                                    BitConverter.ToUInt32(mt, b + 12),
                                    BitConverter.ToUInt32(mt, b + 16),
                                    BitConverter.ToUInt32(mt, b + 20)));
                            }
                            ehData = BuildFatEh(cls2);
                        }
                        else if (fl0 == 0x01 && dsize >= 4 && dsize <= 0x10000 && sect + dsize <= mt.Length && (dsize - 4) % 12 == 0 && dsize > 4)
                        {
                            int ncl = (dsize - 4) / 12;
                            var cls2 = new List<EhClause>(ncl);
                            bool ok2 = true;
                            for (int ci = 0; ci < ncl && ok2; ci++)
                            {
                                int b = sect + 4 + ci * 12;
                                ushort f = BitConverter.ToUInt16(mt, b);
                                ushort tryOff = BitConverter.ToUInt16(mt, b + 2);
                                byte tryLen = mt[b + 4];
                                ushort hOff = BitConverter.ToUInt16(mt, b + 5);
                                byte hLen = mt[b + 7];
                                uint clsTok = BitConverter.ToUInt32(mt, b + 8);
                                // 边界校验: 全部必须落在 codeSize 内
                                if (tryOff + tryLen > codeSize || hOff + hLen > codeSize) ok2 = false;
                                else
                                {
                                    uint cf = f == 3 ? 4u : (f <= 2 ? f : 0u);
                                    cls2.Add(new EhClause(cf, tryOff, tryLen, hOff, hLen, clsTok));
                                }
                            }
                            if (ok2 && cls2.Count > 0) ehData = BuildFatEh(cls2);
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
            // 回滚快照: 注入失败则完全还原 NRS 原状(坏签名会拖死整个 dummy_ptr 类型, 连累 cctor 链)
            MethodSig rollbackSig = md.MethodSig;
            MethodAttributes rollbackAttrs = md.Attributes;
            var rollbackParams = md.ParamDefs.ToList();
            try
            {
                // 签名恢复: 只针对 NRS dummy 化的方法(签名必被改坏)。
                // 非 dummy 方法签名是原版好的, 一律不碰。
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
                            // 每个 TypeDefOrRef 节点按 FullName 映射回本模块。
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
                var body = MethodBodyReader.CreateCilBody(remapResolver, il, ehData, pbind, bodyFlags,
                    (ushort)maxStack, (uint)codeSize, localsTok, gp);
                if (body == null) throw new Exception("CreateCilBody null");
                if (ehData != null && body.ExceptionHandlers.Count == 0)
                    throw new Exception("ehData " + ehData.Length + "B parsed as 0 clauses");
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
                // ldc.i4 token 立即数重映射: NRS 运行时解密函数以 int 参数接收元数据 token
                // (ldc.i4 <tok>; call DecryptFunc), 这些立即数不经过 ITokenOperand resolver。
                // 只修「Slayed 同 token 解析结果 FullName ≠ 基线」的错位 token (对齐的不动, 防误伤常量)。
                var insList = body.Instructions;
                for (int ii = 0; ii < insList.Count - 1; ii++)
                {
                    var cur = insList[ii];
                    if (cur.OpCode.Code != Code.Ldc_I4) continue;
                    if (ii + 1 >= insList.Count) break;
                    var nxt = insList[ii + 1];
                    if (nxt.OpCode.Code != Code.Call && nxt.OpCode.Code != Code.Callvirt) continue;
                    int v;
                    try { v = Convert.ToInt32(cur.Operand); } catch { continue; }
                    if (v < 0x01000000 || v >= 0x02000000 + 0x00FFFFFF) continue;
                    uint vt = (uint)v;
                    byte tbl = (byte)(vt >> 24);
                    if (tbl != 0x01 && tbl != 0x02) continue;
                    try
                    {
                        if (bmodKeep.ResolveToken(vt) is not ITypeDefOrRef bt2) continue;
                        string bFull = bt2.FullName;
                        string sFull = (mod.ResolveToken(vt) as ITypeDefOrRef)?.FullName ?? "?";
                        if (sFull == bFull) continue;   // 已对齐
                        if (s_tdByFull.TryGetValue(bFull, out var hitT))
                        {
                            uint newTok = hitT.MDToken.Raw;
                            if (newTok != vt) { cur.Operand = (int)newTok; ldcFixed++; }
                        }
                    }
                    catch { }
                }
                md.Body = body;
                ok++;
            }
            catch (Exception ex)
            {
                // 完全回滚到 NRS 原状
                md.Signature = rollbackSig;
                md.Attributes = rollbackAttrs;
                md.ParamDefs.Clear();
                foreach (var pd in rollbackParams) md.ParamDefs.Add(pd);
                fail++;
                failed.Add(tok);
                var key = ex.Message.Length > 80 ? ex.Message.Substring(0, 80) : ex.Message;
                failReasons[key] = failReasons.GetValueOrDefault(key) + 1;
            }
        }

        Console.WriteLine("[s1] injected={0} fail={1} no-tok={2} bad-body={3} eh-dropped={4} sig-restored={5} attr-restored={6} ldc-token-fixed={7} excluded-stubbed={8}",
            ok, fail, skipNoTok, skipNoBody, ehDropped, sigFixedTotal, attrFixedTotal, ldcFixed, excludedStubbed);
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
        rep.AppendLine("ldcTokenFixed=" + ldcFixed);
        rep.AppendLine("ehNoSource=" + string.Join(",", ehNoSource));
        foreach (var kv in failReasons.OrderByDescending(x => x.Value))
            rep.AppendLine("fail x" + kv.Value + " " + kv.Key);
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(outPath) ?? ".", "s1_report.txt"), rep.ToString());

        if (noWrite) { Console.WriteLine("[s1] --no-write, not writing"); return ok > 0 ? 0 : 1; }

        // ── NRS rid 复用完整恢复 ──
        // NRS rem-junks 把 177 个方法 + 129 个字段的 MethodDef/FieldDef 行"搬"进
        // dummy_ptr.{GUID}(同 rid, 改名 mXXXXXX/fXXXXXX + stub 签名)。mt IL 是基线空间,
        // call/ldsfld 的 token 在 Slayed 解析会命中 dummy_ptr.{GUID} 的成员 → 触发加载该类型。
        // 恢复 = 搬回基线的 DeclaringType + 真名(+真签名, 前面已做) → token 语义与基线一致,
        // dummy_ptr.{GUID} 只剩 26 个 NRS 新造的 mp* stub。
        int movedM = 0, movedF = 0;
        if (baseSigs != null)
        {
            foreach (var t in mod.GetTypes().Where(x => x.FullName.Contains("dummy") || x.FullName.Contains("__ReactorRemoved")).ToList())
            {
                foreach (var m in t.Methods.ToList())
                {
                    if (bmodKeep == null || bmodKeep.ResolveToken(m.MDToken.Raw) is not MethodDef bm) continue;
                    var bOwner = bm.DeclaringType;
                    if (bOwner == null) continue;
                    TypeDef target;
                    if (bOwner.FullName == "<Module>") target = mod.GlobalType;
                    else if (!s_tdByFull.TryGetValue(bOwner.FullName, out target)) continue;
                    if (ReferenceEquals(target, t)) continue;
                    m.Name = bm.Name;
                    t.Methods.Remove(m);
                    target.Methods.Add(m);
                    movedM++;
                }
                foreach (var f in t.Fields.ToList())
                {
                    if (bmodKeep == null || bmodKeep.ResolveToken(f.MDToken.Raw) is not FieldDef bf) continue;
                    var bOwner = bf.DeclaringType;
                    if (bOwner == null) continue;
                    TypeDef target;
                    if (bOwner.FullName == "<Module>") target = mod.GlobalType;
                    else if (!s_tdByFull.TryGetValue(bOwner.FullName, out target)) continue;
                    if (ReferenceEquals(target, t)) continue;
                    f.Name = bf.Name;
                    // 字段签名恢复(类型映射回本模块)
                    if (bf.FieldSig != null)
                        f.FieldSig = new FieldSig(CloneTypeInto(bf.FieldSig.Type));
                    t.Fields.Remove(f);
                    target.Fields.Add(f);
                    movedF++;
                }
            }
        }
        Console.WriteLine("[s1] rid-reuse restored: methods={0} fields={1}", movedM, movedF);

        // ── dummy 后处理 ──
        // NRS dummy 化的部分方法不在 manifest(无真体可注入), 保持 abstract+无体。
        // 桌面 CLR 对这种残留(特别是 static/abstract 混搭后的 vtable 布局)比 mono 严,
        // 会拒载整个类型(dummy_ptr.{GUID})并连累 cctor 调用链 → 统一补 stub 体。
        int stubbed = 0;
        foreach (var t in mod.GetTypes())
        {
            if (!t.FullName.Contains("dummy") && !t.FullName.Contains("__ReactorRemoved")) continue;
            foreach (var m in t.Methods)
            {
                bool mAbs = (m.Attributes & MethodAttributes.Abstract) != 0;
                if (!mAbs && m.HasBody) continue;
                m.Attributes &= ~MethodAttributes.Abstract;
                if (!m.HasBody)
                {
                    var body = new CilBody();
                    var ret = m.MethodSig?.RetType;
                    if (ret != null && ret.FullName != "System.Void")
                    {
                        switch (ret.ElementType)
                        {
                            case ElementType.Boolean:
                            case ElementType.Char:
                            case ElementType.I1: case ElementType.U1:
                            case ElementType.I2: case ElementType.U2:
                            case ElementType.I4: case ElementType.U4:
                            case ElementType.I8: case ElementType.U8:
                            case ElementType.R4: case ElementType.R8:
                            case ElementType.I: case ElementType.U:
                                body.Instructions.Add(Instruction.CreateLdcI4(0));
                                break;
                            default:
                                body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
                                break;
                        }
                    }
                    body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                    m.Body = body;
                    m.Body.MaxStack = 8;
                }
                stubbed++;
            }
        }
        Console.WriteLine("[s1] dummy stubbed: {0}", stubbed);

        // 修复16: 共享RVA桩独立化 —— Slayed 骨架把数千个桩方法指向同一 RVA(旧布局共享桩)。
        // dnlib 写出时无 CilBody 的方法保留旧 RVA 列, 在重建后的新文件里该位置与
        // 其它新写的方法体 footprint 交叉 -> CLR JIT 报 Bad IL range / InvalidProgram
        // (Wine 实验: 2772 个共享桩独立化后 JIT 层全通过, 死点从 InvalidProgram 前进到运行时层)。
        int deDup = 0;
        {
            var byRva = new Dictionary<uint, List<MethodDef>>();
            foreach (var t in mod.GetTypes())
                foreach (var m in t.Methods)
                {
                    uint r = (uint)m.RVA;
                    if (r == 0 || m.IsAbstract || (m.Attributes & MethodAttributes.PinvokeImpl) != 0) continue;
                    if (!byRva.TryGetValue(r, out var l)) byRva[r] = l = new List<MethodDef>();
                    l.Add(m);
                }
            foreach (var kv in byRva)
            {
                if (kv.Value.Count < 2) continue;
                foreach (var m in kv.Value)
                {
                    // 共享组内全部 stub 化: 注入过的方法 RVA 独立不会进共享组,
                    // 进共享组的都是未注入方法, 其旧 RVA 在新文件里与邻居 footprint 交叉
                    var body = new CilBody();
                    var ret = m.MethodSig?.RetType;
                    if (ret != null && ret.FullName != "System.Void")
                    {
                        switch (ret.ElementType)
                        {
                            case ElementType.Boolean: case ElementType.Char:
                            case ElementType.I1: case ElementType.U1: case ElementType.I2: case ElementType.U2:
                            case ElementType.I4: case ElementType.U4: case ElementType.I8: case ElementType.U8:
                            case ElementType.R4: case ElementType.R8: case ElementType.I: case ElementType.U:
                                body.Instructions.Add(Instruction.CreateLdcI4(0)); break;
                            default: body.Instructions.Add(Instruction.Create(OpCodes.Ldnull)); break;
                        }
                    }
                    body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                    m.Body = body;
                    m.Body.MaxStack = 8;
                    deDup++;
                }
            }
        }
        Console.WriteLine("[s1] shared-rva dedup stubbed: {0}", deDup);

        // 修复17: 全局 abstract 清理 —— 未注入方法(如 --only 子集外)保持 Slayed 的 abstract+无体
        // 状态, 在非抽象类里 TypeLoad。清除全部非接口类型里的 abstract 残留并补 stub。
        int absFixed = 0;
        foreach (var t in mod.GetTypes())
        {
            if (t.IsInterface) continue;
            // <Module> 全局方法 CLR 强制要求 static
            bool global = t == mod.GlobalType;
            foreach (var m in t.Methods)
            {
                if (global)
                {
                    var na = (m.Attributes | MethodAttributes.Static) & ~(MethodAttributes.Virtual | MethodAttributes.Abstract | MethodAttributes.NewSlot);
                    if (na != m.Attributes) { m.Attributes = na; absFixed++; }
                }
                if ((m.Attributes & MethodAttributes.Abstract) == 0) continue;
                m.Attributes &= ~MethodAttributes.Abstract;
                if (!m.HasBody)
                {
                    var body = new CilBody();
                    var ret = m.MethodSig?.RetType;
                    if (ret != null && ret.FullName != "System.Void")
                    {
                        switch (ret.ElementType)
                        {
                            case ElementType.Boolean: case ElementType.Char:
                            case ElementType.I1: case ElementType.U1: case ElementType.I2: case ElementType.U2:
                            case ElementType.I4: case ElementType.U4: case ElementType.I8: case ElementType.U8:
                            case ElementType.R4: case ElementType.R8: case ElementType.I: case ElementType.U:
                                body.Instructions.Add(Instruction.CreateLdcI4(0)); break;
                            default: body.Instructions.Add(Instruction.Create(OpCodes.Ldnull)); break;
                        }
                    }
                    body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                    m.Body = body; m.Body.MaxStack = 8;
                }
                absFixed++;
            }
        }
        Console.WriteLine("[s1] abstract residual cleared: {0}", absFixed);

        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, opts);
        Console.WriteLine("[s1] written: " + outPath);
        // fail>0 = 安全降级(保持 NRS 原状), 不是硬失败; 硬门禁在 probe
        return 0;
    }

    /// <summary>clause 六元组 (flags, tryOff, tryLen, hOff, hLen, cls)。</summary>
    record struct EhClause(uint Flags, uint TryOff, uint TryLen, uint HOff, uint HLen, uint Cls);

    /// <summary>构建 dnlib 可解析的 fat EH 段: 段头 byte0=0x41(0x40|kind1), dsize 不含头。</summary>
    static byte[] BuildFatEh(List<EhClause> clauses)
    {
        int dsize = clauses.Count * 24;
        var outp = new byte[4 + dsize];
        BitConverter.GetBytes((uint)((dsize << 8) | 0x41)).CopyTo(outp, 0);
        for (int i = 0; i < clauses.Count; i++)
        {
            var c = clauses[i];
            int o = 4 + i * 24;
            BitConverter.GetBytes(c.Flags).CopyTo(outp, o);
            BitConverter.GetBytes(c.TryOff).CopyTo(outp, o + 4);
            BitConverter.GetBytes(c.TryLen).CopyTo(outp, o + 8);
            BitConverter.GetBytes(c.HOff).CopyTo(outp, o + 12);
            BitConverter.GetBytes(c.HLen).CopyTo(outp, o + 16);
            BitConverter.GetBytes(c.Cls).CopyTo(outp, o + 20);
        }
        return outp;
    }

    /// <summary>CORINFO EH dump (4B count + 28B/条) -> dnlib fat EH 段。</summary>
    static byte[] CorInfoToCliEh(byte[] cor)
    {
        if (cor.Length < 4) return null;
        int cnt = BitConverter.ToInt32(cor, 0);
        if (cnt <= 0 || cor.Length < 4 + cnt * 28) return null;
        var clauses = new List<EhClause>(cnt);
        for (int i = 0; i < cnt; i++)
        {
            int b = 4 + i * 28;
            uint f = BitConverter.ToUInt32(cor, b);
            uint tryOff = BitConverter.ToUInt32(cor, b + 4);
            uint tryLen = BitConverter.ToUInt32(cor, b + 8);
            uint hOff = BitConverter.ToUInt32(cor, b + 12);
            uint hLen = BitConverter.ToUInt32(cor, b + 16);
            uint cls = BitConverter.ToUInt32(cor, b + 20);
            // CORINFO: 0=catch 1=filter 2=finally 3=fault; CLI: 0/1/2/4(fault) —— fault 3→4
            uint cliFlags = f == 3 ? 4u : (f <= 2 ? f : 0u);
            clauses.Add(new EhClause(cliFlags, tryOff, tryLen, hOff, hLen, cls));
        }
        return BuildFatEh(clauses);
    }

    /// <summary>
    /// token 重映射 Resolver: mt IL 里的 TypeDef/TypeRef token 是基线空间, 而 NRS 删了
    /// 673 个类型导致 Slayed 的 TypeDef rid 错位(castclass/ldtoken 会解析到错误类型甚至
    /// 值类型, JIT 拒绝)。按 FullName 把基线 token 映射到 Slayed 对象。
    /// </summary>
    class RemapResolver : IInstructionOperandResolver
    {
        readonly IInstructionOperandResolver inner;   // Slayed 模块
        readonly ModuleDefMD bmod;                    // 基线模块(token 空间权威)
        readonly Dictionary<string, TypeDef> tdMap;   // FullName -> Slayed TypeDef(含壳)
        readonly Dictionary<string, TypeRef> trMap;   // FullName -> Slayed TypeRef
        readonly Dictionary<string, MemberRef> mrMap; // "类::名(sig)" -> Slayed MemberRef
        readonly Dictionary<uint, IMDTokenProvider> cache = new();

        public RemapResolver(IInstructionOperandResolver inner, ModuleDefMD bmod,
            Dictionary<string, TypeDef> tdMap, Dictionary<string, TypeRef> trMap,
            Dictionary<string, MemberRef> mrMap)
        {
            this.inner = inner; this.bmod = bmod; this.tdMap = tdMap; this.trMap = trMap; this.mrMap = mrMap;
        }

        // MemberRef 的身份 key: 引用类全名 + 成员名 + 签名串(区分重载)
        public static string MemberKey(MemberRef mr)
        {
            var cls = mr.Class != null ? mr.Class.FullName : "?";
            var sig = mr.MethodSig != null ? mr.MethodSig.ToString() : (mr.FieldSig != null ? mr.FieldSig.ToString() : "?");
            return cls + "::" + mr.Name + "(" + sig + ")";
        }

        public string ReadUserString(uint token) => inner.ReadUserString(token);

        public IMDTokenProvider ResolveToken(uint token, GenericParamContext gpContext)
        {
            byte table = (byte)(token >> 24);
            if (table == 0x0A)
            {
                if (cache.TryGetValue(token, out var hitM)) return hitM;
                IMDTokenProvider mappedM = null;
                try
                {
                    if (bmod.ResolveToken(token) is MemberRef bmr)
                    {
                        var key = MemberKey(bmr);
                        if (mrMap.TryGetValue(key, out var hit)) mappedM = hit;
                    }
                }
                catch { }
                if (mappedM != null) { cache[token] = mappedM; return mappedM; }
                return (IMDTokenProvider)inner.ResolveToken(token, gpContext);
            }
            if (table == 0x01 || table == 0x02)
            {
                if (cache.TryGetValue(token, out var hit)) return hit;
                ITypeDefOrRef mapped = null;
                try
                {
                    var bt = bmod.ResolveToken(token) as ITypeDefOrRef;
                    if (bt != null)
                    {
                        if (bt is TypeDef btd && tdMap.TryGetValue(btd.FullName, out var hitT))
                            mapped = hitT;
                        else if (bt is TypeRef btr && trMap.TryGetValue(btr.FullName, out var hitR))
                            mapped = hitR;
                        else if (tdMap.TryGetValue(bt.FullName, out var hit3))
                            mapped = hit3;
                    }
                }
                catch { /* 基线侧解析失败则回落 */ }
                if (mapped != null) { cache[token] = mapped; return mapped; }
                // 映射失败: 回落到 Slayed 直接解析(保持旧行为)
                return (IMDTokenProvider)inner.ResolveToken(token, gpContext);
            }
            return inner.ResolveToken(token, gpContext);
        }
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
        // corlib 内建类型(Void/Object/Int32/...)必须保留 CorLibTypeSig(写出 ELEMENT_TYPE_VOID 等):
        // 若当普通 TypeDefOrRefSig 重建, System.Void 会写成 VALUETYPE+Void token —— mono 报
        // "Expected value type but got type kind 1", 桌面 CLR 报签名错误。
        if (t is CorLibTypeSig csig)
        {
            var cor = s_mod.CorLibTypes;
            switch (csig.ElementType)
            {
                case ElementType.Void: return cor.Void;
                case ElementType.Boolean: return cor.Boolean;
                case ElementType.Char: return cor.Char;
                case ElementType.I1: return cor.SByte;
                case ElementType.U1: return cor.Byte;
                case ElementType.I2: return cor.Int16;
                case ElementType.U2: return cor.UInt16;
                case ElementType.I4: return cor.Int32;
                case ElementType.U4: return cor.UInt32;
                case ElementType.I8: return cor.Int64;
                case ElementType.U8: return cor.UInt64;
                case ElementType.R4: return cor.Single;
                case ElementType.R8: return cor.Double;
                case ElementType.String: return cor.String;
                case ElementType.Object: return cor.Object;
                case ElementType.TypedByRef: return cor.TypedReference;
                case ElementType.I: return cor.IntPtr;
                case ElementType.U: return cor.UIntPtr;
            }
        }
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

    /// <summary>壳构造期的类型映射(不依赖循环变量, 直接复用 MapTdor)。</summary>
    static ITypeDefOrRef MapTdorStatic(ITypeDefOrRef t) => MapTdor(t);

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
