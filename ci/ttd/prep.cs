// prep — C2 最小链: 官方样本正常引导后, 对目标方法做 PrepareMethod 强制 JIT + 新鲜体读取
// 同时是 TTD 录制的宿主进程 (DynamicMethod 唯一 ilSize 标记夹住每次强制/自然调用)
//
// 用法: prep <officialExe> <outDir> <delaySec> [mode] [skipwalk]
//   mode=prep  (默认) 逐目标: marker → PrepareMethod → 新鲜读体 (变更则 dump)
//   mode=agcall        marker → 反射触发 AG.cctor + EvaluateVisibleAttribute 自然执行 → marker
//                      (自然 JIT 路径, RequestWorker.cctor/ctor/TemplateInitializer.ctor 真体在此窗口)
//   skipwalk=1         跳过 Phase C 全量桩复查 (TTD 录制时省时)
//
// dump 格式与 forcedump 完全一致: 24B 头(tok/ilSize/maxStack/ehCount/0/0)+IL; .loc=index|isPinned|TypeFullName
// 输出: outDir/m_<tok>.bin/.loc/.eh + prep.log + postdump.tsv
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

class Prep {
    static StreamWriter Log_;
    static string OutDir = ".";
    static object Lock = new object();
    static void Log(string s) {
        lock (Lock) { Console.WriteLine(s); try { Log_.WriteLine(s); Log_.Flush(); } catch {} }
    }

    // 唯一 ilSize 标记: nops+ret → ilSize = n+1
    static void Marker(int n) {
        var dm = new System.Reflection.Emit.DynamicMethod("mk" + n, typeof(void), Type.EmptyTypes);
        var g = dm.GetILGenerator();
        for (int i = 0; i < n; i++) g.Emit(System.Reflection.Emit.OpCodes.Nop);
        g.Emit(System.Reflection.Emit.OpCodes.Ret);
        ((Action)dm.CreateDelegate(typeof(Action)))();
    }

    static int Main(string[] a) {
        // Log_ 必须最先建立, 任何早期异常都要落盘可查
        OutDir = a.Length > 1 ? a[1] : ".";
        try { if (!Path.IsPathRooted(OutDir)) OutDir = Path.GetFullPath(OutDir); Directory.CreateDirectory(OutDir); } catch {}
        try { Log_ = new StreamWriter(Path.Combine(OutDir, "prep.log")); } catch { Log_ = null; }
        try { return Run(a); }
        catch (Exception ex) { Log("[prep] FATAL " + Chain(ex)); return 9; }
    }

    static int Run(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: prep <exe> <outDir> <delaySec> [mode] [skipwalk]"); return 1; }
        string exe = Path.GetFullPath(a[0]);
        string mode = a.Length > 3 ? a[3] : "prep";
        int delay = int.Parse(a[2]);
        bool skipWalk = a.Length > 4 && a[4] == "skipwalk";
        Directory.SetCurrentDirectory(Path.GetDirectoryName(exe));
        Log("[prep] cwd=" + Environment.CurrentDirectory);

        using (var md5 = MD5.Create())
        using (var fs = File.OpenRead(exe))
            Log("[prep] exe=" + exe + " md5=" + BitConverter.ToString(md5.ComputeHash(fs)).Replace("-", ""));
        Log("[prep] mode=" + mode + " delay=" + delay + " skipwalk=" + skipWalk + " clr=" + Environment.Version);

        var asm = Assembly.LoadFrom(exe);
        Log("[prep] loaded " + asm.FullName);
        // 看门狗
        var wd = new Thread(delegate() { Thread.Sleep(25 * 60 * 1000); Log("[prep] WATCHDOG TIMEOUT"); Environment.Exit(42); });
        wd.IsBackground = true; wd.Start();

        // 引导: 模块 cctor
        foreach (var m in asm.GetModules()) {
            try { RuntimeHelpers.RunModuleConstructor(m.ModuleHandle); Log("[prep] module cctor OK"); }
            catch (Exception ex) { Log("[prep] module cctor FAIL: " + (ex.InnerException ?? ex).Message); }
        }

        Exception entryEx = null;
        var worker = new Thread(delegate() {
            try {
                var ep = asm.EntryPoint;
                object[] args = ep.GetParameters().Length == 1 ? new object[] { new string[0] } : new object[0];
                ep.Invoke(null, args);
            } catch (Exception ex) { entryEx = ex; Log("[prep] entry EX: " + Chain(ex)); }
        });
        worker.SetApartmentState(ApartmentState.STA);
        worker.Start();
        Log("[prep] entry launched, waiting " + delay + "s for boot...");
        Thread.Sleep(delay * 1000);
        Log("[prep] boot wait done, entryEx=" + (entryEx == null ? "none" : entryEx.GetType().Name));

        // 首批目标 + 对照组 (token, 名称)
        var targets = new[] {
            new[] { "06002AF0", "RequestWorker::.ctor" },
            new[] { "06002AF7", "TemplateInitializer::.ctor" },
            new[] { "06002F81", "AG::EvaluateVisibleAttribute" },
            new[] { "06002B06", "TI::InstantiateRandomIterator" },
            new[] { "06004196", "ITP" },
        };
        var mod = asm.GetModules()[0];
        int mi = 0;

        if (mode == "prep") {
            foreach (var t in targets) {
                uint tok = Convert.ToUInt32(t[0], 16);
                Marker(50000 + mi++);
                ForceAndDump(mod, tok, t[1], OutDir);
                Marker(50000 + mi++);
            }
        } else if (mode == "agcall") {
            // 自然执行夹逼: 首次触碰触发整条 JIT 链
            Marker(60000);
            try {
                var ag = asm.GetType("AirExplorer.Values.ArgumentGateway");
                RuntimeHelpers.RunClassConstructor(ag.TypeHandle);
                Log("[prep] AG.cctor natural OK");
            } catch (Exception ex) { Log("[prep] AG.cctor natural EX: " + Chain(ex)); }
            Marker(60001);
            try {
                var ag = asm.GetType("AirExplorer.Values.ArgumentGateway");
                ag.GetMethod("EvaluateVisibleAttribute", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)
                  .Invoke(null, null);
                Log("[prep] EVA natural OK");
            } catch (Exception ex) { Log("[prep] EVA natural EX: " + Chain(ex)); }
            Marker(60002);
            // 调用后再读一次目标方法的新鲜体
            foreach (var t in targets) FreshDumpIfChanged(mod, Convert.ToUInt32(t[0], 16), t[1], OutDir);
        }

        if (!skipWalk) {
            // Phase C: 全量桩复查 — 引导+强制后, 元数据视图是否已解密
            Log("[prep] phase C: full stub walk...");
            int stubs = 0, changed = 0, dumpFail = 0;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            foreach (var ty in AllTypes(asm)) {
                MethodInfo[] ms;
                try { ms = ty.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly); }
                catch { continue; }
                foreach (var m in ms) {
                    byte[] il0 = null;
                    try { var b = m.GetMethodBody(); il0 = b == null ? null : b.GetILAsByteArray(); } catch { continue; }
                    if (il0 == null || il0.Length > 4) continue;
                    stubs++;
                    try {
                        if (m.IsGenericMethodDefinition) continue;
                        RuntimeHelpers.PrepareMethod(m.MethodHandle);
                        if (FreshDumpIfChanged(mod, (uint)m.MetadataToken, ty.FullName + "::" + m.Name, OutDir)) changed++;
                    } catch { }
                    if (sw.ElapsedMilliseconds > 8 * 60 * 1000) { Log("[prep] phase C time cap reached"); goto done; }
                }
            }
        done:
            Log("[prep] phase C done: stubs=" + stubs + " changed=" + changed + " fail=" + dumpFail + " elapsed=" + sw.ElapsedMilliseconds + "ms");
            File.WriteAllText(Path.Combine(OutDir, "phaseC.summary"), "stubs=" + stubs + " changed=" + changed);
        }

        // RefScan: 官方引导后 — ① 直接读委托静态字段的运行时目标(最直接) ② 全量 IL 字节扫赋值点
        RefScan(asm, mod);

        Marker(99999);
        Log("[prep] ALL DONE");
        Log_.Close();
        return 0;
    }

    static IEnumerable<Type> AllTypes(Assembly asm) {
        Type[] ts = null;
        try { ts = asm.GetTypes(); }
        catch (System.Reflection.ReflectionTypeLoadException ex) { ts = ex.Types; }
        foreach (var t in ts) if (t != null) yield return t;
    }

    static void RefScan(Assembly asm, Module mod) {
        // ① 委托字段侦察: RunClassConstructor 暴露 cctor 真异常 → 读值拿目标 → 并抓全部委托类型 .cctor 真体(赋值点就在 cctor 里)
        var dlgFields = new[] {
            "ParserValidator::UpdateFunction",
            "AutomatedRunnerValidator::WatchSpec",
            "ExtendedManagerValidator::GetAnnotation",
            "ModelPredicate::ValidateCustomProvider",
            "ScalableCalcValidator::ValidateGenericController",
            "IsolatedExecutorValidator::ArrangeAggregator",
        };
        var allT = AllTypes(asm).ToList();
        Log("[dlgscan] begin fields=" + dlgFields.Length);
        foreach (var spec in dlgFields) {
            var parts = spec.Split(new[] { "::" }, StringSplitOptions.None);
            try {
                var ty = allT.FirstOrDefault(t => t.Name == parts[0]);
                if (ty == null) { Log("[dlgscan] type missing " + parts[0]); continue; }
                // 先强制触发 cctor(官方里未执行过的, 执行时 Reactor 会原地解密), 无论成败都让真体暴露在内存里
                try { RuntimeHelpers.RunClassConstructor(ty.TypeHandle); Log("[dlgscan] RunClassConstructor OK " + parts[0]); }
                catch (Exception e2) { Log("[dlgscan] RunClassConstructor EX " + parts[0] + ": " + Chain(e2)); }
                // cctor 真体无条件抓取 — 赋值点就在 cctor 里
                var cctor = ty.GetConstructor(BindingFlags.Static | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
                if (cctor != null) {
                    Log("[dlgscan] cctor of " + parts[0] + " tok=0x" + cctor.MetadataToken.ToString("X8"));
                    FreshDumpIfChanged(mod, (uint)cctor.MetadataToken, ty.FullName + "::.cctor", OutDir);
                }
                var f = ty.GetField(parts[1], BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                if (f == null) { Log("[dlgscan] field missing " + spec); continue; }
                var v = f.GetValue(null);
                if (v == null) { Log("[dlgscan] " + spec + " = NULL"); continue; }
                var d = v as Delegate;
                if (d == null) { Log("[dlgscan] " + spec + " = " + v.GetType().FullName + " (not delegate)"); continue; }
                var tgt = d.Method;
                Log("[dlgscan] " + spec + " -> " + tgt.DeclaringType.FullName + "::" + tgt.Name + " tok=0x" + tgt.MetadataToken.ToString("X8"));
                FreshDumpIfChanged(mod, (uint)tgt.MetadataToken, tgt.DeclaringType.FullName + "::" + tgt.Name + " (delegate target of " + spec + ")", OutDir);
            } catch (Exception ex) { Log("[dlgscan] " + spec + " EX " + Chain(ex)); }
        }

        // ② IL 字节扫描: newobj ParserValidator::.ctor(0x73) / stsfld(0x80) 各观察字段
        var wants = new List<Tuple<byte, uint>>();
        try {
            var pv = allT.FirstOrDefault(t => t.Name == "ParserValidator");
            var fld = pv == null ? null : pv.GetField("UpdateFunction", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
            if (fld != null) wants.Add(Tuple.Create((byte)0x80, (uint)fld.MetadataToken));
            var ctor = pv == null ? null : pv.GetConstructor(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance, null, new[] { typeof(object), typeof(IntPtr) }, null);
            if (ctor != null) wants.Add(Tuple.Create((byte)0x73, (uint)ctor.MetadataToken));
            var arv = allT.FirstOrDefault(t => t.Name == "AutomatedRunnerValidator");
            var fld2 = arv == null ? null : arv.GetField("WatchSpec", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
            if (fld2 != null) wants.Add(Tuple.Create((byte)0x80, (uint)fld2.MetadataToken));
        } catch (Exception ex) { Log("[refscan] token resolve fail: " + ex.Message); }
        if (wants.Count == 0) { Log("[refscan] no watch tokens"); return; }
        Log("[refscan] watch: " + string.Join(",", wants.Select(w => "0x" + w.Item2.ToString("X8") + "/op" + w.Item1.ToString("X2"))));
        int found = 0;
        foreach (var ty in allT) {
            MemberInfo[] ms;
            try { ms = ty.GetMembers(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly); } catch { continue; }
            foreach (var mi in ms) {
                MethodBase m = mi as MethodBase;
                if (m == null) continue;
                MethodBody b = null;
                try { b = m.GetMethodBody(); } catch { }
                if (b == null) continue;
                byte[] il;
                try { il = b.GetILAsByteArray(); } catch { continue; }
                if (il == null || il.Length < 6) continue;
                foreach (var w in wants) {
                    var tb = BitConverter.GetBytes(w.Item2);
                    bool hit = false;
                    for (int i = 0; i < il.Length - 4; i++) {
                        if (il[i] != w.Item1) continue;
                        if (il[i + 1] == tb[0] && il[i + 2] == tb[1] && il[i + 3] == tb[2] && il[i + 4] == tb[3]) { hit = true; break; }
                    }
                    if (!hit) continue;
                    found++;
                    Log("[refscan] HIT " + ty.FullName + "::" + m.Name + " tok=0x" + m.MetadataToken.ToString("X8") + " pattern=0x" + w.Item2.ToString("X8"));
                    FreshDumpIfChanged(mod, (uint)m.MetadataToken, ty.FullName + "::" + m.Name, OutDir);
                    break;
                }
            }
        }
        Log("[refscan] done hits=" + found);
    }

    // PrepareMethod 后新鲜读体; 变为真体(>4B)则 dump。用 MethodBase — .ctor 是 RuntimeConstructorInfo, 强转 MethodInfo 会失败
    static bool FreshDumpIfChanged(Module mod, uint tok, string name, string outDir) {
        try {
            var m = mod.ResolveMethod((int)tok);
            if (m == null) { Log("[prep] resolve fail " + name); return false; }
            MethodBody b = null;
            try { b = m.GetMethodBody(); } catch { }
            if (b == null) return false;
            var il = b.GetILAsByteArray();
            Log("[prep] " + tok.ToString("X8") + " " + name + " fresh ilSize=" + il.Length);
            if (il.Length <= 4) return false;
            Dump(mod, tok, m, b, il, outDir);
            return true;
        } catch (Exception ex) { Log("[prep] freshdump fail " + name + ": " + ex.Message); return false; }
    }

    static void ForceAndDump(Module mod, uint tok, string name, string outDir) {
        try {
            var m = mod.ResolveMethod((int)tok);
            if (m == null) { Log("[prep] resolve fail " + name); return; }
            MethodBody b0 = null; int sz0 = -1;
            try { b0 = m.GetMethodBody(); sz0 = b0 == null ? -1 : b0.GetILAsByteArray().Length; } catch { }
            Log("[prep] " + tok.ToString("X8") + " " + name + " before ilSize=" + sz0);
            if (m.IsGenericMethodDefinition) { Log("[prep] generic def, skip PrepareMethod"); return; }
            try { RuntimeHelpers.PrepareMethod(m.MethodHandle); Log("[prep] PrepareMethod OK"); }
            catch (Exception ex) { Log("[prep] PrepareMethod EX: " + (ex.InnerException ?? ex).Message); }
            FreshDumpIfChanged(mod, tok, name, outDir);
        } catch (Exception ex) { Log("[prep] forcedump fail " + name + ": " + ex.Message); }
    }

    static void Dump(Module mod, uint tok, MethodBase m, MethodBody b, byte[] il, string outDir) {
        var bout = new byte[24 + il.Length];
        Put(bout, 0, tok); Put(bout, 4, (uint)il.Length); Put(bout, 8, (uint)b.MaxStackSize);
        Put(bout, 12, (uint)b.ExceptionHandlingClauses.Count); Put(bout, 16, 0); Put(bout, 20, 0);
        Array.Copy(il, 0, bout, 24, il.Length);
        File.WriteAllBytes(Path.Combine(outDir, "m_" + tok.ToString("X8") + ".bin"), bout);
        try {
            var lvs = b.LocalVariables;
            if (lvs.Count > 0) {
                var lsb = new StringBuilder();
                foreach (var lv in lvs) lsb.Append(lv.LocalIndex).Append('|').Append(lv.IsPinned ? 1 : 0).Append('|').Append(lv.LocalType.FullName).Append('\n');
                File.WriteAllText(Path.Combine(outDir, "m_" + tok.ToString("X8") + ".loc"), lsb.ToString());
            }
        } catch { }
        try {
            var cl = b.ExceptionHandlingClauses;
            if (cl.Count > 0) {
                var buf = new byte[4 + cl.Count * 28];
                Put(buf, 0, (uint)cl.Count);
                for (int i = 0; i < cl.Count; i++) {
                    var c = cl[i]; int o = 4 + i * 28;
                    uint f = c.Flags == ExceptionHandlingClauseOptions.Finally ? 2u : c.Flags == ExceptionHandlingClauseOptions.Filter ? 1u : c.Flags == ExceptionHandlingClauseOptions.Fault ? 3u : 0u;
                    Put(buf, o, f); Put(buf, o + 4, (uint)c.TryOffset); Put(buf, o + 8, (uint)c.TryLength);
                    Put(buf, o + 12, (uint)c.HandlerOffset); Put(buf, o + 16, (uint)c.HandlerLength);
                    uint t20 = 0;
                    if (c.Flags == ExceptionHandlingClauseOptions.Filter) t20 = (uint)c.FilterOffset;
                    else if (c.Flags == ExceptionHandlingClauseOptions.Clause && c.CatchType != null) t20 = (uint)c.CatchType.MetadataToken;
                    Put(buf, o + 20, t20); Put(buf, o + 24, 0);
                }
                File.WriteAllBytes(Path.Combine(outDir, "m_" + tok.ToString("X8") + ".eh"), buf);
            }
        } catch { }
        Log("[prep] DUMPED m_" + tok.ToString("X8") + " (" + il.Length + "B il, " + b.LocalVariables.Count + " locals, " + b.ExceptionHandlingClauses.Count + " eh)");
    }

    static void Put(byte[] b, int o, uint v) { b[o] = (byte)v; b[o+1] = (byte)(v>>8); b[o+2] = (byte)(v>>16); b[o+3] = (byte)(v>>24); }
    static string Chain(Exception ex) {
        var sb = new StringBuilder();
        for (var e = ex; e != null; e = e.InnerException) { sb.Append(e.GetType().FullName).Append(": ").Append(e.Message); if (e.InnerException != null) sb.Append(" <-- "); }
        return sb.ToString();
    }
}
