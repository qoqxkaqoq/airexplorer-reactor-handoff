using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// ehfixoff — 用官方 JIT dump 的 m_<rid>.eh (28B CORINFO clause) + .ehn (catch 类型名)
// 校正目标 exe 的 EH catch 类型。
//
// 背景: v66 的 catch 类型有 1515 个是 fixeh 从 cilantro 按序号搬的(搬错); A 线
// forcedump 在 managed 侧拿到的官方 EH 挂在 .eh/.ehn。官方 classTok 是"外来 token
// 空间"(解密上下文), 对本模块无意义 —— 所以以 .ehn 的名字为第一来源, tok 仅当
// ResolveToken 成功(本模块 TypeDef/TypeRef)时用。
//
// 保守策略: 只在 clause 数量与 kind 全部一致时替换 CatchType(不动区间 —— 区间来自
// v66 自己的体, 自洽; offset 换成官方的反而可能对不上 cilantro 体)。
//
// 用法: ehfixoff <dumpDir> <in.exe> <out.exe> [--strict]
class EhFixOff {
    static Dictionary<string, TypeDef> _byFull;
    static Dictionary<string, ITypeDefOrRef> _byRefFull;
    static ModuleDef _mod;

    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: ehfixoff <dumpDir> <in> <out>"); return; }
        string dumpDir = a[0];
        _mod = ModuleDefMD.Load(a[1]);
        var importer = new Importer(_mod, ImporterOptions.TryToUseDefs);

        int fixedM = 0, fixedC = 0, kindMismatch = 0, noDump = 0, cntMismatch = 0, tokHit = 0, nameHit = 0, keepOld = 0, bodyMismatch = 0;

        foreach (var t in _mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody || m.Body.ExceptionHandlers.Count == 0) continue;
                string tok = m.MDToken.Raw.ToString("X8");
                string ep = Path.Combine(dumpDir, "m_" + tok + ".eh");
                if (!File.Exists(ep)) { noDump++; continue; }

                // ★ 体一致性指纹(同 locsig v2): IL 不是这份 dump 的体时不碰
                string bp = Path.Combine(dumpDir, "m_" + tok + ".bin");
                if (!File.Exists(bp)) { bodyMismatch++; continue; }
                var braw0 = File.ReadAllBytes(bp);
                if (braw0.Length < 24) { bodyMismatch++; continue; }
                if (BitConverter.ToUInt32(braw0, 4) != (uint)m.Body.Instructions.Sum(i => i.GetSize())
                    || BitConverter.ToUInt32(braw0, 12) != (uint)m.Body.ExceptionHandlers.Count) { bodyMismatch++; continue; }

                var raw = File.ReadAllBytes(ep);
                if (raw.Length < 4) continue;
                uint cnt = BitConverter.ToUInt32(raw, 0);
                if (cnt != (uint)m.Body.ExceptionHandlers.Count) { cntMismatch++; continue; }

                // .ehn: ci\tName(运行时 CLR 格式, 嵌套是 '+')
                var names = new Dictionary<int, string>();
                string np = Path.Combine(dumpDir, "m_" + m.MDToken.Raw.ToString("X8") + ".ehn");
                if (File.Exists(np)) {
                    int ci = 0;
                    foreach (var ln in File.ReadAllLines(np)) {
                        var p = ln.Split('\t');
                        if (p.Length >= 2) names[ci] = p[1];
                        ci++;
                    }
                }

                bool ok = true;
                for (int i = 0; i < cnt; i++) {
                    int o = 4 + i * 28;
                    uint flags = BitConverter.ToUInt32(raw, o);
                    // 区间一致性旁证(不求相同, 但 kind 必须一致):
                    uint offTryLen = BitConverter.ToUInt32(raw, o + 8);
                    uint offHLen = BitConverter.ToUInt32(raw, o + 16);
                    uint offTok = BitConverter.ToUInt32(raw, o + 20);
                    uint offExtra = BitConverter.ToUInt32(raw, o + 24);
                    var eh = m.Body.ExceptionHandlers[i];
                    // 期望 kind: 0=None(catch) 1=Filter 2=Finally 3=Fault
                    var want = flags == 1u ? ExceptionHandlerType.Filter
                             : flags == 2u ? ExceptionHandlerType.Finally
                             : flags == 3u ? ExceptionHandlerType.Fault
                             : ExceptionHandlerType.Catch;
                    if (eh.HandlerType != want) { ok = false; break; }
                    // filter 的 tok 位置是 FilterOffset 不是类型 token; catch 才有类型
                    if (want == ExceptionHandlerType.Filter) continue;
                    if (want == ExceptionHandlerType.Finally || want == ExceptionHandlerType.Fault) continue;

                    ITypeDefOrRef newType = null;
                    // 1) 官方 tok 若能解析到本模块 → 直接用
                    if ((offTok & 0xFF000000u) == 0x01000000u || (offTok & 0xFF000000u) == 0x02000000u) {
                        try {
                            var res = _mod.ResolveToken(offTok) as ITypeDefOrRef;
                            if (res != null) { newType = res; tokHit++; }
                        } catch { }
                    }
                    // 2) .ehn 名字 → 按名解析(嵌套 '+' 归一化)
                    if (newType == null && names.TryGetValue(i, out var nm)) {
                        var r = ResolveByName(nm);
                        if (r != null) { newType = r; nameHit++; }
                    }
                    // 3) 都没有 → 保留现有
                    if (newType == null) { keepOld++; continue; }
                    if (eh.CatchType == null || eh.CatchType.FullName != newType.FullName) {
                        // catch 类型恒为引用类型, Import(ITypeDefOrRef) 直接换
                        eh.CatchType = importer.Import(newType);
                        fixedC++;
                    }
                }
                if (!ok) { kindMismatch++; continue; }
                fixedM++;
            }
        }
        Console.WriteLine("[ehfixoff] methodsChecked=" + fixedM + " catchFixed=" + fixedC
            + " tokHit=" + tokHit + " nameHit=" + nameHit + " keepOld=" + keepOld
            + " cntMismatch=" + cntMismatch + " kindMismatch=" + kindMismatch+ " noDump=" + noDump + " bodyMismatch=" + bodyMismatch);
        var wopt = new ModuleWriterOptions(_mod);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        _mod.Write(a[2], wopt);
        Console.WriteLine("[out] " + a[2]);
    }

    static ITypeDefOrRef ResolveByName(string full) {
        full = full.Trim();
        if (_byFull == null) {
            _byFull = new Dictionary<string, TypeDef>();
            foreach (var t in _mod.GetTypes())
                if (!_byFull.ContainsKey(t.FullName)) _byFull[t.FullName] = t;
            _byRefFull = new Dictionary<string, ITypeDefOrRef>();
            foreach (var tr in _mod.GetTypeRefs())
                if (!_byRefFull.ContainsKey(tr.FullName)) _byRefFull[tr.FullName] = tr;
        }
        string dn = full.Replace('+', '/');
        if (_byFull.TryGetValue(dn, out var td)) return td;
        if (_byRefFull.TryGetValue(dn, out var r)) return r;
        if (_byRefFull.TryGetValue(full, out var r2)) return r2;
        // corlib 常见 catch 类型兜底
        int dot = dn.LastIndexOf('.');
        if (dot > 0) {
            var ns = dn.Substring(0, dot);
            var nm2 = dn.Substring(dot + 1);
            if (ns == "System" && nm2.EndsWith("Exception")) return FindCorlibType(_mod, ns, nm2);
        }
        return null;
    }

    static ITypeDefOrRef FindCorlibType(ModuleDef mod, string ns, string nm) {
        // 在 TypeRef 表找 corlib 命名空间下同名引用
        foreach (var tr in mod.GetTypeRefs())
            if (tr.Namespace == ns && tr.Name == nm && tr.ResolutionScope is AssemblyRef ar && ar.Name == "mscorlib") return tr;
        return new TypeRefUser(mod, ns, nm, mod.CorLibTypes.AssemblyRef);
    }
}
