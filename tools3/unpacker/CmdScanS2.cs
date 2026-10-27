using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>scans2 — 扫描 "ldc.i4 <n>; call <m>" 模式，按 call 目标统计——识别字符串解密器。</summary>
public static class CmdScanS2
{
    /// <summary>scans2 <exe> concat — 扫 ldstr+ldstr+Concat 模式，重建拼接出的 API 名。</summary>
    public static int ScanConcat(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: scans2 <exe> concat"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                for (int i = 0; i < ins.Count - 2; i++)
                {
                    if (ins[i].OpCode.Code != Code.Ldstr) continue;
                    if (ins[i+1].OpCode.Code == Code.Call && ins[i+1].Operand is MethodDef cm1 &&
                        cm1.Name == "Trim") { /* ldstr; call Trim; ldstr; ... */ }
                    if (ins[i+2].OpCode.Code != Code.Ldstr) continue;
                    var nxt = i + 3 < ins.Count ? ins[i + 3] : null;
                    if (nxt == null) continue;
                    // 找 Concat: 模式宽容——两个 ldstr 之间允许一个 call(Trim)
                    var s1 = ins[i].Operand as string;
                    var s2 = ins[i + 2].Operand as string;
                    if (s1 == null || s2 == null) continue;
                    if (s1.Length + s2.Length < 3) continue;
                    if (false)                         Console.WriteLine("  [{0}] {1}::{2} IL_{3:X4}: \"{4}\" + \"{5}\"",
                            (uint)m.MDToken.Raw, t.FullName, m.Name, ins[i].Offset, s1, s2);
                }
            }
        return 0;
    }

    /// <summary>scans2 <exe> idxinv — 扫 ldc.i4 <n> 后 4 条内出现 ldsfld+callvirt 的模式（委托式取串）。</summary>
    public static int ScanIdxInvoke(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: scans2 <exe> idxinv"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        var freq = new Dictionary<uint, (int cnt, string name)>();
        var idxSamples = new Dictionary<uint, List<int>>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                for (int i = 0; i < ins.Count; i++)
                {
                    if (ins[i].OpCode.Code != Code.Ldc_I4 && ins[i].OpCode.Code != Code.Ldc_I4_S) continue;
                    int idx = ins[i].OpCode.Code == Code.Ldc_I4 ? (int)ins[i].Operand : (sbyte)ins[i].Operand;
                    // 向后看 4 条内: ldsfld(委托字段) + callvirt(Invoke)
                    bool hasField = false, hasInvoke = false;
                    FieldDef fld = null;
                    for (int j = i + 1; j < Math.Min(i + 5, ins.Count); j++)
                    {
                        if (ins[j].OpCode.Code == Code.Ldsfld || ins[j].OpCode.Code == Code.Ldsflda) { hasField = true; fld = ins[j].Operand as FieldDef; }
                        if (ins[j].OpCode.Code == Code.Callvirt && ins[j].Operand is IMethod im && im.Name.String == "Invoke") hasInvoke = true;
                    }
                    if (!hasField || !hasInvoke || fld == null) continue;
                    uint fk = (uint)fld.MDToken.Raw;
                    if (!freq.TryGetValue(fk, out var v)) { freq[fk] = (0, fld.DeclaringType?.FullName + "::" + fld.Name); idxSamples[fk] = new List<int>(); }
                    freq[fk] = (freq[fk].cnt + 1, freq[fk].name);
                    if (idxSamples[fk].Count < 8) idxSamples[fk].Add(idx);
                }
            }
        foreach (var kv in freq.OrderByDescending(x => x.Value.cnt).Take(15))
            Console.WriteLine("  field 0x{0:X8} x{1}  {2}  idx样本: [{3}]", kv.Key, kv.Value.cnt, kv.Value.name,
                string.Join(",", idxSamples[kv.Key]));
        return 0;
    }

    /// <summary>scans2 <exe> resref — 找引用资源名的 ldstr（GetManifestResourceStream 等）。</summary>
    public static int ScanResRef(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: scans2 <exe> resref"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        string[] names = { "ValidatorViewer", "EmitterReporter", "ValidatorProc", "ValidatorProject", "DefinitionError", "FactoryValidator" };
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions)
                {
                    if (ins.OpCode.Code != Code.Ldstr) continue;
                    var sv = ins.Operand as string;
                    if (sv == null) continue;
                    foreach (var nm in names)
                        if (sv.Contains(nm))
                        {
                            Console.WriteLine("[{0}] {1}::{2} @IL_{3:X4}: ldstr \"{4}\"", (uint)m.MDToken.Raw,
                                t.FullName, m.Name, ins.Offset, sv);
                            break;
                        }
                }
            }
        return 0;
    }

    /// <summary>scans2 <exe> appdom — 找现有 AppDomain TypeRef 与 UnhandledException MemberRef。</summary>
    public static int ScanAppDomain(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: scans2 <exe> appdom"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        foreach (var tr in mod.GetTypeRefs())
            if (tr.FullName == "System.AppDomain")
            {
                Console.WriteLine("TypeRef 0x{0:X8} {1} scope={2}", (uint)tr.MDToken.Raw, tr.FullName, tr.ResolutionScope);
                break;
            }
        foreach (var mr in mod.GetMemberRefs())
        {
            if (mr.Name.String.Contains("UnhandledException") || (mr.Name.String == "get_CurrentDomain" && mr.Class?.FullName == "System.AppDomain"))
                Console.WriteLine("MemberRef 0x{0:X8} {1}::{2} sig={3}", (uint)mr.MDToken.Raw, mr.Class?.FullName, mr.Name,
                    mr.MethodSig != null ? mr.MethodSig.ToString() : "?");
        }
        return 0;
    }

    /// <summary>scans2 <exe> concatall — 列出全部 ldstr+ldstr(+call) 组合。</summary>
    public static int ScanConcatAll(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: scans2 <exe> concatall"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                for (int i = 0; i < ins.Count - 2; i++)
                {
                    if (ins[i].OpCode.Code != Code.Ldstr || ins[i].Operand is not string s1 || s1.Length < 2) continue;
                    // 允许中间有 ldstr 链: 收集连续 ldstr 序列（中间夹 call Trim/Concat）
                    var parts = new List<string> { s1 };
                    int j = i + 1;
                    while (j < ins.Count)
                    {
                        if (ins[j].OpCode.Code == Code.Ldstr && ins[j].Operand is string s2) { parts.Add(s2); j++; continue; }
                        if (ins[j].OpCode.Code == Code.Call && ins[j].Operand is MethodDef cm &&
                            (cm.Name == "Trim" || cm.Name == "Concat")) { j++; continue; }
                        break;
                    }
                    if (parts.Count < 2) continue;
                    // 确认后面跟着 Concat（用于构造 API 名）
                    bool hasConcat = false;
                    for (int k = i + 1; k < Math.Min(j + 2, ins.Count); k++)
                        if (ins[k].OpCode.Code == Code.Call && ins[k].Operand is MethodDef cm2 && cm2.Name == "Concat") hasConcat = true;
                    if (!hasConcat) continue;
                    string full = string.Join("", parts);
                    Console.WriteLine("[0x{0:X8}] {1}::{2} IL_{3:X4}: {4} => \"{5}\"", (uint)m.MDToken.Raw,
                        t.FullName, m.Name, ins[i].Offset, string.Join(" | ", parts), full);
                    i = j;  // 跳过已消费
                }
            }
        return 0;
    }

    public static int Run(string[] args)
    {
        if (args.Length >= 3 && args[2] == "concat") return ScanConcat(args);
        if (args.Length >= 3 && args[2] == "concatall") return ScanConcatAll(args);
        if (args.Length >= 3 && args[2] == "appdom") return ScanAppDomain(args);
        if (args.Length >= 3 && args[2] == "resref") return ScanResRef(args);
        if (args.Length >= 3 && args[2] == "idxinv") return ScanIdxInvoke(args);
        if (args.Length < 2) { Console.WriteLine("usage: scans2 <exe>"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        // 统计: ldc.i4(或ldc.i4.s/n) 后紧跟 call/callvirt 的目标方法频率
        var freq = new Dictionary<uint, (int cnt, string name)>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                for (int i = 0; i < ins.Count - 1; i++)
                {
                    if (ins[i].OpCode.Code != Code.Ldc_I4 && ins[i].OpCode.Code != Code.Ldc_I4_S &&
                        ins[i].OpCode.Code != Code.Ldc_I4_0 && ins[i].OpCode.Code != Code.Ldc_I4_1) continue;
                    var nxt = ins[i + 1];
                    if (nxt.OpCode.Code != Code.Call && nxt.OpCode.Code != Code.Callvirt) continue;
                    if (nxt.Operand is not MethodDef cm) continue;   // 只看本模块方法
                    if (!freq.TryGetValue((uint)cm.MDToken.Raw, out var v)) freq[(uint)cm.MDToken.Raw] = (0, cm.FullName);
                    freq[(uint)cm.MDToken.Raw] = (v.cnt + 1, v.name);
                }
            }
        foreach (var kv in freq.OrderByDescending(x => x.Value.cnt).Take(20))
            Console.WriteLine("  call 0x{0:X8} x{1}  {2}", kv.Key, kv.Value.cnt, kv.Value.name);
        return 0;
    }
}
