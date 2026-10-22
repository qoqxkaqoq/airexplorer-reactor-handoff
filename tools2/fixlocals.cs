using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// fixlocals: nbjit 写回时 localsTok=0, nbrestore 只能填一堆 System.Object 占位,
// 于是 ldloc + ldfld 具体字段在 .NET Framework 上直接 AV
// (full trust 下 JIT 不验证, 按 object 布局取偏移 -> 访问违规)。
// 这里从 cilantro 的同名方法把真实 locals 类型搬过来。
//
// 用法: fixlocals <src(cilantro)> <dst> <out> [--dump]
class FixLocals {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: fixlocals <src> <dst> <out> [--dump]"); return; }
        var src = ModuleDefMD.Load(a[0]);
        var dst = ModuleDefMD.Load(a[1]);
        bool dump = a.Any(x => x == "--dump");
        var importer = new Importer(dst, ImporterOptions.TryToUseDefs);

        var idx = new Dictionary<string, List<MethodDef>>();
        foreach (var t in src.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var k = t.FullName + "::" + m.Name + "/" + m.MethodSig.Params.Count;
                if (!idx.ContainsKey(k)) idx[k] = new List<MethodDef>();
                idx[k].Add(m);
            }

        int fixedM = 0, fixedV = 0, miss = 0, allObjTotal = 0;
        foreach (var t in dst.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody || m.Body.Variables.Count == 0) continue;
                // 逐变量判断: 之前只看"全部是 Object", 漏掉了 240/255 是 Object 的方法
                // (如 GenerateAdaptableExtractor: 前 15 个真类型 + 240 个 Object)
                int nObj = m.Body.Variables.Count(v => v.Type.FullName == "System.Object");
                if (nObj == 0) continue;
                allObjTotal++;
                var k = t.FullName + "::" + m.Name + "/" + m.MethodSig.Params.Count;
                if (!idx.TryGetValue(k, out var cands)) { miss++; continue; }
                var sm = cands.FirstOrDefault(x => x.Body.Variables.Count > 0 && !x.Body.Variables.All(v => v.Type.FullName == "System.Object"));
                if (sm == null) { miss++; continue; }
                var sv = sm.Body.Variables;
                // 只有数量完全一致才按 index 对齐(否则整体跳过, 避免错位)
                if (sv.Count != m.Body.Variables.Count) { miss++; continue; }
                int n = 0;
                for (int i = 0; i < sv.Count; i++) {
                    if (m.Body.Variables[i].Type.FullName != "System.Object") continue;
                    m.Body.Variables[i].Type = importer.Import(sv[i].Type);
                    n++;
                }
                fixedM++; fixedV += n;
                if (dump) Console.WriteLine("[fix] " + t.FullName + "::" + m.Name + "  " + m.Body.Variables.Count + " -> " + sv.Count);
            }
        }
        Console.WriteLine("[fixlocals] allObjectMethods=" + allObjTotal + " fixed=" + fixedM + " locals=" + fixedV + " miss=" + miss);
        var wopt = new ModuleWriterOptions(dst);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        dst.Write(a[2], wopt);
        Console.WriteLine("[out] " + a[2]);
    }
}
