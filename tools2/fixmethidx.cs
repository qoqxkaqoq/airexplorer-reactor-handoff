using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// fixmethidx: 移植体里残留的"源模块方法名"(generatedMethod_0288 这类 nb_slayer 命名),
// 目标模块里没有 -> MissingMethodException。按"同类型内方法序号"回退映射。
// 与 fixfieldidx 同理, 只是对象换成方法。
// 用法: fixmethidx <src(cilantro)> <dst> <out> [--dump]
class FixMethIdx {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: fixmethidx <src> <dst> <out> [--dump]"); return; }
        var src = ModuleDefMD.Load(a[0]);
        var dst = ModuleDefMD.Load(a[1]);
        bool dump = a.Any(x => x == "--dump");

        // 源: 类型 FullName -> (方法名 -> 索引)
        var srcIdx = new Dictionary<string, Dictionary<string, int>>();
        foreach (var t in src.GetTypes()) {
            var d = new Dictionary<string, int>();
            for (int i = 0; i < t.Methods.Count; i++) if (!d.ContainsKey(t.Methods[i].Name.String)) d[t.Methods[i].Name.String] = i;
            srcIdx[t.FullName] = d;
        }

        int n = 0, miss = 0;
        foreach (var t in dst.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    var im = ins.Operand as IMethod;
                    if (im == null) continue;
                    var dt = im.DeclaringType;
                    if (dt == null) continue;
                    var dtName = dt.FullName;
                    var dstT = dst.Find(dtName, false);
                    if (dstT == null) continue;
                    var nm = im.Name.String;
                    if (dstT.Methods.Any(x => x.Name.String == nm)) continue;
                    // 目标类型里没有这个方法名 -> 按源索引回退
                    if (!srcIdx.TryGetValue(dtName, out var map)) { miss++; continue; }
                    if (!map.TryGetValue(nm, out int idx)) { miss++; continue; }
                    if (idx >= dstT.Methods.Count) { miss++; continue; }
                    var target = dstT.Methods[idx];
                    // 参数个数一致才换, 否则跳过
                    int want = im.MethodSig == null ? -1 : im.MethodSig.Params.Count;
                    if (target.MethodSig != null && want >= 0 && target.MethodSig.Params.Count != want) { miss++; continue; }
                    if (dump) Console.WriteLine("[fix] " + dtName + "::" + nm + " (idx " + idx + ") -> " + target.Name);
                    ins.Operand = target;
                    n++;
                }
            }
        }
        Console.WriteLine("[fixmethidx] fixed=" + n + " miss=" + miss);
        var wopt = new ModuleWriterOptions(dst);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        dst.Write(a[2], wopt);
        Console.WriteLine("[out] " + a[2]);
    }
}
