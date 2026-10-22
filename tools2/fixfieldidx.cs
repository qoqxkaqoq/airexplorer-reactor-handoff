using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// fixfieldidx: 移植体里残留的"源模块字段名"(booleanField_0287 这类 nb_slayer 命名),
// 目标模块里没有 -> MissingFieldException。按"同类型内字段序号"回退映射。
// 前提: 两版同一类型的字段顺序一致(cilantro 只是改了名, 没重排)。
//
// 用法: fixfieldidx <src(cilantro)> <dst> <out> [--dump]
class FixFieldIdx {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: fixfieldidx <src> <dst> <out> [--dump]"); return; }
        var src = ModuleDefMD.Load(a[0]);
        var dst = ModuleDefMD.Load(a[1]);
        bool dump = a.Any(x => x == "--dump");

        // 建: 源类型 FullName -> 源字段名 -> 索引
        var srcFieldIdx = new Dictionary<string, Dictionary<string, int>>();
        foreach (var t in src.GetTypes()) {
            var d = new Dictionary<string, int>();
            for (int i = 0; i < t.Fields.Count; i++) d[t.Fields[i].Name.String] = i;
            srcFieldIdx[t.FullName] = d;
        }

        int n = 0, miss = 0;
        foreach (var t in dst.GetTypes()) {
            if (!t.HasFields) continue;
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    if (!(ins.Operand is IField f)) continue;
                    // 已经是本模块 FieldDef 且属于某个类型 -> 检查名字是否存在
                    var dtName = f.DeclaringType == null ? null : f.DeclaringType.FullName;
                    if (dtName == null) continue;
                    var dstT = dst.Find(dtName, false);
                    if (dstT == null) continue;
                    if (dstT.Fields.Any(x => x.Name.String == f.Name.String)) continue;
                    // 目标类型里没有这个字段名 -> 按源索引回退
                    if (!srcFieldIdx.TryGetValue(dtName, out var map)) { miss++; continue; }
                    if (!map.TryGetValue(f.Name.String, out int idx)) { miss++; continue; }
                    if (idx >= dstT.Fields.Count) { miss++; continue; }
                    var target = dstT.Fields[idx];
                    if (dump) Console.WriteLine("[fix] " + dtName + "::" + f.Name + " (idx " + idx + ") -> " + target.Name);
                    ins.Operand = target;
                    n++;
                }
            }
        }
        Console.WriteLine("[fixfieldidx] fixed=" + n + " miss=" + miss);
        var wopt = new ModuleWriterOptions(dst);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        dst.Write(a[2], wopt);
        Console.WriteLine("[out] " + a[2]);
    }
}
