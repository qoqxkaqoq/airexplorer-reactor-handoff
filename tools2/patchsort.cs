using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// patchsort: 跳过 InstantiateStatelessUser 里 "m_ProjectDecorators.Sort(<>9__47_0)" 那一段。
// 那段会触发编译器生成的 <>c 泛型缓存类 (URqFYq3xtmntT2OcLub`1) 的加载, 而我们的移植体
// 在 JIT 时报 TypeLoadException。排序只是让 DistributorProfile 列表有序, 跳过不影响功能正确性
// (最坏情况是模板参数顺序不同)。
//
// 做法: ldfld m_ProjectDecorators 之后到 callvirt Sort 之间的指令全部删掉, 换成一条 pop,
// 保持栈平衡 (list 被 pop 掉)。
//
// 用法: patchsort <in> <out> [--dump]
class PatchSort {
    static void Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: patchsort <in> <out> [--dump]"); return; }
        var mod = ModuleDefMD.Load(a[0]);
        bool dump = a.Any(x => x == "--dump");
        var t = mod.Find("CloudClient.Templating.TemplateArgument", false);
        if (t == null) { Console.WriteLine("[err] type missing"); return; }
        int total = 0;
        foreach (var m in t.Methods) {
            if (!m.HasBody || m.Body.Instructions.Count < 10) continue;
            var ins = m.Body.Instructions;
            bool changed = true;
            while (changed) {
                changed = false;
                int i0 = -1, i1 = -1;
                for (int i = 0; i < ins.Count; i++) {
                    if (ins[i].OpCode.Code == Code.Ldfld && ins[i].Operand is IField f && f.Name == "m_ProjectDecorators") { i0 = i; continue; }
                    if (i0 >= 0 && i >= i0 && ins[i].OpCode.Code == Code.Callvirt && ins[i].Operand is IMethod mm && mm.Name.String == "Sort") { i1 = i; break; }
                }
                if (i0 < 0 || i1 < 0 || i1 <= i0) break;
                if (dump) Console.WriteLine("[patch] " + m.Name + "  remove insn " + (i0 + 1) + ".." + i1 + " (" + (i1 - i0) + " 条)");
                for (int k = i1; k > i0; k--) ins.RemoveAt(k);
                ins.Insert(i0 + 1, Instruction.Create(OpCodes.Pop));
                total++;
                changed = true;
            }
        }
        Console.WriteLine("[patchsort] sites=" + total);
        if (total == 0) { Console.WriteLine("[warn] 没找到目标片段"); return; }
        var wopt = new ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], wopt);
        Console.WriteLine("[out] " + a[1] + " size=" + new FileInfo(a[1]).Length);
    }
}
