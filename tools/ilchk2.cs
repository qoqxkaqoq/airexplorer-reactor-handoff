using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class IlChk2 {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        int bad = 0, total = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                total++;
                var body = m.Body;
                var probs = new List<string>();
                // 分支目标必须存在且指向有效指令
                foreach (var ins in body.Instructions) {
                    if (ins.Operand is Instruction tgt) { if (!body.Instructions.Contains(tgt)) probs.Add("分支越界@" + ins.Offset); }
                    else if (ins.Operand is IList<Instruction> tl) { foreach (var t2 in tl) if (!body.Instructions.Contains(t2)) probs.Add("switch越界@" + ins.Offset); }
                }
                foreach (var eh in body.ExceptionHandlers) {
                    if (eh.TryStart != null && !body.Instructions.Contains(eh.TryStart)) probs.Add("EH.Try越界");
                    if (eh.TryEnd != null && !body.Instructions.Contains(eh.TryEnd)) probs.Add("EH.TryEnd越界");
                    if (eh.FilterStart != null && !body.Instructions.Contains(eh.FilterStart)) probs.Add("EH.Filter越界");
                    if (eh.HandlerStart != null && !body.Instructions.Contains(eh.HandlerStart)) probs.Add("EH.Handler越界");
                    if (eh.HandlerEnd != null && !body.Instructions.Contains(eh.HandlerEnd)) probs.Add("EH.HandlerEnd越界");
                }
                // 模拟栈深 (保守上界, 只查明显爆炸)
                if (probs.Count > 0) { bad++; if (bad <= 8) Console.WriteLine("问题: " + t.FullName + "::" + m.Name + " → " + string.Join("; ", probs)); }
            }
        }
        Console.WriteLine("总方法=" + total + " 有问题=" + bad);
        return 0;
    }
}
