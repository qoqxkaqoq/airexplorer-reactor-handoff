using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class IlChk {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            if (t.FullName != "CloudClient.Templating.DispatcherInitializer") continue;
            foreach (var m in t.Methods) {
                if (m.Name.String != "DefineEfficientProfiler" || !m.HasBody) continue;
                var b = m.Body;
                Console.WriteLine("指令=" + b.Instructions.Count + " locals=" + b.Variables.Count + " EH=" + b.ExceptionHandlers.Count + " maxstack=" + b.MaxStack);
                // 1) 分支目标越界?
                var set = new System.Collections.Generic.HashSet<Instruction>(b.Instructions);
                int bad = 0;
                foreach (var ins in b.Instructions) {
                    if (ins.Operand is Instruction ti && !set.Contains(ti)) { bad++; if (bad < 4) Console.WriteLine("  分支目标丢失 @" + ins.Offset); }
                    if (ins.Operand is Instruction[] tas) foreach (var x in tas) if (!set.Contains(x)) { bad++; if (bad < 6) Console.WriteLine("  switch 目标丢失 @" + ins.Offset); }
                }
                Console.WriteLine("越界分支: " + bad);
                // 2) EH 边界?
                int ebad = 0;
                foreach (var eh in b.ExceptionHandlers) {
                    if (eh.TryStart == null || eh.TryEnd == null || !set.Contains(eh.TryStart) || !set.Contains(eh.TryEnd)) { ebad++; Console.WriteLine("  EH Try 边界异常: " + eh.TryStart?.Offset + "-" + eh.TryEnd?.Offset); }
                    if (eh.HandlerStart != null && !set.Contains(eh.HandlerStart)) { ebad++; Console.WriteLine("  EH Handler 越界"); }
                }
                Console.WriteLine("EH 异常: " + ebad);
                // 3) locals 索引越界?
                int lbad = 0;
                foreach (var ins in b.Instructions) {
                    if (ins.GetLocal(b.Variables) == null && (ins.OpCode.Code == Code.Ldloc || ins.OpCode.Code == Code.Stloc || ins.OpCode.Code == Code.Ldloca)) { lbad++; if (lbad < 4) Console.WriteLine("  local 越界 @" + ins.Offset + " " + ins.OpCode + " " + ins.Operand); }
                }
                Console.WriteLine("local 越界: " + lbad);
                // 4) 指令 offset 单调?
                bool mono = true;
                for (int i = 1; i < b.Instructions.Count; i++) if (b.Instructions[i].Offset <= b.Instructions[i-1].Offset) { mono = false; break; }
                Console.WriteLine("offset 单调: " + mono);
            }
        }
        return 0;
    }
}
