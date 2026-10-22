using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class MaxChk {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            if (t.FullName != "CloudClient.Templating.DispatcherInitializer") continue;
            foreach (var m in t.Methods) {
                if (m.Name.String != "DefineEfficientProfiler") continue;
                Console.WriteLine("体存在=" + m.HasBody);
                if (!m.HasBody) return 0;
                var b = m.Body;
                Console.WriteLine("maxstack=" + b.MaxStack + " initLocals=" + b.InitLocals + " 指令=" + b.Instructions.Count + " locals=" + b.Variables.Count + " EH=" + b.ExceptionHandlers.Count);
                // eval stack 模拟
                int depth = 0, maxd = 0;
                foreach (var ins in b.Instructions) {
                    string op = ins.OpCode.Name;
                    if (op.StartsWith("ld") || op.StartsWith("call") && !op.Contains("void") || op.StartsWith("dup") || op.StartsWith("ld")) {
                        // 粗略
                    }
                    if (op.StartsWith("ld") || op == "dup" || op == "ldloca" || op == "ldarga" || op == "cgt" || op == "clt" || op == "ceq") { depth++; if (depth > maxd) maxd = depth; }
                    else if (op.StartsWith("st") || op == "pop" || op.StartsWith("br") || op == "ret" || op == "throw" || op.StartsWith("stelem") || op.StartsWith("stind")) depth = Math.Max(0, depth - 1);
                    else if (op.StartsWith("add") || op.StartsWith("sub") || op.StartsWith("mul") || op.StartsWith("div") || op.StartsWith("and") || op.StartsWith("or") || op.StartsWith("xor") || op.StartsWith("shl") || op.StartsWith("shr") || op.StartsWith("cmp")) depth = Math.Max(0, depth - 1);
                }
                Console.WriteLine("粗估栈深峰值=" + maxd + " 结束=" + depth);
            }
        }
        return 0;
    }
}
