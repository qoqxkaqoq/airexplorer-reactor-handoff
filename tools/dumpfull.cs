using System;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class DumpFull {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string tn = a[1], mn = a[2];
        foreach (var t in mod.GetTypes()) {
            if (t.FullName != tn) continue;
            foreach (var m in t.Methods) {
                if (m.Name.String != mn || !m.HasBody) continue;
                using (var w = new StreamWriter(a[3])) {
                    foreach (var ins in m.Body.Instructions)
                        w.WriteLine($"{ins.Offset:X4}|{ins.OpCode.Name}|{Fmt(ins)}");
                    // switch 表
                    foreach (var ins in m.Body.Instructions) {
                        if (ins.Operand is Instruction[] sw) {
                            w.WriteLine($"SWITCH@{ins.Offset:X4}|{string.Join(",", Array.ConvertAll(sw, x => x.Offset.ToString("X4")))}");
                        }
                    }
                    foreach (var eh in m.Body.ExceptionHandlers)
                        w.WriteLine($"EH|try={T(eh.TryStart)}-{T(eh.TryEnd)} handler={T(eh.HandlerStart)}-{T(eh.HandlerEnd)} filter={(eh.FilterStart==null?"-":T(eh.FilterStart))} type={eh.HandlerType}");
                }
                Console.WriteLine($"导出 {m.Body.Instructions.Count} 指令 → {a[3]}");
                return 0;
            }
        }
        Console.WriteLine("未找到"); return 1;
    }
    static string T(Instruction i) => i == null ? "-" : i.Offset.ToString("X4");
    static string Fmt(Instruction i) {
        if (i.Operand == null) return "";
        if (i.Operand is Instruction t) return "->" + t.Offset.ToString("X4");
        if (i.Operand is Instruction[] ta) return "[" + ta.Length + "目标]";
        return i.Operand.ToString();
    }
}
