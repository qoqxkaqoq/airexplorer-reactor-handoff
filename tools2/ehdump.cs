using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// ehdump: 打印方法的 EH 子句(catch 类型/范围偏移), 用来查"catch 为什么不生效"
// 用法: ehdump <file> <typeSubstr> [methodSubstr]
class EhDump {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            if (t.FullName.IndexOf(a[1], StringComparison.Ordinal) < 0) continue;
            foreach (var m in t.Methods) {
                if (a.Length > 2 && m.Name.IndexOf(a[2], StringComparison.Ordinal) < 0) continue;
                if (!m.HasBody || m.Body.ExceptionHandlers.Count == 0) continue;
                Console.WriteLine("### " + t.FullName + "::" + m.Name + "  insn=" + m.Body.Instructions.Count);
                foreach (var eh in m.Body.ExceptionHandlers) {
                    Console.WriteLine("  " + eh.HandlerType
                        + "  try " + Off(m, eh.TryStart) + "-" + Off(m, eh.TryEnd)
                        + "  handler " + Off(m, eh.HandlerStart) + "-" + Off(m, eh.HandlerEnd)
                        + (eh.CatchType == null ? "" : ("  catch=" + eh.CatchType.FullName))
                        + (eh.FilterStart == null ? "" : ("  filter=" + Off(m, eh.FilterStart))));
                }
            }
        }
    }
    static string Off(MethodDef m, Instruction i) {
        if (i == null) return "end";
        int idx = m.Body.Instructions.IndexOf(i);
        return idx < 0 ? "?" : ("IL_" + i.Offset.ToString("X4") + "[#" + idx + "]");
    }
}
