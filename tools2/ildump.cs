using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// ildump: 按类型子串 + 方法子串 dump IL
// 用法: ildump <file> <typeSubstr> [methodSubstr]
class IlDump {
    static void Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: ildump <file> <typeSubstr> [methodSubstr]"); return; }
        var mod = ModuleDefMD.Load(a[0]);
        string ts = a[1];
        string ms = a.Length > 2 ? a[2] : null;
        int nt = 0;
        foreach (var t in mod.GetTypes()) {
            if (t.FullName.IndexOf(ts, StringComparison.Ordinal) < 0) continue;
            nt++;
            Console.WriteLine("### TYPE " + t.FullName + "  (fields=" + t.Fields.Count + ", methods=" + t.Methods.Count + ", gparams=" + t.GenericParameters.Count + ", base=" + (t.BaseType == null ? "null" : t.BaseType.FullName) + ")");
            foreach (var m in t.Methods) {
                if (ms != null && m.Name.String.IndexOf(ms, StringComparison.Ordinal) < 0) continue;
                Console.WriteLine("  --- " + Sig(m) + (m.HasBody ? "  [" + m.Body.Instructions.Count + " insn, maxstack=" + m.Body.MaxStack + "]" : "  [no body]"));
                if (!m.HasBody) continue;
                if (m.Body.Variables.Count > 0)
                    Console.WriteLine("    LOCALS(" + m.Body.Variables.Count + "): " + string.Join(" | ", m.Body.Variables.Select(v => v.Type.FullName)));
                foreach (var ins in m.Body.Instructions) {
                    Console.WriteLine("    " + ins.Offset.ToString("X4") + "  " + ins.OpCode.Name.PadRight(12) + Fmt(ins));
                }
                foreach (var eh in m.Body.ExceptionHandlers)
                    Console.WriteLine("    EH " + eh.HandlerType + " try " + eh.TryStart.Offset.ToString("X4") + "-" + eh.TryEnd.Offset.ToString("X4") + " h " + eh.HandlerStart.Offset.ToString("X4") + "-" + eh.HandlerEnd.Offset.ToString("X4"));
            }
        }
        if (nt == 0) Console.WriteLine("(no type matched)");
    }
    static string Sig(MethodDef m) {
        string s = (m.IsStatic ? "static " : "") + m.ReturnType.TypeName + " " + m.Name;
        if (m.HasGenericParameters) s += "<" + m.GenericParameters.Count + ">";
        s += "(" + string.Join(", ", m.Parameters.Select(p => p.Type.TypeName + " " + p.Name)) + ")";
        return s;
    }
    static string Fmt(Instruction ins) {
        var o = ins.Operand;
        if (o == null) return "";
        if (o is Instruction i) return "IL_" + i.Offset.ToString("X4");
        if (o is Instruction[] arr) return "[" + string.Join(",", arr.Select(x => "IL_" + x.Offset.ToString("X4"))) + "]";
        if (o is IMethod m) return m.FullName + "  [tok 0x" + m.MDToken.Raw.ToString("X8") + "]";
        if (o is IField f) return f.FullName + "  [tok 0x" + f.MDToken.Raw.ToString("X8") + "]";
        if (o is IType t) return t.FullName + "  [tok 0x" + t.MDToken.Raw.ToString("X8") + "]";
        if (o is string s) return "\"" + s.Replace("\n", "\\n") + "\"";
        return o.ToString();
    }
}
