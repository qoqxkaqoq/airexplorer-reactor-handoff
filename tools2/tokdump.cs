// tokdump.cs — 打印指定方法里每条指令的操作数类型与其真实元数据 token
// 用法: tokdump <file.exe> <TypeFullName> <MethodName>
using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;

class TokDump {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string tn = a[1], mn = a[2];
        foreach (var t in mod.GetTypes()) {
            if (t.FullName != tn) continue;
            foreach (var m in t.Methods) {
                if (m.Name.String != mn) continue;
                Console.WriteLine("=== " + tn + "::" + mn + "  il=" + (m.HasBody ? m.Body.Instructions.Count : 0) +
                                  "  自身token=0x" + m.MDToken.Raw.ToString("X8") + "  rva=0x" + m.RVA.ToString("X"));
                if (!m.HasBody) continue;
                Console.WriteLine("  maxstack=" + m.Body.MaxStack + " locals=" + m.Body.Variables.Count);
                foreach (var ins in m.Body.Instructions) {
                    string tok = "-";
                    var op = ins.Operand;
                    if (op is IMDTokenProvider p) tok = "0x" + p.MDToken.Raw.ToString("X8") + " (" + op.GetType().Name + ")";
                    else if (op != null) tok = op.GetType().Name;
                    Console.WriteLine(string.Format("    {0:X4}  {1,-12} {2}   {3}",
                        ins.Offset, ins.OpCode.Name, tok, SafeStr(op)));
                }
                return;
            }
        }
        Console.WriteLine("未找到 " + tn + "::" + mn);
    }

    static string SafeStr(object op) {
        try { return op == null ? "" : op.ToString(); } catch { return "?"; }
    }
}
