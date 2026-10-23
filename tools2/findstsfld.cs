using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class FindStsfld {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string needle = a[1]; // 字段名片段
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    if ((ins.OpCode.Code == Code.Stsfld || ins.OpCode.Code == Code.Stfld) && ins.Operand != null
                        && ins.Operand.ToString().Contains(needle)) {
                        Console.WriteLine((ins.OpCode.Code == Code.Stsfld ? "stsfld" : "newobj ") + " @ " + m.MDToken.Raw.ToString("X8") + " " + t.FullName + "::" + m.Name + " instrs=" + m.Body.Instructions.Count);
                        break;
                    }
                }
            }
        }
    }
}
