using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class CountCall {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string needle = a[1];
        int n = 0;
        var callers = new List<string>();
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                bool hit = false;
                foreach (var ins in m.Body.Instructions) {
                    if ((ins.OpCode.Code == Code.Call || ins.OpCode.Code == Code.Callvirt) && ins.Operand != null
                        && ins.Operand.ToString().Contains(needle)) { hit = true; break; }
                }
                if (hit) { n++; if (callers.Count < 8) callers.Add(m.MDToken.Raw.ToString("X8") + " " + t.FullName + "::" + m.Name); }
            }
        }
        Console.WriteLine("[countcall] " + needle + " 被调用方法数 = " + n);
        foreach (var c in callers) Console.WriteLine("  " + c);
    }
}
