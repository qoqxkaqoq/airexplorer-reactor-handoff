using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class Ldstr {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        int total = 0;
        var byMethod = new Dictionary<string,int>();
        var samples = new List<string>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    if (ins.OpCode.Code != Code.Ldstr) continue;
                    total++;
                    var s = ins.Operand as string ?? "";
                    if (samples.Count < 40) samples.Add(s);
                }
            }
        Console.WriteLine("ldstr total = " + total);
        Console.WriteLine("=== samples ===");
        foreach (var s in samples) Console.WriteLine("  [" + s + "]");

        // 每个方法调用其它"疑似解密"方法的情况
        Console.WriteLine("=== calls to ReportStatelessReporter-like (string)->string ===");
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    if (ins.OpCode.Code != Code.Call) continue;
                    if (ins.Operand is IMethod im && im.MethodSig != null && im.MethodSig.Params.Count == 1
                        && im.MethodSig.Params[0].TypeName == "String" && im.MethodSig.RetType.TypeName == "String")
                        Console.WriteLine("  " + m.Name + " -> " + im.FullName);
                }
            }
    }
}
