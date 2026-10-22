using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class DiagRef {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            if (t.FullName != "CloudClient.Templating.DispatcherInitializer") continue;
            foreach (var m in t.Methods) {
                if (m.Name.String != "SearchStrategy" || !m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    var mr = ins.Operand as MemberRef;
                    if (mr == null || !mr.Name.String.Contains("InstantiateAccessibleProcessor")) continue;
                    Console.WriteLine("operand: " + ins.OpCode + " " + mr.Name);
                    Console.WriteLine("  Class 类型: " + mr.Class.GetType().Name);
                    var tr = mr.Class as TypeRef;
                    if (tr != null) {
                        Console.WriteLine("  FullName: " + tr.FullName);
                        Console.WriteLine("  Scope: " + (tr.ResolutionScope == null ? "null" : tr.ResolutionScope.GetType().Name + " " + tr.ResolutionScope));
                    }
                    Console.WriteLine("  sig: " + mr.MethodSig);
                }
            }
        }
        return 0;
    }
}
