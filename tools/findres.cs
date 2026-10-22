// findres.cs — 找引用资源名的代码 + Properties.Resources 等价类
using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class FindRes {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string[] resNames = new string[] {
            "ErrorReceiver.ValidatorViewer", "ValidatorArgument.EmitterReporter",
            "ValidatorAllocator.ValidatorProc", "CollectorTransaction.ValidatorProject",
            "ValidatorGenerator.DefinitionError"
        };
        // 1) 谁引用了这些资源名 (ldstr)
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string s) {
                        foreach (var rn in resNames)
                            if (s == rn || s == rn.Replace('.', '_') || (s.Length > 0 && rn.StartsWith(s)))
                                Console.WriteLine("[use] " + t.FullName + "::" + m.Name + " → ldstr \"" + s + "\"");
                    }
                }
            }
        // 2) ResourceManager 相关类 (构造/属性)
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    var im = ins.Operand as IMethod;
                    if (im == null) continue;
                    var dn = im.DeclaringType == null ? "" : im.DeclaringType.FullName;
                    if (dn.Contains("ResourceManager") && (im.Name.String == ".ctor" || im.Name.String == "GetObject" || im.Name.String == "GetString"))
                        Console.WriteLine("[rm] " + t.FullName + "::" + m.Name + " → " + dn + "::" + im.Name);
                }
            }
        }
        return 0;
    }
}
