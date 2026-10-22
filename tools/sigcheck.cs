using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class SigCheck {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            if (t.FullName != "CloudClient.Templating.DispatcherInitializer" && t.FullName != "CloudClient.Templating.TemplateArgument") continue;
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                if (m.Name.String != "SearchStrategy" && m.Name.String != "InstantiateAccessibleProcessor" && m.Name.String != "InstantiateStatelessUser") continue;
                Console.WriteLine("=== " + t.Name + "::" + m.Name + " | 声明sig: " + m.MethodSig);
                foreach (var ins in m.Body.Instructions) {
                    var im = ins.Operand as IMethod;
                    if (im == null || ins.OpCode != OpCodes.Call && ins.OpCode != OpCodes.Callvirt) continue;
                    var full = (im.DeclaringType == null ? "?" : im.DeclaringType.FullName) + "::" + im.Name;
                    if (!full.Contains("InstantiateAccessibleProcessor") && !full.Contains("InstantiateStatelessUser")) continue;
                    Console.WriteLine("  call " + full);
                    Console.WriteLine("    操作数sig: " + im.MethodSig);
                    var md = im.ResolveMethodDef();
                    Console.WriteLine("    解析: " + (md == null ? "失败(null!)" : md.MethodSig + " 声明类型=" + md.DeclaringType.FullName));
                    if (md != null && md.MethodSig != null && im.MethodSig != null) {
                        bool same = im.MethodSig.ToString() == md.MethodSig.ToString();
                        Console.WriteLine("    sig一致: " + same);
                    }
                }
            }
        }
        return 0;
    }
}
