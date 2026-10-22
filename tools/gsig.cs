using System;using System.Linq;
using dnlib.DotNet;

class GSig {
    static int Main(string[] a) {
        foreach (var path in a) {
            var mod = ModuleDefMD.Load(path);
            foreach (var t in mod.GetTypes())
                if (t.FullName == "CloudClient.Templating.TemplateArgument")
                    foreach (var m in t.Methods)
                        if (m.Name.String == "InstantiateStatelessUser") {
                            var gp = m.GenericParameters.Count > 0 ? m.GenericParameters[0] : null;
                            Console.WriteLine("=== " + System.IO.Path.GetFileName(path));
                            Console.WriteLine("  sig=" + m.MethodSig);
                            Console.WriteLine("  GP=" + (gp == null ? "无" : gp.Name));
                            Console.WriteLine("  attrs=" + m.Attributes + " impl=" + m.ImplAttributes);
                        }
        }
        return 0;
    }
}
