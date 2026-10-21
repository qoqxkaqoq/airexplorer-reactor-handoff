using System;
using dnlib.DotNet;

class MsVer2 {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            if (t.FullName == "CloudClient.Templating.DispatcherInitializer" || t.FullName == "CloudClient.Models.StatelessModel") {
                foreach (var m in t.Methods) {
                    if ((m.Name.String == "DefineEfficientProfiler" || m.Name.String == "SearchAdapter") && m.HasBody)
                        Console.WriteLine(t.Name + "::" + m.Name + " maxstack=" + m.Body.MaxStack);
                }
            }
        }
        return 0;
    }
}
