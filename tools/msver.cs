using System;
using dnlib.DotNet;

class MsVer {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            if (t.FullName != "CloudClient.Templating.DispatcherInitializer") continue;
            foreach (var m in t.Methods) {
                if (m.Name.String == "DefineEfficientProfiler" && m.HasBody)
                    Console.WriteLine("DefineEfficientProfiler maxstack=" + m.Body.MaxStack + " 指令=" + m.Body.Instructions.Count);
            }
        }
        return 0;
    }
}
