using System;
using dnlib.DotNet;

class TokOf {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            if (t.FullName != "CloudClient.Templating.DispatcherInitializer") continue;
            foreach (var m in t.Methods) {
                if (m.Name.String == "StopClient" || m.Name.String == "GenerateConfigurableSpec" || m.Name.String == "VerifyCombinedStateRequest" || m.Name.String == "ValidateGenericRunnerFilter")
                    Console.WriteLine(m.Name + " token=0x" + m.MDToken.Raw.ToString("X8") + " hasBody=" + m.HasBody);
            }
        }
        return 0;
    }
}
