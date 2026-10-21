using System;
using dnlib.DotNet;

class FwChk {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        Console.WriteLine("RuntimeVersion: " + mod.RuntimeVersion);
        foreach (var ar in mod.GetAssemblyRefs())
            Console.WriteLine("AssemblyRef: " + ar.FullName);
        return 0;
    }
}
