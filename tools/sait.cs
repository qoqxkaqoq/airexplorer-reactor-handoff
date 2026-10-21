using System;
using dnlib.DotNet;

class Sait {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.Types) {
            if (t.Name.String.Contains("StaticArrayInit")) {
                Console.WriteLine("[SAIT] " + t.FullName + " layout=" + (t.ClassLayout != null ? t.ClassLayout.ClassSize.ToString() : "null"));
            }
        }
        Console.WriteLine("done");
        return 0;
    }
}
