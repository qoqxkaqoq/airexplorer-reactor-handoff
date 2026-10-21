using System;
using dnlib.DotNet;

class FldChk {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes())
            foreach (var f in t.Fields) {
                if (!f.Name.String.StartsWith("0E448EF5")) continue;
                Console.WriteLine("字段: " + t.Name + "::" + f.Name.Substring(0, 16) + "...");
                Console.WriteLine("  InitialValue=" + (f.InitialValue == null ? "null" : f.InitialValue.Length + " B") + " RVA=" + f.RVA);
            }
        return 0;
    }
}
