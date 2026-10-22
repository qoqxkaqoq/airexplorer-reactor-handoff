using System;
using System.Linq;
using dnlib.DotNet;
class MProps {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            if (t.FullName.IndexOf(a[1], StringComparison.Ordinal) < 0) continue;
            foreach (var m in t.Methods) {
                if (a.Length > 2 && m.Name.IndexOf(a[2], StringComparison.Ordinal) < 0) continue;
                Console.WriteLine(t.FullName + "::" + m.Name + "  implFlags=" + m.ImplAttributes
                    + " (0x" + ((int)m.ImplAttributes).ToString("X") + ")  attrs=0x" + ((int)m.Attributes).ToString("X")
                    + "  rva=0x" + m.RVA.ToString("X") + " body=" + m.HasBody);
            }
        }
    }
}
