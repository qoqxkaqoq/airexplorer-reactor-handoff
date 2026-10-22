using System;
using System.Linq;
using dnlib.DotNet;
class FldProps {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            if (t.FullName.IndexOf(a[1], StringComparison.Ordinal) < 0) continue;
            foreach (var f in t.Fields) {
                if (a.Length > 2 && f.Name.IndexOf(a[2], StringComparison.Ordinal) < 0) continue;
                Console.WriteLine(t.FullName + "::" + f.Name + "  type=" + f.FieldType.TypeName
                    + "  static=" + f.IsStatic + " initonly=" + f.IsInitOnly + " literal=" + f.IsLiteral
                    + " rva=0x" + f.RVA.ToString("X") + " attrs=0x" + ((int)f.Attributes).ToString("X"));
            }
        }
    }
}
