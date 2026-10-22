using System;
using System.Linq;
using dnlib.DotNet;
class FindField {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes())
            foreach (var f in t.Fields) {
                if (f.Name.String.IndexOf(a[1], StringComparison.Ordinal) < 0) continue;
                Console.WriteLine(t.FullName + " :: " + f.Name + " : " + f.FieldType.TypeName);
            }
    }
}
