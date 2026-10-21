using System;
using dnlib.DotNet;

class FType {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes())
            foreach (var f in t.Fields) {
                if (!f.Name.String.StartsWith("0E448EF5")) continue;
                var ts = f.FieldSig.Type;
                Console.WriteLine("sig 类型: " + ts.GetType().Name + " | FullName=" + ts.FullName + " | ElementType=" + ts.ElementType);
                Console.WriteLine("RVA=" + f.RVA + " InitialValue=" + (f.InitialValue == null ? "null" : f.InitialValue.Length + "B") + " 属性=" + f.Attributes);
            }
        return 0;
    }
}
