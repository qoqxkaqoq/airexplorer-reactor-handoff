using System;
using System.Linq;
using dnlib.DotNet;

class Locs {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var t = mod.Find(a[1], false);
        var m = t.FindMethod(a[2]);
        Console.WriteLine(a[0] + " :: " + t.FullName + "::" + m.Name + " instr=" + (m.HasBody ? m.Body.Instructions.Count : -1));
        if (!m.HasBody) return;
        Console.WriteLine("maxstack=" + m.Body.MaxStack + " locals=" + m.Body.Variables.Count + " initlocals=" + m.Body.InitLocals);
        for (int i = 0; i < m.Body.Variables.Count; i++) {
            var v = m.Body.Variables[i];
            Console.WriteLine(string.Format("  L{0,-4} type={1,-32} etype={2}", i, v.Type.FullName, v.Type.ElementType));
        }
    }
}
