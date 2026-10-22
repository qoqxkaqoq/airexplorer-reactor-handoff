using System;
using System.Linq;
using dnlib.DotNet;
class TypeList {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes().OrderBy(x => x.FullName)) {
            var ms = t.Methods.Where(m => m.HasBody).ToList();
            if (ms.Count == 0) continue;
            Console.WriteLine(string.Format("{0}  [{1} methods, {2} instrs]",
                t.FullName, ms.Count, ms.Sum(m => m.Body.Instructions.Count)));
            foreach (var m in ms.OrderByDescending(m => m.Body.Instructions.Count).Take(6))
                Console.WriteLine(string.Format("    {0}  ({1})", m.Name, m.Body.Instructions.Count));
        }
    }
}
