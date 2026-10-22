using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
class PairList {
    static void Main(string[] a) {
        var dst = ModuleDefMD.Load(a[0]);
        var src = ModuleDefMD.Load(a[1]);
        int minSrc = a.Length > 2 ? int.Parse(a[2]) : 10;
        var pairs = new List<string>();
        foreach (var t in dst.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody || m.Body.Instructions.Count > 4) continue;
                var sm = src.Find(t.FullName, false)?.Methods.FirstOrDefault(x => x.Name == m.Name && x.HasBody);
                if (sm == null) continue;
                if (sm.Body.Instructions.Count < minSrc) continue;
                pairs.Add(t.FullName + "\t" + m.Name.String + "\t" + sm.Body.Instructions.Count);
            }
        Console.WriteLine("pairs = " + pairs.Count);
        foreach (var p in pairs.Take(15)) Console.WriteLine("  " + p);
        System.IO.File.WriteAllLines(a[3], pairs.Select(p => p.Split('\t')[0] + "\t" + p.Split('\t')[1]));
    }
}
