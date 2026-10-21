using System;
using System.Linq;
using dnlib.DotNet;

class FindGen {
    static int Main(string[] a) {
        foreach (var path in a) {
            var mod = ModuleDefMD.Load(path);
            var all = mod.GetTypes().ToList();
            var gens = all.Where(t => t.Name.String.StartsWith("Generated")).ToList();
            var t0425 = all.Where(t => t.Name.String.Contains("0425")).ToList();
            Console.WriteLine("=== " + path.Split('/').Last() + " | 类型总数 " + all.Count + " | GeneratedEnum* " + gens.Count + " | 含0425 " + t0425.Count);
            foreach (var t in gens.Take(30)) Console.WriteLine("  " + t.FullName + " (嵌套于" + (t.DeclaringType == null ? "无" : t.DeclaringType.FullName) + ")");
            foreach (var t in t0425.Take(3)) Console.WriteLine("  [0425] " + t.FullName);
        }
        return 0;
    }
}
