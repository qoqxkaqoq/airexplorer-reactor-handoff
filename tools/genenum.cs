using System;
using System.Linq;
using dnlib.DotNet;

class GenEnum {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var gens = mod.Types.Where(t => t.Name.String.StartsWith("GeneratedEnum")).ToList();
        Console.WriteLine("[gen] GeneratedEnum* 类型数: " + gens.Count);
        foreach (var t in gens.Take(8)) {
            Console.WriteLine("[gen] " + t.FullName + " | 基类=" + (t.BaseType == null ? "null" : t.BaseType.FullName) +
                " | 字段=" + t.Fields.Count + " 方法=" + t.Methods.Count + " 嵌套=" + t.NestedTypes.Count);
        }
        // dst (参数2) 里有几个?
        if (a.Length > 1) {
            var dst = ModuleDefMD.Load(a[1]);
            var dgs = dst.Types.Where(t => t.Name.String.StartsWith("GeneratedEnum")).ToList();
            Console.WriteLine("[dst] GeneratedEnum* 类型数: " + dgs.Count);
            var miss = gens.Count(g => dst.Find(g.FullName, false) == null);
            Console.WriteLine("[dst] 缺失: " + miss + "/" + gens.Count);
        }
        return 0;
    }
}
