using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;

// 列出无法解析的 TypeRef (移植带来的外部名), 按声明类型分组
class Unresolved {
    static void Main(string[] a) {
        var dir = Path.GetDirectoryName(Path.GetFullPath(a[0]));
        var res = new AssemblyResolver { EnableTypeDefCache = true };
        res.PostSearchPaths.Insert(0, dir); res.PreSearchPaths.Insert(0, dir);
        var ctx = new ModuleContext(res); res.DefaultModuleContext = ctx;
        var mod = ModuleDefMD.Load(a[0], ctx);

        var groups = new Dictionary<string, List<string>>();
        foreach (var tr in mod.GetTypeRefs()) {
            if (tr.ResolutionScope is AssemblyRef) continue;
            if (tr.Resolve() != null) continue;
            var key = tr.DeclaringType == null ? "(top)" : tr.DeclaringType.FullName;
            if (!groups.TryGetValue(key, out var l)) { l = new List<string>(); groups[key] = l; }
            l.Add(tr.Name.String);
        }
        int total = 0;
        foreach (var kv in groups.OrderByDescending(x => x.Value.Count)) {
            Console.WriteLine(kv.Key + "  -> " + kv.Value.Count + " 个: " + string.Join(",", kv.Value.Take(8)));
            total += kv.Value.Count;
        }
        Console.WriteLine("unresolved TypeRefs = " + total);
    }
}
