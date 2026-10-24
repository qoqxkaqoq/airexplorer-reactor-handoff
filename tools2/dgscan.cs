using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;

// dgscan — find types with the most static nonpublic fields (GetFields(1064) semantics)
class DgScan {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var rows = new List<(uint tok, int cnt, string name)>();
        foreach (var td in mod.GetTypes()) {
            int cnt = 0, del = 0;
            foreach (var f in td.Fields) if (f.IsStatic && !f.IsPublic) { cnt++; if (f.FieldType?.FullName?.Contains("Delegate") == true) del++; }
            if (cnt > 0) rows.Add((td.MDToken.Raw, cnt, td.FullName));
        }
        foreach (var r in rows.OrderByDescending(r => r.cnt).Take(10))
            Console.WriteLine($"{r.tok:X8} static-nonpub={r.cnt} {r.name}");
    }
}
