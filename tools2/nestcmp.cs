using System;
using System.Linq;
using dnlib.DotNet;
class NC { static void Main(string[] a) {
  var o = ModuleDefMD.Load(a[0]).Find(a[2], false);
  var c = ModuleDefMD.Load(a[1]).Find(a[2], false);
  var on = o.NestedTypes.ToList(); var cn = c.NestedTypes.ToList();
  Console.WriteLine(a[2] + "  official=" + on.Count + "  cilantro=" + cn.Count);
  int n = Math.Min(on.Count, cn.Count);
  for (int i = 0; i < n; i++) {
    var of = string.Join(",", on[i].Fields.Select(f => f.Name.String).Take(3));
    var cf = string.Join(",", cn[i].Fields.Select(f => f.Name.String).Take(3));
    Console.WriteLine(string.Format("  [{0}] {1,-32} | {2,-24}  OF=({3})  CF=({4})", i, on[i].Name, cn[i].Name, of, cf));
  }
} }
