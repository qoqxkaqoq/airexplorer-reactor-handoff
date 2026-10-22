using System;
using System.Linq;
using dnlib.DotNet;
class SB { static void Main(string[] a) {
  var mod = ModuleDefMD.Load(a[0]);
  foreach (var t in mod.GetTypes().OrderBy(x=>x.FullName)) {
    var stubs = t.Methods.Where(m => m.HasBody && m.Body.Instructions.Count <= 4).ToList();
    if (stubs.Count == 0) continue;
    Console.WriteLine(t.FullName + "  stubs=" + stubs.Count);
    foreach (var m in stubs.Take(4)) Console.WriteLine("    " + m.Name);
  }
} }
