using System;
using System.Linq;
using dnlib.DotNet;
class FN { static void Main(string[] a) {
  var mod = ModuleDefMD.Load(a[0]);
  var list = mod.GetTypes().Where(t => t.Name.String.StartsWith("GeneratedEnum_") || t.Name.String.StartsWith("GeneratedType_") || t.Name.String.StartsWith("GeneratedMethod_")).ToList();
  Console.WriteLine("fake types = " + list.Count);
  foreach (var t in list.Take(40)) {
    var flds = string.Join(",", t.Fields.Select(f => f.Name.String).Take(4));
    Console.WriteLine("  " + t.FullName + "  (fields: " + flds + ")");
  }
} }
