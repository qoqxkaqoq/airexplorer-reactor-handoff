using System;
using System.Linq;
using dnlib.DotNet;
class S { static void Main(string[] a) {
  var mod = ModuleDefMD.Load(a[0]);
  int n4=0, ntot=0;
  foreach (var t in mod.GetTypes()) foreach (var m in t.Methods) {
    if (!m.HasBody) continue; ntot++;
    if (m.Body.Instructions.Count <= 4) n4++;
  }
  Console.WriteLine("methods=" + ntot + "  <=4 instrs=" + n4);
} }
