using System;
using System.Linq;
using dnlib.DotNet;
class TM { static void Main(string[] a) {
  var mod = ModuleDefMD.Load(a[0]);
  var t = mod.Find(a[1], false);
  if (t == null) { Console.WriteLine("type not found: " + a[1]); return; }
  Console.WriteLine(t.FullName + "  [" + t.Methods.Count + " methods, " + t.Fields.Count + " fields]");
  foreach (var f in t.Fields) Console.WriteLine("  F " + f.Name + " : " + f.FieldType.TypeName + (f.IsStatic ? " (static)" : ""));
  foreach (var m in t.Methods) Console.WriteLine("  M " + m.Name + "(" + string.Join(",", m.MethodSig == null ? new string[0] : m.MethodSig.Params.Select(p => p.TypeName).ToArray()) + ") : " + (m.MethodSig == null ? "?" : m.MethodSig.RetType.TypeName));
} }
