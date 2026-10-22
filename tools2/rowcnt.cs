using System;
using dnlib.DotNet;
using dnlib.DotNet.MD;
class RC { static void Main(string[] a) {
  var m = ModuleDefMD.Load(a[0]);
  var t = m.TablesStream;
  Console.WriteLine(System.IO.Path.GetFileName(a[0]) + ":");
  Console.WriteLine("  MethodDef=" + t.MethodTable.Rows);
  Console.WriteLine("  MemberRef=" + t.MemberRefTable.Rows);
  Console.WriteLine("  MethodSpec=" + t.MethodSpecTable.Rows);
  Console.WriteLine("  TypeRef=" + t.TypeRefTable.Rows);
  Console.WriteLine("  TypeSpec=" + t.TypeSpecTable.Rows);
  Console.WriteLine("  Field=" + t.FieldTable.Rows);
  Console.WriteLine("  StandAloneSig=" + t.StandAloneSigTable.Rows);
} }
