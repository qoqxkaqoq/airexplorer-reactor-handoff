using System;using System.Linq;using dnlib.DotNet;
class TT{static void Main(string[] a){var m=ModuleDefMD.Load(a[0]);
foreach(var t in m.GetTypes()) if(t.Name.String.Contains(a[1]))
Console.WriteLine(t.FullName+"  0x"+t.MDToken.Raw.ToString("X8")+"  fields="+t.Fields.Count+" methods="+t.Methods.Count+" base="+(t.BaseType==null?"-":t.BaseType.FullName));}}
