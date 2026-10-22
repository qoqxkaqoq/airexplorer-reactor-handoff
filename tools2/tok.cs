using System;using System.Linq;using dnlib.DotNet;
class T{static void Main(string[] a){var m=ModuleDefMD.Load(a[0]);
foreach(var t in m.GetTypes()) if(t.FullName.Contains(a[1]))
foreach(var x in t.Methods) if(x.Name.String==a[2])
Console.WriteLine(t.FullName+"::"+x.Name+"  0x"+x.MDToken.Raw.ToString("X8")+"  rva=0x"+x.RVA.ToString("X"));}}
