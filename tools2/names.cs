using System;using System.IO;using System.Linq;using dnlib.DotNet;
// names <exe> <tokenlistfile>  -- 把 token 列表翻成 类型::方法(指令数)
class Names{static void Main(string[] a){
var m=ModuleDefMD.Load(a[0]);
foreach(var line in File.ReadAllLines(a[1])){
 var s=line.Trim(); if(s.Length==0) continue;
 uint tok=Convert.ToUInt32(s,16);
 var md=m.ResolveToken(tok) as MethodDef;
 if(md==null){Console.WriteLine("0x"+tok.ToString("X8")+"  <unresolved>");continue;}
 int n=md.HasBody?md.Body.Instructions.Count:-1;
 Console.WriteLine("0x"+tok.ToString("X8")+"  "+md.DeclaringType.FullName+"::"+md.Name+"  insn="+n
   +(md.HasGenericParameters?"  GENERIC("+md.GenericParameters.Count+")":""));
}}}
