using System;using System.Linq;using dnlib.DotNet;using dnlib.DotNet.Emit;
// castscan <exe> <typeSubstr> : 找所有 castclass/isinst/unbox.any/callvirt 到该类型的指令
class CastScan{static void Main(string[] a){
var m=ModuleDefMD.Load(a[0]);int n=0;
foreach(var t in m.GetTypes())foreach(var md in t.Methods){
 if(!md.HasBody)continue;
 foreach(var ins in md.Body.Instructions){
  var c=ins.OpCode.Code;
  if(c!=Code.Castclass&&c!=Code.Isinst&&c!=Code.Unbox_Any&&c!=Code.Callvirt&&c!=Code.Call&&c!=Code.Newobj)continue;
  var ty=ins.Operand as ITypeDefOrRef ?? (ins.Operand as IMethod)?.DeclaringType;
  if(ty==null)continue;
  if(ty.FullName.IndexOf(a[1],StringComparison.Ordinal)<0)continue;
  Console.WriteLine(t.FullName+"::"+md.Name+"  IL_"+ins.Offset.ToString("X4")+"  "+ins.OpCode.Name+"  "+ty.FullName);n++;
 }}
Console.WriteLine("[castscan] hits="+n);}}
