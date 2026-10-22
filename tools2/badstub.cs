using System;using System.IO;using System.Linq;using dnlib.DotNet;using dnlib.DotNet.Emit;
// badstub <exe> : 找出所有"必崩桩" —— ldnull 紧跟 unbox.any (对 null 做 unbox 必抛 NRE)。
// 输出: token  类型::方法  指令数
class BadStub{
 static void Main(string[] a){
  var mod=ModuleDefMD.Load(a[0]);int n=0;
  var outp=new System.Text.StringBuilder();
  foreach(var t in mod.GetTypes())foreach(var m in t.Methods){
   if(!m.HasBody)continue;
   var ins=m.Body.Instructions;
   for(int k=0;k+1<ins.Count;k++){
    if(ins[k].OpCode.Code!=Code.Ldnull)continue;
    if(ins[k+1].OpCode.Code!=Code.Unbox_Any)continue;
    Console.WriteLine("0x"+m.MDToken.Raw.ToString("X8")+"  "+t.FullName+"::"+m.Name+"  insn="+ins.Count);
    outp.AppendLine(m.MDToken.Raw.ToString("X8"));
    n++;
   }
  }
  Console.WriteLine("[badstub] 必崩桩="+n);
  if(n>0)File.WriteAllText("/tmp/badstub.txt",outp.ToString());
 }}
