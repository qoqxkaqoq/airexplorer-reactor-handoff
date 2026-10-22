using System;using System.Linq;using dnlib.DotNet;using dnlib.DotNet.Emit;using dnlib.DotNet.Writer;
// noopcast <in> <out> <typeSubstr> <methodName> <castTypeSubstr>
// 把方法里的 "castclass <castType>" 换成 nop —— 调用点紧接着的 callvirt 参数类型
// 本来就是基类(ConnectedObserver), cast 是 Reactor 加的混淆, 去掉后语义更正确。
class NoopCast{
 static void Main(string[] a){
  if(a.Length<5){Console.WriteLine("usage: noopcast <in> <out> <typeSubstr> <method> <castTypeSubstr>");return;}
  var mod=ModuleDefMD.Load(a[0]);int n=0;
  foreach(var t in mod.GetTypes()){
   if(t.FullName.IndexOf(a[2],StringComparison.Ordinal)<0)continue;
   foreach(var m in t.Methods){
    if(m.Name.String!=a[3]||!m.HasBody)continue;
    foreach(var ins in m.Body.Instructions){
     if(ins.OpCode.Code!=Code.Castclass)continue;
     var ty=ins.Operand as ITypeDefOrRef;
     if(ty==null||ty.FullName.IndexOf(a[4],StringComparison.Ordinal)<0)continue;
     Console.WriteLine("[noop] "+t.FullName+"::"+m.Name+"  IL_"+ins.Offset.ToString("X4")+"  castclass "+ty.FullName);
     ins.OpCode=OpCodes.Nop;ins.Operand=null;n++;
    }
   }
  }
  Console.WriteLine("[noopcast] replaced="+n);
  if(n==0)return;
  var wopt=new ModuleWriterOptions(mod);
  wopt.MetadataOptions.Flags|=MetadataFlags.PreserveAll|MetadataFlags.KeepOldMaxStack;
  mod.Write(a[1],wopt);
  Console.WriteLine("[out] "+a[1]);
 }}
