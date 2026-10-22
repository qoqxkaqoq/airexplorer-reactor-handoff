using System;using System.Linq;using dnlib.DotNet;using dnlib.DotNet.Emit;using dnlib.DotNet.Writer;
// nosort: 把所有 callvirt List::Sort(Comparison<T>) 换成 "pop; pop"
// 现象: GenerateAdaptableExtractor IL_06D5 的 Sort 用的 comparison 是
//   ldftn 方法指针 + newobj Comparison::.ctor(Object,IntPtr) 造出来的, 栈上缺 target 对象,
//   委托 target 无效 -> Sort 抛 ArgumentNullException -> 主窗口弹 Error detected 后崩溃。
// 排序只影响 DistributorProfile 的顺序, 跳过不改变功能。
// 用法: nosort <in> <out> [typeSubstr]
class NoSort{
 static void Main(string[] a){
  if(a.Length<2){Console.WriteLine("usage: nosort <in> <out> [typeSubstr]");return;}
  var mod=ModuleDefMD.Load(a[0]);string flt=a.Length>2?a[2]:null;int n=0;
  foreach(var t in mod.GetTypes()){
   if(flt!=null&&t.FullName.IndexOf(flt,StringComparison.Ordinal)<0)continue;
   foreach(var m in t.Methods){
    if(!m.HasBody)continue;
    var ins=m.Body.Instructions;
    for(int k=0;k<ins.Count;k++){
     if(ins[k].OpCode.Code!=Code.Callvirt)continue;
     var im=ins[k].Operand as IMethod;
     if(im==null||im.Name.String!="Sort")continue;
     Console.WriteLine("[nosort] "+t.FullName+"::"+m.Name+"  IL_"+ins[k].Offset.ToString("X4")+"  "+im.FullName);
     ins[k].OpCode=OpCodes.Pop;ins[k].Operand=null;
     ins.Insert(k+1,Instruction.Create(OpCodes.Pop));
     n++;k++;
    }
   }
  }
  Console.WriteLine("[nosort] replaced="+n);
  if(n==0)return;
  var wopt=new ModuleWriterOptions(mod);
  wopt.MetadataOptions.Flags|=MetadataFlags.PreserveAll|MetadataFlags.KeepOldMaxStack;
  mod.Write(a[1],wopt);
  Console.WriteLine("[out] "+a[1]);
 }}
