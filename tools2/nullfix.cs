using System;using System.Linq;using dnlib.DotNet;using dnlib.DotNet.Emit;using dnlib.DotNet.Writer;
// nullfix: 把方法里 "ldnull; ret" 换成 "newobj <同返回类型的列表>; ret"
// 现象: InstantiateConfigurableModule 在 _TemplateConfig.m_ProjectDecorators == null 时
//       直接 return null, 调用方 AddRange(null) -> ArgumentNullException -> 主窗口弹
//       "Error detected" 后崩溃。UI 启动时解释器状态机没走到 IL_045E 那个写入点。
// 用法: nullfix <in> <out> <typeSubstr> <methodSubstr>
class NullFix{
 static void Main(string[] a){
  if(a.Length<4){Console.WriteLine("usage: nullfix <in> <out> <typeSubstr> <methodSubstr>");return;}
  var mod=ModuleDefMD.Load(a[0]);int n=0;
  foreach(var t in mod.GetTypes()){
   if(t.FullName.IndexOf(a[2],StringComparison.Ordinal)<0)continue;
   foreach(var m in t.Methods){
    if(m.Name.String.IndexOf(a[3],StringComparison.Ordinal)<0||!m.HasBody)continue;
    var ins=m.Body.Instructions;
    // 方法里已有的 "newobj 列表" 作为模板
    IMethod ctor=null;
    foreach(var i in ins) if(i.OpCode.Code==Code.Newobj&&i.Operand is IMethod im){ctor=im;break;}
    if(ctor==null){Console.WriteLine("[skip] "+m.Name+" 无 newobj 模板");continue;}
    for(int k=0;k<ins.Count-1;k++){
     if(ins[k].OpCode.Code!=Code.Ldnull)continue;
     if(ins[k+1].OpCode.Code!=Code.Ret)continue;
     Console.WriteLine("[fix] "+t.FullName+"::"+m.Name+"  IL_"+ins[k].Offset.ToString("X4")+"  ldnull -> newobj "+ctor.FullName);
     ins[k].OpCode=OpCodes.Newobj;ins[k].Operand=ctor;n++;
    }
   }
  }
  Console.WriteLine("[nullfix] replaced="+n);
  if(n==0)return;
  var wopt=new ModuleWriterOptions(mod);
  wopt.MetadataOptions.Flags|=MetadataFlags.PreserveAll|MetadataFlags.KeepOldMaxStack;
  mod.Write(a[1],wopt);
  Console.WriteLine("[out] "+a[1]);
 }}
