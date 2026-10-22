using System;using System.Linq;using dnlib.DotNet;using dnlib.DotNet.Emit;using dnlib.DotNet.Writer;
// initfield: 把 DetachedCalculator..ctor 从 nop 桩改成真体, 初始化 m_ProjectDecorators
// 根因: m_ProjectDecorators 的唯一写入点在 InstantiateStatelessUser IL_045E(解释器状态机),
//       UI 启动路径没跑到 -> 字段为 null -> GenerateAdaptableExtractor 里 ANE。
//       在构造函数里给个空 List, 从根上保证它永不为 null。
// 用法: initfield <in> <out>
class InitField{
 static void Main(string[] a){
  if(a.Length<2){Console.WriteLine("usage: initfield <in> <out>");return;}
  var mod=ModuleDefMD.Load(a[0]);
  var dt=mod.Find("CloudClient.Templating.TemplateArgument/DetachedCalculator",false);
  if(dt==null){Console.WriteLine("[err] type missing");return;}
  var ctor=dt.Methods.FirstOrDefault(m=>m.Name==".ctor"&&m.MethodSig!=null&&m.MethodSig.Params.Count==0);
  var fld=dt.Fields.FirstOrDefault(f=>f.Name=="m_ProjectDecorators");
  if(ctor==null||fld==null){Console.WriteLine("[err] ctor/field missing");return;}
  // List<DistributorProfile>::.ctor()
  IMethod listCtor=null;
  foreach(var t in mod.GetTypes())foreach(var m in t.Methods){
   if(!m.HasBody)continue;
   foreach(var ins in m.Body.Instructions)
    if(ins.OpCode.Code==Code.Newobj&&ins.Operand is IMethod im
       &&im.FullName.Contains("List`1<")&&im.FullName.Contains("DistributorProfile")
       &&im.FullName.Contains(".ctor()")){listCtor=im;break;}
   if(listCtor!=null)break;
  }
  if(listCtor==null){Console.WriteLine("[err] List ctor not found");return;}
  Console.WriteLine("[initfield] List ctor = "+listCtor.FullName+" [tok 0x"+listCtor.MDToken.Raw.ToString("X8")+"]");
  var body=new CilBody();
  body.MaxStack=8;body.InitLocals=false;
  body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
  body.Instructions.Add(Instruction.Create(OpCodes.Newobj,listCtor));
  body.Instructions.Add(Instruction.Create(OpCodes.Stfld,fld));
  body.Instructions.Add(Instruction.Create(OpCodes.Ret));
  ctor.Body=body;
  Console.WriteLine("[initfield] DetachedCalculator..ctor -> " + body.Instructions.Count + " insn");
  var wopt=new ModuleWriterOptions(mod);
  wopt.MetadataOptions.Flags|=MetadataFlags.PreserveAll|MetadataFlags.KeepOldMaxStack;
  mod.Write(a[1],wopt);
  Console.WriteLine("[out] "+a[1]);
 }}
