using System;using System.Linq;using dnlib.DotNet;using dnlib.DotNet.Emit;using dnlib.DotNet.Writer;
// preinit: 在指定 ctor 的基类调用之后, 无条件插入 "ldarg.0; newobj T; stfld F"。
// 用途: 控制流平坦化的状态机里, 字段写入分支排在读取分支之后, UI 路径先读后写 -> NRE。
//       在构造函数开头预初始化, 保证任何路径下字段非 null。
// 用法: preinit <in> <out> <declType> <ctorParamCount> <fieldName> <initTypeFullName>
class PreInit{
 static void Main(string[] a){
  if(a.Length<6){Console.WriteLine("usage: preinit <in> <out> <declType> <paramCount> <field> <initType>");return;}
  var mod=ModuleDefMD.Load(a[0]);
  int pc=int.Parse(a[3]);
  var t=mod.GetTypes().FirstOrDefault(x=>x.FullName==a[2]);
  if(t==null){Console.WriteLine("[err] type missing "+a[2]);return;}
  var ctor=t.Methods.FirstOrDefault(m=>m.Name==".ctor"&&m.MethodSig!=null&&m.MethodSig.Params.Count==pc);
  var fld=t.Fields.FirstOrDefault(f=>f.Name==a[4]);
  var it=mod.Find(a[5],false);
  var itCtor=it==null?null:it.Methods.FirstOrDefault(m=>m.Name==".ctor"&&m.MethodSig!=null&&m.MethodSig.Params.Count==0);
  Console.WriteLine("[diag] ctor="+(ctor!=null)+" fld="+(fld!=null)+" it="+(it!=null)+" itCtor="+(itCtor!=null));
  if(ctor==null||fld==null||itCtor==null){
    if(it!=null) foreach(var m in it.Methods) if(m.Name==".ctor") Console.WriteLine("  itCtor候选: 参数="+m.MethodSig.Params.Count);
    if(t!=null) foreach(var m in t.Methods) if(m.Name==".ctor") Console.WriteLine("  dstCtor候选: 参数="+m.MethodSig.Params.Count);
    return;}
  var ins=ctor.Body.Instructions;
  int idx=-1;
  for(int i=0;i<ins.Count;i++){
   if(ins[i].OpCode.Code==Code.Call&&ins[i].Operand is IMethod im&&im.Name==".ctor"
      &&im.DeclaringType!=null&&im.DeclaringType.FullName.StartsWith("System.Windows.Forms.")){idx=i;break;}
  }
  if(idx<0){Console.WriteLine("[err] base ctor call not found");return;}
  ins.Insert(idx+1,Instruction.Create(OpCodes.Stfld,fld));
  ins.Insert(idx+1,Instruction.Create(OpCodes.Newobj,itCtor));
  ins.Insert(idx+1,Instruction.Create(OpCodes.Ldarg_0));
  Console.WriteLine("[preinit] "+t.FullName+"::"+ctor.Name+"  base@IL_"+ins[idx].Offset.ToString("X4")+"  插入 "+a[4]+" = new "+a[5]+"()");
  var wopt=new ModuleWriterOptions(mod);
  wopt.MetadataOptions.Flags|=MetadataFlags.PreserveAll|MetadataFlags.KeepOldMaxStack;
  mod.Write(a[1],wopt);
  Console.WriteLine("[out] "+a[1]);
 }}
