// dginject <in.exe> <out.exe> — 在 RequestWorker::.ctor 开头注入官方运行时实测的委托静态字段赋值
// 依据: dlgscan (prep.cs) 读官方进程: UpdateFunction->String::Concat, GetAnnotation->WebRequest::get_DefaultWebProxy,
//       ValidateCustomProvider->CredentialCache::get_DefaultCredentials (均为 BCL 方法, target=null)
// 引用纪律: 优先复用模块内既有 MemberRef; 否则用模块内既有 AssemblyRef(TypeRef) 构造 —
//           禁止 dnlib 跨运行时 Import(net8 typeof → System.Net.Requests 8.0.0.0 坏引用, net48 无法解析)
using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class DgInject {
    static ModuleDefMD mod;

    static void Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: dginject <in> <out>"); return; }
        mod = ModuleDefMD.Load(a[0]);
        var ag = mod.GetTypes().First(t => t.Name == "RequestWorker");
        var ctor = ag.FindMethod(".ctor");
        var body = ctor.Body;

        var plans = new[] {
            new { Dlg = "ParserValidator", Fld = "UpdateFunction", Meth = "Concat", Tn = "System.String", Asm = "mscorlib", Ret = "String" },
            new { Dlg = "ExtendedManagerValidator", Fld = "GetAnnotation", Meth = "get_DefaultWebProxy", Tn = "System.Net.WebRequest", Asm = "System", Ret = "IWebProxy" },
            new { Dlg = "ModelPredicate", Fld = "ValidateCustomProvider", Meth = "get_DefaultCredentials", Tn = "System.Net.CredentialCache", Asm = "System", Ret = "ICredentials" },
        };
        var ins = new System.Collections.Generic.List<Instruction>();
        foreach (var p in plans) {
            var dt = mod.GetTypes().FirstOrDefault(t => t.Name == p.Dlg);
            if (dt == null) { Console.WriteLine("[dginject] type missing " + p.Dlg); return; }
            var fld = dt.Fields.FirstOrDefault(f => f.Name == p.Fld && f.IsStatic);
            var dctor = dt.FindMethod(".ctor");
            if (fld == null || dctor == null) { Console.WriteLine("[dginject] member missing " + p.Dlg + "::" + p.Fld); return; }

            var mref = FindOrCreateMref(p.Meth, p.Tn, p.Asm, p.Ret);
            if (mref == null) { Console.WriteLine("[dginject] cannot build mref for " + p.Tn + "::" + p.Meth); return; }
            ins.Add(new Instruction(OpCodes.Ldnull));
            ins.Add(new Instruction(OpCodes.Ldftn, mref));
            ins.Add(new Instruction(OpCodes.Newobj, mod.Import(dctor)));
            ins.Add(new Instruction(OpCodes.Stsfld, mod.Import(fld)));
            Console.WriteLine("[dginject] " + p.Dlg + "::" + p.Fld + " = ldftn " + p.Tn + "::" + p.Meth + " (ref ok)");
        }
        // 插到最前(在 call DefineActiveEvent 之前 — 委托先于一切业务)
        for (int i = ins.Count - 1; i >= 0; i--) body.Instructions.Insert(0, ins[i]);

        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
        foreach (var t in mod.GetTypes()) foreach (var m in t.Methods) if (m.HasBody) m.Body.KeepOldMaxStack = true;
        mod.Write(a[1], opts);
        Console.WriteLine("[dginject] wrote " + a[1]);
    }

    // 优先既有 MemberRef, 其次构造(复用既有 AssemblyRef / TypeRef)
    static IMethod FindOrCreateMref(string methName, string typeFullName, string asmName, string retKind) {
        foreach (var mr in mod.GetMemberRefs()) {
            if (mr.IsMethodRef && mr.Name == methName && mr.Class != null && mr.Class.FullName == typeFullName) {
                Console.WriteLine("[dginject] reuse existing MemberRef " + typeFullName + "::" + methName);
                return mr;
            }
        }
        IResolutionScope scope = null;
        foreach (var ar in mod.GetAssemblyRefs()) if (ar.Name == asmName) { scope = ar; break; }
        if (scope == null) { Console.WriteLine("[dginject] no AssemblyRef " + asmName); return null; }
        TypeRef tr = null;
        foreach (var t2 in mod.GetTypeRefs()) if (t2.FullName == typeFullName && t2.ResolutionScope == scope) { tr = t2; break; }
        if (tr == null) tr = new TypeRefUser(mod, typeFullName.Substring(0, typeFullName.LastIndexOf('.')).Replace("System.Net", "System.Net"), typeFullName.Substring(typeFullName.LastIndexOf('.') + 1), scope);
        TypeSig ret;
        if (retKind == "String") ret = mod.CorLibTypes.String;
        else {
            TypeRef rtr = null;
            foreach (var t2 in mod.GetTypeRefs()) if (t2.FullName == "System.Net." + retKind) { rtr = t2; break; }
            if (rtr == null) { Console.WriteLine("[dginject] no TypeRef for return " + retKind); return null; }
            ret = new ClassSig(rtr);
        }
        return new MemberRefUser(mod, methName, MethodSig.CreateStatic(ret), tr);
    }
}
