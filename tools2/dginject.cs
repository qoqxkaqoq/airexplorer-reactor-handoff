// dginject <in.exe> <out.exe> — 在 RequestWorker::.ctor 开头注入官方运行时实测的委托静态字段赋值
// 依据: dlgscan (prep.cs) 读官方进程: UpdateFunction->String::Concat, GetAnnotation->WebRequest::get_DefaultWebProxy,
//       ValidateCustomProvider->CredentialCache::get_DefaultCredentials (均为 BCL 方法, target=null)
// 模式: ldnull; ldftn <bcl>; newobj <DlgType>::.ctor(object,IntPtr); stsfld <fld>
using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class DgInject {
    static void Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: dginject <in> <out>"); return; }
        var mod = ModuleDefMD.Load(a[0]);
        var ag = mod.Find("AirExplorer.Networking.RequestWorker", true);
        var ctor = ag.FindMethod(".ctor");
        var body = ctor.Body;

        // 目标(类型全名, 字段名, BCL 方法)
        var plans = new[] {
            new { Dlg = "ParserValidator", Fld = "UpdateFunction", Bcl = "Concat" },
            new { Dlg = "ExtendedManagerValidator", Fld = "GetAnnotation", Bcl = "Proxy" },
            new { Dlg = "ModelPredicate", Fld = "ValidateCustomProvider", Bcl = "Cred" },
        };
        var ins = new System.Collections.Generic.List<Instruction>();
        foreach (var p in plans) {
            var dt = mod.GetTypes().FirstOrDefault(t => t.Name == p.Dlg);
            if (dt == null) { Console.WriteLine("[dginject] type missing " + p.Dlg); return; }
            var fld = dt.Fields.FirstOrDefault(f => f.Name == p.Fld && f.IsStatic);
            var dctor = dt.FindMethod(".ctor");
            if (fld == null || dctor == null) { Console.WriteLine("[dginject] member missing " + p.Dlg + "::" + p.Fld); return; }
            MethodDef bcl = null;
            System.Reflection.MethodBase rbcl = null;
            if (p.Bcl == "Concat")
                rbcl = typeof(string).GetMethods().FirstOrDefault(m => m.Name == "Concat" && m.GetParameters().Length == 2 && m.GetParameters()[0].ParameterType == typeof(string));
            else if (p.Bcl == "Proxy")
                rbcl = typeof(System.Net.WebRequest).GetProperty("DefaultWebProxy").GetGetMethod();
            else if (p.Bcl == "Cred")
                rbcl = typeof(System.Net.CredentialCache).GetProperty("DefaultCredentials").GetGetMethod();
            if (rbcl == null) { Console.WriteLine("[dginject] bcl missing " + p.Bcl); return; }
            ins.Add(new Instruction(OpCodes.Ldnull));
            ins.Add(new Instruction(OpCodes.Ldftn, mod.Import(rbcl)));
            ins.Add(new Instruction(OpCodes.Newobj, mod.Import(dctor)));
            ins.Add(new Instruction(OpCodes.Stsfld, mod.Import(fld)));
            Console.WriteLine("[dginject] " + p.Dlg + "::" + p.Fld + " = ldftn " + rbcl.DeclaringType.Name + "::" + rbcl.Name);
        }
        // 插到最前(在 call DefineActiveEvent 之前 — 委托先于一切业务)
        for (int i = ins.Count - 1; i >= 0; i--) body.Instructions.Insert(0, ins[i]);

        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
        opts.MetadataOptions.Flags &= ~MetadataFlags.KeepOldMaxStack; // KeepOldMaxStack 是 body 级
        foreach (var t in mod.GetTypes()) foreach (var m in t.Methods) if (m.HasBody) m.Body.KeepOldMaxStack = true;
        mod.Write(a[1], opts);
        Console.WriteLine("[dginject] wrote " + a[1]);
    }
}
