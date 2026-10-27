using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>uehook — 向 <Module>::.cctor 注入 AppDomain.UnhandledException 日志钩子。</summary>
public static class CmdUeHook
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: uehook <in.exe> <out.exe> [logPath]"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        string logPath = args.Length > 3 ? args[3] : "C:\\airtest\\ue.log";
        var cctor = mod.GlobalType.FindMethod(".cctor");
        if (cctor == null || !cctor.HasBody) { Console.WriteLine("[uehook] <Module>::.cctor missing"); return 1; }

        var corlib = mod.CorLibTypes;
        var objSig = corlib.Object.ToTypeDefOrRef();
        var ueea = new TypeRefUser(mod, "System", "UnhandledExceptionEventArgs", mod.CorLibTypes.AssemblyRef);
        var ueeaSig = new ClassSig(ueea);
        // handler: static void Handler(object s, UnhandledExceptionEventArgs e)
        var handler = new MethodDefUser("UEHook",
            MethodSig.CreateStatic(corlib.Void, objSig.ToTypeSig(), ueeaSig),
            MethodImplAttributes.IL,
            MethodAttributes.Static | MethodAttributes.Public | MethodAttributes.HideBySig);
        mod.GlobalType.Methods.Add(handler);

        var body = new CilBody();
        var eArg = handler.Parameters[1];
        body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Instructions.Add(Instruction.Create(OpCodes.Callvirt,
            new MemberRefUser(mod, "get_ExceptionObject",
                MethodSig.CreateInstance(corlib.Object),
                ueea)));
        body.Instructions.Add(Instruction.Create(OpCodes.Callvirt,
            new MemberRefUser(mod, "ToString",
                MethodSig.CreateInstance(corlib.String),
                corlib.Object.ToTypeDefOrRef())));
        body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, logPath));
        body.Instructions.Add(Instruction.Create(OpCodes.Call,
            new MemberRefUser(mod, "WriteAllText",
                MethodSig.CreateStatic(corlib.Void, corlib.String, corlib.String),
                new TypeRefUser(mod, "System.IO", "File", mod.CorLibTypes.AssemblyRef))));
        body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        handler.Body = body;

        // <Module>::.cctor 头部插: ldnull; ldftn handler; call AppDomain.add_UnhandledException
        var appDomain = new TypeRefUser(mod, "System", "AppDomain", mod.CorLibTypes.AssemblyRef);
        var addHandler = new MemberRefUser(mod, "add_UnhandledException",
            MethodSig.CreateStatic(corlib.Void,
                new GenericInstSig(new ClassSig(new TypeRefUser(mod, "System", "EventHandler`1", mod.CorLibTypes.AssemblyRef)),
                    new ClassSig(new TypeRefUser(mod, "System", "UnhandledExceptionEventArgs", mod.CorLibTypes.AssemblyRef)))),
            appDomain);
        var cins = cctor.Body.Instructions;
        var first = cins[0];
        var i1 = Instruction.Create(OpCodes.Ldnull);
        var i2 = Instruction.Create(OpCodes.Ldftn, handler);
        var i3 = Instruction.Create(OpCodes.Call, addHandler);
        cins.Insert(0, i1); cins.Insert(1, i2); cins.Insert(2, i3);
        // EH 边界若从 first 开始需调整——<Module> cctor 有 EH 时 try 边界可能悬空，安全重绑
        foreach (var eh in cctor.Body.ExceptionHandlers)
        {
            if (ReferenceEquals(eh.TryStart, first)) eh.TryStart = i1;
            if (ReferenceEquals(eh.TryEnd, first)) eh.TryEnd = i3;
            if (ReferenceEquals(eh.HandlerStart, first)) eh.HandlerStart = i1;
            if (ReferenceEquals(eh.HandlerEnd, first)) eh.HandlerEnd = i3;
        }
        cctor.Body.MaxStack = (ushort)Math.Max((int)cctor.Body.MaxStack, 4);

        var opts = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(args[2], opts);
        Console.WriteLine("[uehook] injected, log=" + logPath + " -> " + args[2]);
        return 0;
    }
}
