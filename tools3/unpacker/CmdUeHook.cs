using SR = System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;


namespace AirExplorerUnpacker;

/// <summary>uehook — 向 <Module>::.cctor 注入 AppDomain.UnhandledException 日志钩子（Importer 版）。</summary>
public static class CmdUeHook
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: uehook <in.exe> <out.exe> [logPath]"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        string logPath = args.Length > 3 ? args[3] : "C:\\airtest\\ue.log";
        var cctor = mod.GlobalType.FindMethod(".cctor");
        if (cctor == null || !cctor.HasBody) { Console.WriteLine("[uehook] <Module>::.cctor missing"); return 1; }

        // 全部用产物里已存在的引用（Slayed 现成 MemberRef/TypeRef）—— 100% 可解析
        var getCurrentDomain = (IMethod)mod.ResolveToken(0x0A000A41)!;
        var addUe = (IMethod)mod.ResolveToken(0x0A000B0E)!;
        var appDomain = ((MemberRef)getCurrentDomain).Class;
        // UnhandledExceptionEventHandler TypeRef: 复用 add_UnhandledException 签名里的类型
        var uehType = ((MemberRef)addUe).MethodSig!.Params[0].ToTypeDefOrRef();
        var corlib = mod.CorLibTypes;
        var handler = new MethodDefUser("UEHook",
            MethodSig.CreateStatic(corlib.Void, corlib.Object,
                new ClassSig(uehType)),
            dnlib.DotNet.MethodImplAttributes.IL,
            dnlib.DotNet.MethodAttributes.Static | dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.HideBySig);
        mod.GlobalType.Methods.Add(handler);

        var body = new CilBody();
        body.Instructions.Add(Instruction.Create(OpCodes.Ldarg_1));
        body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, GetMember(mod, "UnhandledExceptionEventArgs", "get_ExceptionObject", 0)));
        body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, GetMember(mod, "Object", "ToString", 0)));
        body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, logPath));
        body.Instructions.Add(Instruction.Create(OpCodes.Call, GetMember(mod, "File", "WriteAllText", 2)));
        body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        handler.Body = body;

        var cins = cctor.Body.Instructions;
        var first = cins[0];
        var i0 = Instruction.Create(OpCodes.Call, getCurrentDomain);
        var i1 = Instruction.Create(OpCodes.Ldnull);
        var i2 = Instruction.Create(OpCodes.Ldftn, handler);
        var i3 = Instruction.Create(OpCodes.Callvirt, addUe);
        cins.Insert(0, i0); cins.Insert(1, i1); cins.Insert(2, i2); cins.Insert(3, i3);
        // 修复: EH 不重绑 —— 插入的 hook 指令栈平衡且合法, 在 try 内外都合法;
        // 原重绑逻辑(TryEnd=i3)反而把 hook 包进 try 且边界错位 → InvalidProgram
        if (cctor.Body.ExceptionHandlers.Count > 0)
        {
            // 若原 try 从 first 开始, 把 TryStart 前移到 i0 即可 (TryEnd 不动)
            foreach (var eh in cctor.Body.ExceptionHandlers)
                if (ReferenceEquals(eh.TryStart, first)) eh.TryStart = i0;
        }
        cctor.Body.MaxStack = (ushort)Math.Max((int)cctor.Body.MaxStack, 4);

        var opts = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(args[2], opts);
        Console.WriteLine("[uehook] injected, log=" + logPath + " -> " + args[2]);
        return 0;
    }

    static MemberRef? _cachedExcObj, _cachedToStr, _cachedWrite;
    static MemberRef GetMember(ModuleDef mod, string typeName, string name, int argCount)
    {
        MemberRef? c = typeName == "UnhandledExceptionEventArgs" ? _cachedExcObj : typeName == "Object" ? _cachedToStr : _cachedWrite;
        if (c != null) return c;
        foreach (var mr in mod.GetMemberRefs())
        {
            if (mr.Name.String != name) continue;
            if (mr.Class == null || !mr.Class.FullName.EndsWith("." + typeName)) continue;
            if (mr.MethodSig != null && mr.MethodSig.Params.Count == argCount)
            {
                if (typeName == "UnhandledExceptionEventArgs") _cachedExcObj = mr;
                else if (typeName == "Object") _cachedToStr = mr;
                else _cachedWrite = mr;
                return mr;
            }
        }
        Console.WriteLine($"[uehook] WARNING: member {typeName}::{name} not found, using null (will crash)");
        return null!;
    }
}
