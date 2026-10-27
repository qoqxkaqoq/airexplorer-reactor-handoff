using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>
/// S3 委托表回接 — 读 zdec/Project.bin（3266 条 [Field][Member] 对），
/// 生成 &lt;Module&gt;::InitDelegates 全局初始化方法（ldftn member → newobj 委托ctor → stsfld field），
/// 并在 &lt;Module&gt;::cctor 尾部插入调用。
/// 用法: s3 &lt;in.exe&gt; &lt;out.exe&gt; &lt;Project.bin&gt;
/// </summary>
public static class CmdS3
{
    public static int Run(string[] args)
    {
        if (args.Length < 4) { Console.WriteLine("usage: s3 <in.exe> <out.exe> <Project.bin>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var data = File.ReadAllBytes(args[3]);

        var global = mod.GlobalType;
        var init = new MethodDefUser("InitDelegates",
            MethodSig.CreateStatic(mod.CorLibTypes.Void),
            MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig);
        init.Body = new CilBody();
        global.Methods.Add(init);

        int ok = 0, skipField = 0, skipMember = 0, skipCtor = 0;
        for (int i = 0; i + 8 <= data.Length; i += 8)
        {
            uint fTok = BitConverter.ToUInt32(data, i);
            uint mTok = BitConverter.ToUInt32(data, i + 4);
            // 0x4A = MemberRef 带 Reactor 标志位 0x40
            if ((mTok >> 24) == 0x4A) mTok = (mTok & 0x00FFFFFF) | 0x0A000000;

            var body = init.Body.Instructions;
            var f = mod.ResolveToken(fTok) as FieldDef;
            if (f == null || f.FieldSig?.Type == null) { skipField++; continue; }
            var delType = f.FieldSig.Type.ToTypeDefOrRef().ResolveTypeDef();
            if (delType == null) { skipField++; continue; }

            // 委托 .ctor: (object, native int)
            MethodDef? ctor = null;
            foreach (var cm in delType.Methods)
            {
                if (cm.Name != ".ctor" || cm.MethodSig == null || cm.MethodSig.Params.Count != 2) continue;
                if (cm.MethodSig.Params[0].FullName == "System.Object" &&
                    cm.MethodSig.Params[1].FullName == "System.IntPtr") { ctor = cm; break; }
            }
            if (ctor == null) { skipCtor++; continue; }

            object member = null;
            if (mod.ResolveToken(mTok) is MemberRef mrm) member = mrm;
            else if (mod.ResolveToken(mTok) is MethodDef mdm) member = mdm;
            if (member == null) { skipMember++; continue; }
            // 修复37: 过滤 NRS 重启桩 —— Project 数据里有 4 对绑定到
            // System.Diagnostics.Process::Start（NRS 通过它们 CreateProcess 重启自己）。
            // 这些绑定 Invoke 时=重启 exe → 必须跳过（业务代码如需 Process.Start 走自己的引用）
            if (member is MemberRef mst && mst.Class?.FullName == "System.Diagnostics.Process" &&
                mst.Name.String == "Start")
            { skipMember++; continue; }
            // 修复36: 可访问性过滤 —— 跨程序集 protected 方法（ContainerControl::Dispose 等）
            // 经 ldftn 会 MethodAccessException。外部 TypeRef 无法静态查可见性, 用名称启发:
            // Dispose/Dispose(Boolean)/Finalize/ComponentDispose 是常见 protected 族
            if (member is MemberRef mref2 && mref2.Class != null)
            {
                var clsFull = mref2.Class.FullName ?? "";
                var mn = mref2.Name.String;
                bool external = mref2.Class is TypeRef trr && trr.ResolutionScope is AssemblyRef;
                if (external && (mn == "Dispose" || mn == "Finalize" || mn.StartsWith("Dispose(")))
                { skipMember++; continue; }
            }

            body.Add(Instruction.Create(OpCodes.Ldnull));                       // 目标实例=null(静态方法)
            if (member is MethodDef mdm2)
                body.Add(Instruction.Create(OpCodes.Ldftn, (IMethod)mdm2));
            else
                body.Add(Instruction.Create(OpCodes.Ldftn, (IMethod)member));
            body.Add(Instruction.Create(OpCodes.Newobj, ctor));
            body.Add(Instruction.Create(OpCodes.Stsfld, f));
            ok++;
        }
        init.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        init.Body.MaxStack = 8;

        // <Module>::.cctor 尾部插 call InitDelegates
        MethodDef? mcc = null;
        foreach (var m in global.Methods) if (m.Name == ".cctor") { mcc = m; break; }
        if (mcc == null)
        {
            mcc = new MethodDefUser(".cctor", MethodSig.CreateStatic(mod.CorLibTypes.Void),
                MethodImplAttributes.IL, MethodAttributes.Private | MethodAttributes.Static
                | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
            mcc.Body = new CilBody();
            global.Methods.Add(mcc);
        }
        // 插在最前（ret 之前）: 找第一个 ret 前插
        if (!mcc.HasBody) mcc.Body = new CilBody();
        var cins = mcc.Body.Instructions;
        var call = Instruction.Create(OpCodes.Call, init);
        int insertAt = 0;
        for (int i = 0; i < cins.Count; i++)
            if (cins[i].OpCode.Code == Code.Ret) { insertAt = i; break; }
        cins.Insert(insertAt, call);

        var opts = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(args[2], opts);
        Console.WriteLine($"[s3] delegates={ok} skipField={skipField} skipMember={skipMember} skipCtor={skipCtor} -> {args[2]}");
        return 0;
    }
}
