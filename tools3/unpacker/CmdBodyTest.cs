using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>bodytest &lt;in&gt; &lt;out&gt; &lt;tok&gt; [nop|empty] — 把指定方法的体替换为 nop 体(保留 maxstack/locals)做二分实验。</summary>
public static class CmdBodyTest
{
    public static int Run(string[] args)
    {
        if (args.Length < 4) { Console.WriteLine("usage: bodytest <in> <out> <tok>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var m = mod.ResolveToken(Convert.ToUInt32(args[3], 16)) as MethodDef;
        if (m == null || !m.HasBody) { Console.WriteLine("no body"); return 1; }
        int nInstr = m.Body.Instructions.Count;
        int nEh = m.Body.ExceptionHandlers.Count;
        var vars = m.Body.Variables;
        // 全 nop 体: 覆盖全部变量 (initlocals 需要), 再 ret
        var body = new CilBody(true, new List<Instruction>(), new List<ExceptionHandler>(), new List<Local>());
        foreach (var v in vars) body.Variables.Add(v);
        body.MaxStack = m.Body.MaxStack;
        body.InitLocals = m.Body.InitLocals;
        body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        m.Body = body;
        m.Body.SimplifyBranches();
        mod.Write(args[2]);
        Console.WriteLine("[bodytest] {0}: {1} instrs/{2} eh -> ret-only, written {3}", args[3], nInstr, nEh, args[2]);
        return 0;
    }
}
