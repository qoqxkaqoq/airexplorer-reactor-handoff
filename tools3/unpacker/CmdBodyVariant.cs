using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>bodyvariant &lt;in&gt; &lt;out&gt; &lt;tok&gt; &lt;mode&gt; — 体变体实验: half1/half2(保留前/后半体)/catexc(CatchType→System.Exception)/noeh(去EH保留体)。</summary>
public static class CmdBodyVariant
{
    public static int Run(string[] args)
    {
        if (args.Length < 5) { Console.WriteLine("usage: bodyvariant <in> <out> <tok> <half1|half2|catexc|noeh>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var m = mod.ResolveToken(Convert.ToUInt32(args[3], 16)) as MethodDef;
        if (m == null || !m.HasBody) { Console.WriteLine("no body"); return 1; }
        string mode = args[4];
        var ins = m.Body.Instructions;
        if (mode == "half1" || mode == "half2")
        {
            int cut = ins.Count / 2;
            var body = new CilBody(true, new List<Instruction>(), new List<ExceptionHandler>(), m.Body.Variables);
            body.MaxStack = (ushort)(m.Body.MaxStack + 32); // 半体栈会破, 放大保平安
            if (mode == "half1")
            {
                for (int i = 0; i < cut; i++) body.Instructions.Add(ins[i]);
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            }
            else
            {
                // 后半体: 需要自平衡, 简化: 直接 ret
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            }
            m.Body = body;
            m.Body.KeepOldMaxStack = false;
            // 半体分支引用被截断的目标 → 简化: 全部 br 目标指向 ret —— 太复杂, half1 用 nop 填充方式代替:
            if (mode == "half1")
            {
                // 后半段全部替换为 nop, 保持所有跳转目标有效
                m.Body = new CilBody(true, ins, m.Body.ExceptionHandlers, m.Body.Variables);
                for (int i = cut; i < ins.Count; i++)
                {
                    if (ins[i].OpCode.OperandType == OperandType.InlineNone) ins[i] = Instruction.Create(OpCodes.Nop);
                    else ins[i] = Instruction.Create(OpCodes.Nop);
                }
                m.Body.MaxStack = (ushort)(m.Body.MaxStack + 32);
                m.Body.KeepOldMaxStack = false;
            }
        }
        else if (mode == "catexc")
        {
            var exc = mod.CorLibTypes.GetTypeRef("System", "Exception");
            foreach (var eh in m.Body.ExceptionHandlers)
                if (eh.HandlerType == ExceptionHandlerType.Catch) eh.CatchType = new TypeRefUser(mod, "System", "Exception", mod.CorLibTypes.AssemblyRef);
        }
        else if (mode == "noeh")
        {
            m.Body.ExceptionHandlers.Clear();
            // leave -> br (leave 只能用于 EH 内)
            foreach (var i in m.Body.Instructions)
                if (i.OpCode.Code == Code.Leave || i.OpCode.Code == Code.Leave_S)
                    i.OpCode = i.OpCode.Code == Code.Leave ? OpCodes.Br : OpCodes.Br_S;
        }
        mod.Write(args[2]);
        Console.WriteLine("[bodyvariant] {0} {1} -> {2}", args[3], mode, args[2]);
        return 0;
    }
}
