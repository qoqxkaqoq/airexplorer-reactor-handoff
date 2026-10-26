using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>fulldiff &lt;prod&gt; &lt;base&gt; &lt;tok&gt; — 全指令对比两个模块的同 token 方法（opcode + operand 身份）。</summary>
public static class CmdFullDiff
{
    public static int Run(string[] args)
    {
        if (args.Length < 4) { Console.WriteLine("usage: fulldiff <prod> <base> <tok>"); return 2; }
        var prod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var basem = (ModuleDefMD)ModuleDefMD.Load(args[2]);
        var mp = prod.ResolveToken(Convert.ToUInt32(args[3], 16)) as MethodDef;
        var mb = basem.ResolveToken(Convert.ToUInt32(args[3], 16)) as MethodDef;
        if (mp?.Body == null || mb?.Body == null) { Console.WriteLine("no body"); return 1; }
        var ip = mp.Body.Instructions;
        var ib = mb.Body.Instructions;
        Console.WriteLine("[fulldiff] prod={0} base={1} instrs {2} vs {3}", ip.Count, ib.Count, ip.Count, ib.Count);
        int n = Math.Min(ip.Count, ib.Count);
        int diffs = 0;
        for (int i = 0; i < n; i++)
        {
            var a = ip[i]; var b = ib[i];
            bool same = a.OpCode == b.OpCode;
            string sa = OpStr(a), sb = OpStr(b);
            if (a.OpCode.OperandType == OperandType.InlineNone) { same = same; }
            else same = same && sa == sb;
            if (!same)
            {
                diffs++;
                if (diffs <= 30)
                    Console.WriteLine("  DIFF IL_{0:X4}: prod: {1} {2} | base: {3} {4}", a.Offset, a.OpCode, sa, b.OpCode, sb);
            }
        }
        Console.WriteLine("[fulldiff] diffs={0} / {1}", diffs, n);
        return 0;
    }

    static string OpStr(Instruction i)
    {
        return i.Operand switch
        {
            null => "",
            ITokenOperand t => t.MDToken.Raw.ToString("X8"),
            Instruction x => "IL_" + x.Offset.ToString("X4"),
            Parameter p => "arg" + p.Index,
            Local l => "loc" + l.Index,
            _ => i.Operand.ToString() ?? ""
        };
    }
}
