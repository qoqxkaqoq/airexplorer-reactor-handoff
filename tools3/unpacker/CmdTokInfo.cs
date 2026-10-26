using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>tokinfo &lt;exe&gt; &lt;tok&gt; [tok...] — 打印指定 token 的方法签名与体统计。</summary>
public static class CmdTokInfo
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: tokinfo <exe> <tok...>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        for (int i = 2; i < args.Length; i++)
        {
            uint raw = Convert.ToUInt32(args[i], 16);
            var r = mod.ResolveToken(raw);
            if (r is MethodDef m)
            {
                Console.WriteLine("[{0}] {1}::{2} static={3} HasThis={4} sig={5} instrs={6} maxstack={7} locals={8} eh={9} impl={10}",
                    args[i], m.DeclaringType?.FullName, m.Name, m.IsStatic, m.MethodSig?.HasThis,
                    m.MethodSig != null ? m.MethodSig.ToString() : "null",
                    m.HasBody ? m.Body.Instructions.Count : -1,
                    m.HasBody ? m.Body.MaxStack : 0,
                    m.HasBody ? m.Body.Variables.Count : -1,
                    m.HasBody ? m.Body.ExceptionHandlers.Count : -1,
                    m.ImplAttributes);
                if (m.HasBody && m.Body.Instructions.Count <= 24)
                    foreach (var ins in m.Body.Instructions)
                        Console.WriteLine("      IL_{0:X4} {1} {2}", ins.Offset, ins.OpCode,
                            ins.Operand is ITokenOperand t ? "tok:" + t.MDToken.Raw.ToString("X8")
                            : ins.Operand?.ToString() ?? "");
            }
            else Console.WriteLine("[{0}] resolved: {1}", args[i], r?.GetType().Name ?? "NULL");
        }
        return 0;
    }
}
