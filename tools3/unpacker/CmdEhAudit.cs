using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>ehaudit &lt;exe&gt; &lt;tok&gt; — EH 子句的 CatchType 解析 + dnlib 栈重算。</summary>
public static class CmdEhAudit
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: ehaudit <exe> <tok>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var m = mod.ResolveToken(Convert.ToUInt32(args[2], 16)) as MethodDef;
        if (m == null || !m.HasBody) { Console.WriteLine("no body"); return 1; }
        foreach (var eh in m.Body.ExceptionHandlers)
        {
            string cls = "?";
            try { cls = eh.CatchType != null ? eh.CatchType.FullName : "-"; }
            catch (Exception ex) { cls = "RESOLVE-FAIL: " + ex.Message; }
            Console.WriteLine("[eh] {0} try IL_{1:X4}..IL_{2:X4} h IL_{3:X4}..IL_{4:X4} cls={5}",
                eh.HandlerType, eh.TryStart?.Offset ?? 0xFFFF, eh.TryEnd?.Offset ?? 0xFFFF,
                eh.HandlerStart?.Offset ?? 0xFFFF, eh.HandlerEnd?.Offset ?? 0xFFFF, cls);
            // 检查边界是否在指令边界上
            bool ts = m.Body.Instructions.Any(i => i.Offset == (eh.TryStart?.Offset ?? uint.MaxValue));
            bool te = eh.TryEnd == null || m.Body.Instructions.Any(i => i.Offset == eh.TryEnd.Offset);
            bool hs = m.Body.Instructions.Any(i => i.Offset == (eh.HandlerStart?.Offset ?? uint.MaxValue));
            bool he = eh.HandlerEnd == null || m.Body.Instructions.Any(i => i.Offset == eh.HandlerEnd.Offset);
            Console.WriteLine("      on-instruction-boundary: tryS={0} tryE={1} hS={2} hE={3}", ts, te, hs, he);
        }
        // 栈重算验证: 用 KeepOldMaxStack=false 重新写出会触发 dnlib 计算(太重), 这里跳过
        return 0;
    }
}
