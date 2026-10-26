using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>audittoks &lt;exe&gt; &lt;tok&gt; — 解析方法体内全部类型/成员 token, 报解析失败者。</summary>
public static class CmdAuditToks
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: audittoks <exe> <tok>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var m = mod.ResolveToken(Convert.ToUInt32(args[2], 16)) as MethodDef;
        if (m == null || !m.HasBody) { Console.WriteLine("no body"); return 1; }
        int n = 0, fail = 0;
        foreach (var ins in m.Body.Instructions)
        {
            if (ins.Operand is ITokenOperand t)
            {
                n++;
                try
                {
                    var r = mod.ResolveToken(t.MDToken.Raw);
                    if (r == null) { fail++; Console.WriteLine("[NULL] IL_{0:X4} {1} {2:X8}", ins.Offset, ins.OpCode, t.MDToken.Raw); }
                }
                catch (Exception ex)
                {
                    fail++;
                    Console.WriteLine("[FAIL] IL_{0:X4} {1} {2:X8}: {3}", ins.Offset, ins.OpCode, t.MDToken.Raw, ex.Message);
                }
            }
        }
        // locals 也查
        foreach (var v in m.Body.Variables)
        {
            try
            {
                string fn = v.Type.FullName;
                if (fn.Contains("__ReactorRemoved")) Console.WriteLine("[local-shell] loc{0}: {1}", v.Index, fn);
            }
            catch (Exception ex) { fail++; Console.WriteLine("[LOCAL-FAIL] loc{0}: {1}", v.Index, ex.Message); }
        }
        Console.WriteLine("[audittoks] tokens={0} fails={1}", n, fail);
        return 0;
    }
}
