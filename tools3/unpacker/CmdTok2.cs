using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>tok2 &lt;exeA&gt; &lt;exeB&gt; &lt;token&gt; — 双方解析同一 token 的类型身份。</summary>
public static class CmdTok2
{
    public static int Run(string[] args)
    {
        if (args.Length < 4) { Console.WriteLine("usage: tok2 <exeA> <exeB> <token>"); return 2; }
        var a = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var b = (ModuleDefMD)ModuleDefMD.Load(args[2]);
        uint tok = Convert.ToUInt32(args[3], 16);
        var ta = a.ResolveToken(tok) as ITypeDefOrRef;
        var tb = b.ResolveToken(tok) as ITypeDefOrRef;
        Console.WriteLine("A({0}): {1}", args[1], ta?.FullName ?? "(null)");
        Console.WriteLine("B({0}): {1}", args[2], tb?.FullName ?? "(null)");
        return 0;
    }
}
