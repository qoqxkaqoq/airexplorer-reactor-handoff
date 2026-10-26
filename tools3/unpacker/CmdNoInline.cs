using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>noinline &lt;in&gt; &lt;out&gt; &lt;tok&gt; — 给方法加 NoInlining 标记。</summary>
public static class CmdNoInline
{
    public static int Run(string[] args)
    {
        if (args.Length < 4) { Console.WriteLine("usage: noinline <in> <out> <tok>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var m = mod.ResolveToken(Convert.ToUInt32(args[3], 16)) as MethodDef;
        if (m == null) { Console.WriteLine("null"); return 1; }
        m.ImplAttributes &= ~MethodImplAttributes.AggressiveInlining;
        m.ImplAttributes |= MethodImplAttributes.NoInlining;
        mod.Write(args[2]);
        Console.WriteLine("[noinline] {0:X8} -> {1}", m.MDToken.Raw, args[2]);
        return 0;
    }
}
