using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>finddup &lt;exe&gt; &lt;nameSub&gt; — 列出 FullName 含某串的全部类型（找 NRS stub 与壳的并存身份）。</summary>
public static class CmdFindDup
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: finddup <exe> <name-sub>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        foreach (var t in mod.GetTypes())
        {
            if (!t.FullName.Contains(args[2])) continue;
            Console.WriteLine("[{0:X8}] {1} base={2} isValueType={3} attrs={4} methods={5} fields={6}",
                t.MDToken.Raw, t.FullName, t.BaseType?.FullName ?? "null",
                t.IsValueType, t.Attributes, t.Methods.Count, t.Fields.Count);
        }
        return 0;
    }
}
