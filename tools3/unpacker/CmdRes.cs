using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>resinfo — 对比两边的 ManifestResource 表。</summary>
public static class CmdRes
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: resinfo <exe>"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        Console.WriteLine("[resinfo] {0}: ManifestResource rows={1}", args[1], mod.Resources.Count);
        foreach (var r in mod.Resources.Take(20))
        {
            if (r is EmbeddedResource er)
                Console.WriteLine("  embedded: {0} size={1} attrs={2}", er.Name, er.CreateReader().Length, er.Attributes);
            else
                Console.WriteLine("  {0}: {1}", r.ResourceType, r.Name);
        }
        return 0;
    }
}
