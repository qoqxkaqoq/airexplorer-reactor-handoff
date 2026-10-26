using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>findmethod &lt;exe&gt; &lt;name&gt; — 按方法名查 token。</summary>
public static class CmdFindMethod
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: findmethod <exe> <name>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
                if (m.Name.ToString().Contains(args[2]))
                    Console.WriteLine("[{0:X8}] {1}::{2}", m.MDToken.Raw, t.FullName, m.Name);
        return 0;
    }
}
