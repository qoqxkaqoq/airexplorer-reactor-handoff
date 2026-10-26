using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>findcctor &lt;exe&gt; &lt;typeSub&gt; — 找类型的 .cctor token。</summary>
public static class CmdFindCctor
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: findcctor <exe> <type-sub>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        foreach (var t in mod.GetTypes())
        {
            if (!t.FullName.Contains(args[2])) continue;
            foreach (var m in t.Methods)
                if (m.Name == ".cctor")
                    Console.WriteLine("[{0:X8}] {1}::{2} (rva={3})", m.MDToken.Raw, t.FullName, m.Name, m.RVA);
        }
        return 0;
    }
}
