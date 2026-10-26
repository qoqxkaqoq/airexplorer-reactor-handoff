using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>typetoks &lt;exe&gt; &lt;typeSub&gt; &lt;out&gt; — 输出类型的全部方法 token。</summary>
public static class CmdTypeToks
{
    public static int Run(string[] args)
    {
        if (args.Length < 4) { Console.WriteLine("usage: typetoks <exe> <type-sub> <out>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        int n = 0;
        foreach (var t in mod.GetTypes())
        {
            if (!t.FullName.Contains(args[2])) continue;
            foreach (var m in t.Methods)
            {
                File.AppendAllText(args[3], m.MDToken.Raw.ToString("X8") + "\n");
                n++;
            }
        }
        Console.WriteLine("[typetoks] {0} -> {1} tokens", args[2], n);
        return 0;
    }
}
