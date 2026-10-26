using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>pinvoke &lt;exe&gt; — 列出全部 P/Invoke (DllImport) 声明: DLL 名 + 函数名。</summary>
public static class CmdScanPinvoke
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: pinvoke <exe>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var byDll = new SortedDictionary<string, List<string>>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (m.ImplMap == null) continue;
                var dll = m.ImplMap.Module?.Name?.ToString() ?? "?";
                var fn = m.ImplMap.Name?.ToString() ?? m.Name;
                if (!byDll.TryGetValue(dll, out var l)) byDll[dll] = l = new List<string>();
                l.Add(fn + " (" + t.FullName.Split('/').Last() + "::" + m.Name + ")");
            }
        foreach (var kv in byDll)
        {
            Console.WriteLine("== {0} ({1}) ==", kv.Key, kv.Value.Count);
            foreach (var s in kv.Value.Distinct().OrderBy(x => x)) Console.WriteLine("   " + s);
        }
        return 0;
    }
}
