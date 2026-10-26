using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>frvadetail &lt;exe&gt; — 列出全部 FieldRVA 行的字段归属与类型（找标量+RVA 非法组合）。</summary>
public static class CmdFrvaDetail
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: frvadetail <exe>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var img = mod.Metadata.PEImage;
        foreach (var t in mod.GetTypes())
            foreach (var f in t.Fields)
            {
                if (f.RVA == 0) continue;
                string ft = f.FieldSig?.Type?.FullName ?? "?";
                // 标量(非数组/非指针)字段带 RVA 是非法的(CLR 只允许初始数据给数组/struct)
                bool scalar = f.FieldSig?.Type is SZArraySig == false && f.FieldSig?.Type is ClassSig == false && f.FieldSig?.Type is GenericInstSig == false;
                Console.WriteLine("[frva] {0}::{1} tok={2:X8} rva={3:X8} type={4} scalar={5} attrs={6}",
                    t.FullName, f.Name, f.MDToken.Raw, (uint)f.RVA, ft, scalar ? "YES-BAD?" : "no", f.Attributes);
            }
        return 0;
    }
}
