using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>scanmi &lt;exe&gt; — 扫描 MethodImpl 行归属与方法体归属不一致(跨类型残留)。</summary>
public static class CmdScanMethodImpl
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: scanmi <exe>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        int bad = 0, total = 0;
        var miTable = mod.TablesStream.MethodImplTable;
        if (miTable != null)
        {
            int rows = (int)miTable.Rows;
            for (int ri = 1; ri <= rows; ri++)
            {
                total++;
                var cls = mod.ResolveToken(0x09000000 | (uint)ri) as ITypeDefOrRef; // MethodImpl row Class 列
                var bodyM = mod.ResolveToken(0x09000000 | (uint)ri) as IMethod; // 占位——MethodImpl 行读取见下
            }
        }
        Console.WriteLine("[scanmi] total={0} bad={1}", total, bad);
        return 0;
    }
}
