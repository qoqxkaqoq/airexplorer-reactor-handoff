using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>tokalign &lt;slayed&gt; &lt;baseline&gt; [N] — 抽样对比两模块同 token 方法的 所属类型::名字 与签名, 验证 token 空间对齐。</summary>
public static class CmdTokAlign
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: tokalign <exeA> <exeB> [samples]"); return 2; }
        var a = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var b = (ModuleDefMD)ModuleDefMD.Load(args[2]);
        int samples = args.Length > 3 ? int.Parse(args[3]) : 4000;
        int mismName = 0, mismSig = 0, checkedN = 0;
        var rnd = new Random(42);
        var all = new List<MethodDef>();
        foreach (var t in a.GetTypes()) all.AddRange(t.Methods);
        // 全局方法也要
        foreach (var m in a.GlobalType.Methods) all.Add(m);
        var pick = all.OrderBy(x => rnd.Next()).Take(samples).ToList();
        foreach (var ma in pick)
        {
            var tok = ma.MDToken.Raw;
            if (b.ResolveToken(tok) is not MethodDef mb) continue;
            checkedN++;
            string na = (ma.DeclaringType?.FullName ?? "?") + "::" + ma.Name;
            string nb = (mb.DeclaringType?.FullName ?? "?") + "::" + mb.Name;
            if (na != nb)
            {
                mismName++;
                if (mismName <= 10) Console.WriteLine("[name-mismatch] {0:X8}: A={1} B={2}", tok, na, nb);
            }
            string sa = ma.MethodSig?.ToString() ?? "null";
            string sb = mb.MethodSig?.ToString() ?? "null";
            if (sa != sb)
            {
                mismSig++;
                if (mismSig <= 10) Console.WriteLine("[sig-mismatch] {0:X8}: A={1} B={2}", tok, sa, sb);
            }
        }
        Console.WriteLine("[tokalign] checked={0} name-mismatch={1} sig-mismatch={2}", checkedN, mismName, mismSig);
        // 专项: 06000004 / 06000001 / 06000002 / 06000003
        foreach (uint tok in new uint[] { 1, 2, 3, 4 })
        {
            var ma = a.ResolveToken(tok) as MethodDef;
            var mb = b.ResolveToken(tok) as MethodDef;
            Console.WriteLine("[spec] {0:X8}: A={1}::{2} sig={3} | B={4}::{5} sig={6}",
                tok, ma?.DeclaringType?.FullName, ma?.Name, ma?.MethodSig,
                mb?.DeclaringType?.FullName, mb?.Name, mb?.MethodSig);
        }
        return 0;
    }
}
