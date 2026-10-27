using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>
/// scanres — 全方法全 operand token 可解析性扫描。
/// 对每个有体方法的每条指令 token 做 Module.ResolveToken，
/// 报出全部解析失败（null/异常/类型不匹配）——JIT 对解析失败的 token 直接 InvalidProgram。
/// 用法: scanres &lt;exe&gt; [--max N]
/// </summary>
public static class CmdScanRes
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: scanres <exe> [--max N]"); return 2; }
        string path = args[1];
        int max = 30;
        for (int i = 2; i < args.Length; i++)
            if (args[i] == "--max") max = int.Parse(args[++i]);

        var mod = ModuleDefMD.Load(path);
        int methods = 0, checkedTok = 0, failedTok = 0, failedMethods = 0;
        var byKind = new Dictionary<string, int>();
        var samples = new List<string>();

        foreach (var t in mod.GetTypes())
        {
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                methods++;
                bool mFail = false;
                foreach (var ins in m.Body.Instructions)
                {
                    if (ins.Operand is not ITokenOperand op) continue;
                    uint tok = op.MDToken.Raw;
                    if (tok == 0) continue;
                    checkedTok++;
                    object? res = null;
                    try { res = mod.ResolveToken(tok); }
                    catch (Exception e)
                    {
                        failedTok++; mFail = true;
                        Count(byKind, "EXC:" + e.GetType().Name);
                        if (samples.Count < max) samples.Add($"EXC {e.GetType().Name} tok=0x{tok:X8} {t.FullName}::{m.Name} IL_{ins.Offset:X4}");
                        continue;
                    }
                    if (res == null)
                    {
                        failedTok++; mFail = true;
                        Count(byKind, "NULL:" + (tok >> 24));
                        if (samples.Count < max) samples.Add($"NULL tok=0x{tok:X8} ({op.GetType().Name}) {t.FullName}::{m.Name} IL_{ins.Offset:X4}");
                    }
                }
                if (mFail) { failedMethods++; }
            }
        }
        Console.WriteLine($"[scanres] {Path.GetFileName(path)}: methods={methods} tokens={checkedTok} failed={failedTok} failedMethods={failedMethods}");
        foreach (var kv in byKind.OrderByDescending(x => x.Value).Take(15))
            Console.WriteLine($"  {kv.Key}: {kv.Value}");
        foreach (var s in samples) Console.WriteLine("  " + s);
        return 0;
    }

    static void Count(Dictionary<string, int> d, string k)
    { d.TryGetValue(k, out var v); d[k] = v + 1; }
}
