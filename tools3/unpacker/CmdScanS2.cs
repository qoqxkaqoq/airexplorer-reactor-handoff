using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>scans2 — 扫描 "ldc.i4 <n>; call <m>" 模式，按 call 目标统计——识别字符串解密器。</summary>
public static class CmdScanS2
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: scans2 <exe>"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        // 统计: ldc.i4(或ldc.i4.s/n) 后紧跟 call/callvirt 的目标方法频率
        var freq = new Dictionary<uint, (int cnt, string name)>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                for (int i = 0; i < ins.Count - 1; i++)
                {
                    if (ins[i].OpCode.Code != Code.Ldc_I4 && ins[i].OpCode.Code != Code.Ldc_I4_S &&
                        ins[i].OpCode.Code != Code.Ldc_I4_0 && ins[i].OpCode.Code != Code.Ldc_I4_1) continue;
                    var nxt = ins[i + 1];
                    if (nxt.OpCode.Code != Code.Call && nxt.OpCode.Code != Code.Callvirt) continue;
                    if (nxt.Operand is not MethodDef cm) continue;   // 只看本模块方法
                    if (!freq.TryGetValue((uint)cm.MDToken.Raw, out var v)) freq[(uint)cm.MDToken.Raw] = (0, cm.FullName);
                    freq[(uint)cm.MDToken.Raw] = (v.cnt + 1, v.name);
                }
            }
        foreach (var kv in freq.OrderByDescending(x => x.Value.cnt).Take(20))
            Console.WriteLine("  call 0x{0:X8} x{1}  {2}", kv.Key, kv.Value.cnt, kv.Value.name);
        return 0;
    }
}
