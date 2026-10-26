using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>checksig — 统计 NRS dummy 方法的分布与参数数, 以及 manifest 方法与其签名兼容性。</summary>
public static class CmdCheckSig
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: checksig <exe> [manifest]"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var man = new Dictionary<string, string>();
        if (args.Length > 2)
            foreach (var ln in File.ReadLines(args[2]).Skip(1))
            {
                var p = ln.Split('\t');
                if (p.Length >= 4) man[p[1]] = p[2];
            }
        var dummyTypes = new List<string>();
        int nDummy = 0, nDummyInManifest = 0, argMismatch = 0;
        var mismatchSamples = new List<string>();
        foreach (var t in mod.GetTypes())
        {
            if (t.FullName.Contains("dummy") || t.FullName.Contains("Dummy"))
                dummyTypes.Add(t.FullName);
            foreach (var m in t.Methods)
            {
                bool isDummy = t.FullName.Contains("dummy");
                if (isDummy) nDummy++;
                var tok = m.MDToken.Raw.ToString("X8");
                if (man.ContainsKey(tok))
                {
                    if (isDummy) nDummyInManifest++;
                    int pcount = m.Parameters.Count;
                    // 检查 body 中最大 arg 索引
                    if (m.HasBody)
                    {
                        int maxArg = -1;
                        foreach (var ins in m.Body.Instructions)
                        {
                            if (ins.OpCode.Code == Code.Ldarg || ins.OpCode.Code == Code.Ldarga || ins.OpCode.Code == Code.Starg)
                            { if (ins.Operand is Parameter p) maxArg = Math.Max(maxArg, p.Index); }
                            else if (ins.OpCode.Code == Code.Ldarg_0) maxArg = Math.Max(maxArg, 0);
                            else if (ins.OpCode.Code == Code.Ldarg_1) maxArg = Math.Max(maxArg, 1);
                            else if (ins.OpCode.Code == Code.Ldarg_2) maxArg = Math.Max(maxArg, 2);
                            else if (ins.OpCode.Code == Code.Ldarg_3) maxArg = Math.Max(maxArg, 3);
                        }
                        if (maxArg >= pcount)
                        {
                            argMismatch++;
                            if (mismatchSamples.Count < 10)
                                mismatchSamples.Add(string.Format("{0} {1} pcount={2} maxArg={3} dummy={4} sig={5}",
                                    tok, man[tok], pcount, maxArg, isDummy, m.MethodSig != null ? m.MethodSig.ToString() : "null"));
                        }
                    }
                }
            }
        }
        Console.WriteLine("[checksig] dummy types: " + string.Join(", ", dummyTypes.Take(5)));
        Console.WriteLine("[checksig] dummy methods: {0}, of which in manifest: {1}", nDummy, nDummyInManifest);
        Console.WriteLine("[checksig] arg-index >= param-count: {0}", argMismatch);
        foreach (var s in mismatchSamples) Console.WriteLine("    " + s);
        return 0;
    }
}
