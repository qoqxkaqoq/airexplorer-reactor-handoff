using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;
using dnlib.IO;

namespace AirExplorerUnpacker;

/// <summary>
/// inspect — 检查 exe 模块现状并与 bodies_manifest.tsv 对齐。
/// 输出: MethodDef 总数/体形态分布、manifest token 命中率、槽体样貌分类。
/// </summary>
public static class CmdInspect
{
    public static int Run(string[] args)
    {
        // inspect <exe> [manifest.tsv]
        if (args.Length < 2) { Console.WriteLine("usage: inspect <exe> [bodies_manifest.tsv]"); return 2; }
        string exe = args[1];
        string manifest = args.Length > 2 ? args[2] : null;

        Console.WriteLine("[inspect] loading " + exe);
        var mod = ModuleDefMD.Load(exe);
        Console.WriteLine("[inspect] module: " + mod.Name + " kind=" + mod.Kind + " machine=" + mod.Machine);
        Console.WriteLine("[inspect] entrypoint tok=" + (mod.EntryPoint?.MDToken.Raw.ToString("X8") ?? "none"));

        var methods = new List<MethodDef>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
                methods.Add(m);
        Console.WriteLine("[inspect] MethodDefs=" + methods.Count);

        int noBody = 0, tiny = 0, fat = 0, abi = 0;
        int stubLdc = 0;               // tiny 桩, code[0]==0x20 (ldc.i4 ticket)
        int zeroPad = 0;               // 体几乎全零
        long totalIl = 0;
        var sizeBuckets = new int[8];  // 0,1-15,16-63,64-255,256-1k,1k-4k,4k-16k,16k+
        foreach (var m in methods)
        {
            if (m.Body == null) { noBody++; continue; }
            var ins = m.Body.Instructions;
            if (ins.Count == 0) { abi++; continue; }
            totalIl += ins.Count;
            // 判头形态
            if (m.Body.HeaderSize == 1) tiny++; else fat++;
            var first = ins[0];
            if (ins.Count >= 1 && first.OpCode.Code == Code.Ldc_I4 && first.Operand is int) stubLdc++;
            if (ins.Count <= 2 && ins.All(i => i.IsLdloc() || i.IsStloc() || i.OpCode.Code == Code.Ret || i.OpCode.Code == Code.Nop || i.OpCode.Code == Code.Ldnull))
            { /* trivial */ }
            int sz = ins.Count; // 指令数量级分桶（近似体积）
            int b = sz == 0 ? 0 : sz <= 3 ? 1 : sz <= 12 ? 2 : sz <= 48 ? 3 : sz <= 200 ? 4 : sz <= 800 ? 5 : sz <= 3200 ? 6 : 7;
            sizeBuckets[b]++;
            // 全零体特征 (Necrobit 残留)
            if (ins.Count >= 4 && ins.Take(4).All(i => i.OpCode.Code == Code.Nop)) zeroPad++;
        }
        Console.WriteLine("[inspect] bodies: none={0} tiny={1} fat={2} empty={3}", noBody, tiny, fat, abi);
        Console.WriteLine("[inspect] stub-like ldc.i4 first: {0}", stubLdc);
        Console.WriteLine("[inspect] nop-padded bodies: {0}", zeroPad);
        Console.WriteLine("[inspect] size buckets 0,1-15,16-63,64-255,256-1k,1k-4k,4k-16k,16k+: " +
                          string.Join(",", sizeBuckets));
        Console.WriteLine("[inspect] total instr count: " + totalIl);

        // StandAloneSig 数量 (locals 签名池)
        var md = ((ModuleDefMD)mod);
        Console.WriteLine("[inspect] StandAloneSig rows: " + (md.TablesStream?.StandAloneSigTable?.Rows ?? 0));

        // manifest 对齐
        if (manifest != null && File.Exists(manifest))
        {
            var tokmap = new Dictionary<string, (string rva, string name, string src)>();
            foreach (var ln in File.ReadLines(manifest).Skip(1))
            {
                var p = ln.Split('\t');
                if (p.Length >= 4) tokmap[p[1]] = (p[0], p[2], p[3]);
            }
            Console.WriteLine("[inspect] manifest rows: " + tokmap.Count);

            int hit = 0, miss = 0, hitWithBody = 0;
            var srcHit = new Dictionary<string, int>();
            foreach (var m in methods)
            {
                var tok = m.MDToken.Raw.ToString("X8");
                if (!tokmap.TryGetValue(tok, out var info)) continue;
                hit++;
                srcHit[info.src] = srcHit.GetValueOrDefault(info.src) + 1;
                if (m.HasBody && m.Body.Instructions.Count > 0) hitWithBody++;
            }
            miss = tokmap.Count - hit;
            Console.WriteLine("[inspect] manifest tokens found in module: {0}/{1} (miss={2})", hit, tokmap.Count, miss);
            foreach (var kv in srcHit.OrderByDescending(x => x.Value))
                Console.WriteLine("    src {0}: {1}", kv.Key, kv.Value);
        }
        return 0;
    }
}
