using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>
/// scanil — 扫描产物方法体中的可疑指令: null operand / ldstr token 状态。
/// 用法: scanil &lt;exe&gt; [manifest]
/// </summary>
public static class CmdScanIl
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: scanil <exe> [manifest]"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var man = new Dictionary<string, string>();
        if (args.Length > 2)
            foreach (var ln in File.ReadLines(args[2]).Skip(1))
            {
                var p = ln.Split('\t');
                if (p.Length >= 4) man[p[1]] = p[2];
            }

        int nNull = 0, nLdstrNull = 0, nLdstrOk = 0, nTokNull = 0, nMethodNoBody = 0;
        var nullSamples = new List<string>();
        var ldstrNullSamples = new List<string>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                var tok = m.MDToken.Raw.ToString("X8");
                if (!m.HasBody) { nMethodNoBody++; continue; }
                foreach (var ins in m.Body.Instructions)
                {
                    if (ins.Operand == null && ins.OpCode.OperandType != OperandType.InlineNone)
                    {
                        nNull++;
                        if (nullSamples.Count < 8)
                            nullSamples.Add(string.Format("{0} {1} IL_{2:X4} {3}", tok,
                                man.GetValueOrDefault(tok, t.FullName + "::" + m.Name), ins.Offset, ins.OpCode));
                        if (ins.OpCode.Code == Code.Ldstr)
                        {
                            nLdstrNull++;
                            if (ldstrNullSamples.Count < 8)
                                ldstrNullSamples.Add(string.Format("{0} {1} IL_{2:X4}", tok,
                                    man.GetValueOrDefault(tok, "?"), ins.Offset));
                        }
                    }
                    else if (ins.OpCode.Code == Code.Ldstr && ins.Operand is string) nLdstrOk++;
                }
            }
        Console.WriteLine("[scanil] null-operand instrs: {0} (ldstr: {1}, other: {2})", nNull, nLdstrNull, nNull - nLdstrNull);
        Console.WriteLine("[scanil] ldstr with string operand: {0}", nLdstrOk);
        Console.WriteLine("[scanil] methods without body: {0}", nMethodNoBody);
        foreach (var s in nullSamples) Console.WriteLine("    null: " + s);
        foreach (var s in ldstrNullSamples) Console.WriteLine("    ldstr-null: " + s);
        return 0;
    }
}
