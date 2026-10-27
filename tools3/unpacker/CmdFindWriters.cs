using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>findwr — 找全部 stsfld/ldsflda 指定字段的方法与位置。</summary>
public static class CmdFindWriters
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: findwr <exe> <fieldTokenHex>"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        uint tok = Convert.ToUInt32(args[2].Replace("0x", ""), 16);
        FieldDef? target = mod.ResolveToken(tok) as FieldDef;
        if (target == null) { Console.WriteLine("field not found: " + args[2]); return 1; }
        Console.WriteLine("[findwr] target: " + target.DeclaringType?.FullName + "::" + target.Name);
        int hits = 0;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions)
                {
                    bool isWrite = ins.OpCode.Code == Code.Stsfld;
                    bool isAddr = ins.OpCode.Code == Code.Ldsflda;
                    if (!isWrite && !isAddr) continue;
                    if (ins.Operand is FieldDef fd && fd.MDToken.Raw == tok)
                    {
                        Console.WriteLine("  {0} {1}::{2} @IL_{3:X4} ({4})", isWrite ? "WRITE" : "ADDR  ",
                            t.FullName, m.Name, ins.Offset, (uint)m.MDToken.Raw);
                        hits++;
                    }
                }
            }
        Console.WriteLine("[findwr] total={0}", hits);
        return 0;
    }
}
