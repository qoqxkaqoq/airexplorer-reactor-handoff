using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>findthread — 找全部 Thread 创建/启动点。</summary>
public static class CmdFindThread
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: findthread <exe>"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions)
                {
                    string? hit = null;
                    if (ins.OpCode.Code == Code.Newobj && ins.Operand is IMethod no &&
                        (no.Name.String == ".ctor" && (no.DeclaringType?.Name.String == "Thread" || no.DeclaringType?.Name.String.Contains("ThreadStart") == true)))
                        hit = "new Thread";
                    if (ins.OpCode.Code == Code.Callvirt && ins.Operand is IMethod cv &&
                        cv.Name.String == "Start" && cv.DeclaringType?.Name.String == "Thread")
                        hit = "Thread.Start";
                    if (hit != null)
                        Console.WriteLine("[{0}] {1}::{2} @IL_{3:X4}: {4}", (uint)m.MDToken.Raw,
                            t.FullName, m.Name, ins.Offset, hit);
                }
            }
        return 0;
    }
}
