using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>findpinv — 找全部 P/Invoke 声明及其调用者。</summary>
public static class CmdFindPinv
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: findpinv <exe> [filter]"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        string? filter = args.Length > 2 ? args[2].ToLowerInvariant() : null;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions)
                {
                    if (ins.Operand is MemberRef mr && mr.Name.String.Contains("FailFast"))
                    {
                        Console.WriteLine("[{0}] {1}::{2} @IL_{3:X4} calls {4}::{5}", (uint)m.MDToken.Raw,
                            t.FullName, m.Name, ins.Offset, mr.Class?.FullName, mr.Name);
                    }
                    if (ins.Operand is MethodDef md2 && md2.Name.String.Contains("FailFast"))
                    {
                        Console.WriteLine("[{0}] {1}::{2} @IL_{3:X4} calls def {4}::{5}", (uint)m.MDToken.Raw,
                            t.FullName, m.Name, ins.Offset, md2.DeclaringType?.FullName, md2.Name);
                    }
                }
            }
        return 0;
    }
}
