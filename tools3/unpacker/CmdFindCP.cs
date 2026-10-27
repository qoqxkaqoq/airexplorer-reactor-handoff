using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>findcp — 找所有 ldstr 含 CreateProcess/StartupInfo 等进程创建特征的代码。</summary>
public static class CmdFindCP
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: findcp <exe>"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        string[] keys = { "CreateProcess", "reate rocess", "StartupInfo", "Command Line", "ommand" };
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions)
                {
                    if (i.OpCode.Code != Code.Ldstr || i.Operand is not string s) continue;
                    foreach (var k in keys)
                        if (s.Contains(k))
                        {
                            Console.WriteLine("[0x{0:X8}] {1}::{2} @IL_{3:X4}: \"{4}\"", (uint)m.MDToken.Raw,
                                t.FullName, m.Name, i.Offset, s.Length > 60 ? s.Substring(0, 60) : s);
                            break;
                        }
                }
            }
        return 0;
    }
}
