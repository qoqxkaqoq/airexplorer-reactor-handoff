using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>findcp — 找所有 ldstr 含 CreateProcess/StartupInfo 等进程创建特征的代码。</summary>
public static class CmdFindCP
{
    /// <summary>findcp <exe> members — 找 Name 含 Create 的 MemberRef/MethodDef。</summary>
    public static int ScanMembers(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: findcp <exe> members"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        foreach (var mr in mod.GetMemberRefs())
        {
            var n = mr.Name.String;
            if (n.Length > 4 && (n.IndexOf("Create", StringComparison.OrdinalIgnoreCase) >= 0 ||
                n.IndexOf("Process", StringComparison.OrdinalIgnoreCase) >= 0) && n != "CreateDelegate")
            {
                var sig = mr.MethodSig != null ? mr.MethodSig.ToString() : "?";
                Console.WriteLine("MemberRef 0x{0:X8} {1}::{2} {3}", (uint)mr.MDToken.Raw, mr.Class?.FullName, n, sig);
            }
        }
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                var n = m.Name.String;
                if (n.Length > 4 && (n.IndexOf("CreateProcess", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    n.IndexOf("SpawnProc", StringComparison.OrdinalIgnoreCase) >= 0))
                    Console.WriteLine("MethodDef 0x{0:X8} {1}::{2} {3}", (uint)m.MDToken.Raw, t.FullName, n, m.MethodSig);
            }
        return 0;
    }

    /// <summary>findcp <exe> pstart — 找 Process.Start 调用者。</summary>
    public static int ScanProcessStart(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: findcp <exe> pstart"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions)
                {
                    if (i.Operand is IMethod im && im.DeclaringType?.FullName == "System.Diagnostics.Process" &&
                        (im.Name.String == "Start" || im.Name.String.Contains("GetCurrentProcess")))
                        Console.WriteLine("[0x{0:X8}] {1}::{2} @IL_{3:X4}: {4}::{5}", (uint)m.MDToken.Raw,
                            t.FullName, m.Name, i.Offset, im.DeclaringType.FullName, im.Name);
                }
            }
        return 0;
    }

    /// <summary>findcp <exe> app — 找 Application 子类与其 Shutdown/MainWindow/Startup 引用。</summary>
    public static int ScanApp(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: findcp <exe> app"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        foreach (var t in mod.GetTypes())
        {
            if (t.BaseType?.FullName != "System.Windows.Application") continue;
            Console.WriteLine("App class: [0x{0:X8}] {1} (methods={2})", (uint)t.MDToken.Raw, t.FullName, t.Methods.Count);
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions)
                {
                    if (i.Operand is IMethod im && (im.Name.String.Contains("Shutdown") || im.Name.String.Contains("MainWindow") ||
                        im.Name.String == "Run"))
                        Console.WriteLine("  [0x{0:X8}] {1} @IL_{2:X4}: {3}::{4}", (uint)m.MDToken.Raw, m.Name, i.Offset,
                            im.DeclaringType?.FullName, im.Name);
                    if (i.OpCode.Code == Code.Ldstr && i.Operand is string sv && sv.Length < 60)
                        Console.WriteLine("  [0x{0:X8}] {1} @IL_{2:X4}: ldstr \"{3}\"", (uint)m.MDToken.Raw, m.Name, i.Offset, sv);
                }
            }
        }
        return 0;
    }

    public static int Run(string[] args)
    {
        if (args.Length >= 3 && args[2] == "members") return ScanMembers(args);
        if (args.Length >= 3 && args[2] == "pstart") return ScanProcessStart(args);
        if (args.Length >= 3 && args[2] == "app") return ScanApp(args);
        if (args.Length >= 3 && args[2] == "pstart") return ScanProcessStart(args);
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
