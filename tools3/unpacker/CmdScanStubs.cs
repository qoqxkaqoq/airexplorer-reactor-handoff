using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>scanstubs — 全量扫描 NRS 暗桩（反调试/反篡改/native 代理/资源校验）。</summary>
public static class CmdScanStubs
{
    static readonly string[] DebugStrs = { "debug", "tamper", "debugger", "hook", "cheat", "vmware", "virtual", "sandbox" };
    static readonly string[] NrsNames = { "keogyBbmx", "StopClient", "TrackCompiler", "VerifyProcessor", "VerifyScopeAnnotationInspector",
        "FormatContainer", "GenerateAutomatableResponder", "InstantiateJoinedService", "CheckExpandableParameter",
        "ValidateSortedDispatcher", "FillResolver", "SortRole", "PlayStrategy", "ValidateGlobalParser", "CheckRandomFinalizer",
        "InstantiateGlobalCalculator", "DefineEfficientProfiler", "GenerateConfigurableSpec", "UpdatePredictor" };

    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: scanstubs <exe> [detail]"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        bool detail = args.Length > 2 && args[2] == "detail";

        var nrsMethods = new HashSet<uint>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
                if (NrsNames.Any(n => m.Name.String.Contains(n)))
                    nrsMethods.Add((uint)m.MDToken.Raw);

        Console.WriteLine("=== NRS 运行时方法（核心暗桩族）===");
        foreach (var tok in nrsMethods.OrderBy(x => x))
        {
            if (mod.ResolveToken(tok) is not MethodDef md) continue;
            string feat = "";
            if (md.HasBody)
            {
                foreach (var i in md.Body.Instructions)
                {
                    if (i.OpCode.Code == Code.Ldstr && i.Operand is string s)
                    {
                        var low = s.ToLowerInvariant();
                        foreach (var ds in DebugStrs) if (low.Contains(ds)) { feat += " ldstr[" + s.Trim() + "]"; break; }
                    }
                    if (i.Operand is IMethod im && (im.Name.String.Contains("GetDelegateForFunctionPointer") ||
                        im.Name.String.Contains("GetProcAddress") || im.Name.String.Contains("LoadLibrary") ||
                        im.Name.String.Contains("IsDebuggerPresent") || im.Name.String.Contains("CheckRemoteDebugger") ||
                        im.Name.String.Contains("OutputDebugString") || im.Name.String.Contains("TerminateProcess") ||
                        im.Name.String.Contains("WriteProcessMemory") || im.Name.String.Contains("OpenProcess") ||
                        im.Name.String.Contains("CreateProcess") || im.Name.String.Contains("GetTickCount") ||
                        im.Name.String.Contains("QueryPerformance")))
                        feat += " " + im.Name.String;
                }
            }
            Console.WriteLine("  [0x{0:X8}] {1}::{2} instrs={3} eh={4}{5}", tok,
                md.DeclaringType?.FullName, md.Name, md.HasBody ? md.Body.Instructions.Count : 0,
                md.HasBody ? md.Body.ExceptionHandlers.Count : 0, feat);
        }

        Console.WriteLine();
        Console.WriteLine("=== 反调试/可疑字符串扫描（全部方法）===");
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions)
                {
                    if (i.OpCode.Code != Code.Ldstr || i.Operand is not string s) continue;
                    var low = s.ToLowerInvariant();
                    foreach (var ds in DebugStrs)
                    {
                        if (low.Contains(ds) && s.Length < 80 && nrsMethods.Contains((uint)m.MDToken.Raw))
                        {
                            Console.WriteLine("  [0x{0:X8}] {1}::{2} @IL_{3:X4}: \"{4}\"", (uint)m.MDToken.Raw,
                                t.FullName, m.Name, i.Offset, s);
                            break;
                        }
                    }
                }
            }

        Console.WriteLine();
        Console.WriteLine("=== GetDelegateForFunctionPointer 全调用者（native 代理创建点）===");
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
            {
                if (!m.HasBody) continue;
                foreach (var i in m.Body.Instructions)
                {
                    if (i.Operand is IMethod im && im.Name.String.Contains("GetDelegateForFunctionPointer"))
                        Console.WriteLine("  [0x{0:X8}] {1}::{2} @IL_{3:X4}", (uint)m.MDToken.Raw, t.FullName, m.Name, i.Offset);
                }
            }
        return 0;
    }
}
