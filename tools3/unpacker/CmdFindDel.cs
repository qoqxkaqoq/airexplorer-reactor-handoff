using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>finddel — 找 Invoke 签名匹配给定方法的 delegate 类型。</summary>
public static class CmdFindDel
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: finddel <exe> <methodTok>"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        uint tok = Convert.ToUInt32(args[2].Replace("0x", ""), 16);
        IMethod? target = mod.ResolveToken(tok) as IMethod;
        if (target == null) { Console.WriteLine("method not found: " + args[2]); return 1; }
        var sig = target.MethodSig ?? (target as MemberRef)?.MethodSig;
        if (sig == null) { Console.WriteLine("no sig"); return 1; }
        string targetSig = sig.ToString() ?? "";
        Console.WriteLine("[finddel] target sig: " + targetSig);

        foreach (var t in mod.GetTypes())
        {
            if (t.BaseType?.FullName != "System.MulticastDelegate") continue;
            var invoke = t.FindMethod("Invoke");
            if (invoke?.MethodSig == null) continue;
            if (invoke.MethodSig.ToString() == targetSig)
                Console.WriteLine("  MATCH: [0x{0:X8}] {1} (Invoke {2})", (uint)t.MDToken.Raw, t.FullName, targetSig);
        }
        return 0;
    }
}
