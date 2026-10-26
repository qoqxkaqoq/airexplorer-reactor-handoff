using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>dummyaudit &lt;exe&gt; [baseline] — 全量审计 dummy 类型树: 非法 attrs 组合/abstract 方法残留/签名异常。</summary>
public static class CmdDummyAudit
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: dummyaudit <exe> [baseline]"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        ModuleDefMD bmod = args.Length > 2 ? (ModuleDefMD)ModuleDefMD.Load(args[2]) : null;

        int nBadAttrs = 0, nAbstractMethod = 0, nWeirdSig = 0;
        foreach (var t in mod.GetTypes())
        {
            if (!t.FullName.Contains("dummy")) continue;
            // 非法类型 attrs 组合
            bool isAbstract = (t.Attributes & TypeAttributes.Abstract) != 0;
            bool isSealed = (t.Attributes & TypeAttributes.Sealed) != 0;
            bool isInterface = t.IsInterface;
            if (isInterface || (isAbstract && isSealed))
            {
                nBadAttrs++;
                Console.WriteLine("[bad-type-attrs] {0} abstract={1} sealed={2} iface={3}", t.FullName, isAbstract, isSealed, isInterface);
            }
            foreach (var m in t.Methods)
            {
                bool mAbs = (m.Attributes & MethodAttributes.Abstract) != 0;
                if (mAbs && m.HasBody) { Console.WriteLine("[abs-with-body] {0}::{1}", t.FullName, m.Name); nAbstractMethod++; }
                if (mAbs && !m.HasBody) { nAbstractMethod++; if (nAbstractMethod <= 12) Console.WriteLine("[abs-no-body] {0}::{1} sig={2}", t.FullName, m.Name, m.MethodSig?.ToString()); }
                // 签名异常: 返回/参数类型是 <Module>
                if (m.MethodSig != null)
                {
                    string rs = m.MethodSig.RetType?.ToString();
                    if (rs != null && (rs.Contains("<Module>") || rs.Contains("__ReactorRemoved")))
                    {
                        nWeirdSig++;
                        if (nWeirdSig <= 15)
                        {
                            var bsig = bmod != null && bmod.ResolveToken(m.MDToken.Raw) is MethodDef bm ? bm.MethodSig?.ToString() : "?";
                            Console.WriteLine("[weird-sig] {0}::{1} tok={2:X8} ret={3} baseline={4}",
                                t.FullName, m.Name, m.MDToken.Raw, rs, bsig);
                        }
                    }
                }
            }
        }
        Console.WriteLine("[dummyaudit] bad-type-attrs={0} abstract-methods={1} weird-sigs={2}", nBadAttrs, nAbstractMethod, nWeirdSig);
        return 0;
    }
}
