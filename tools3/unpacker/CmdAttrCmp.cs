using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>attrcmp — 对比官方与产物某方法的全部方法级元数据属性 + MethodImpl/Semantics 关联。</summary>
public static class CmdAttrCmp
{
    public static int Run(string[] args)
    {
        if (args.Length < 4) { Console.WriteLine("usage: attrcmp <official.exe> <prod.exe> <tok>"); return 2; }
        var off = ModuleDefMD.Load(args[1]);
        var prod = ModuleDefMD.Load(args[2]);
        uint tok = Convert.ToUInt32(args[3].Replace("0x", ""), 16);
        var mo = off.ResolveToken(tok) as MethodDef;
        var mp = prod.ResolveToken(tok) as MethodDef;
        if (mo == null || mp == null) { Console.WriteLine("not found"); return 1; }
        Console.WriteLine($"[attrcmp] 0x{tok:X8} {mo.Name}");
        Console.WriteLine($"  Attributes : official={mo.Attributes}  prod={mp.Attributes}  {(mo.Attributes == mp.Attributes ? "" : ">>> DIFF")}");
        Console.WriteLine($"  ImplAttrs  : official={mo.ImplAttributes}  prod={mp.ImplAttributes}  {(mo.ImplAttributes == mp.ImplAttributes ? "" : ">>> DIFF")}");
        Console.WriteLine($"  HasImplMap : official={mo.HasImplMap}  prod={mp.HasImplMap}");
        Console.WriteLine($"  SemAttrs   : official={mo.SemanticsAttributes}  prod={mp.SemanticsAttributes}");
        Console.WriteLine($"  ParamCount : official={mo.Parameters.Count}  prod={mp.Parameters.Count}");
        Console.WriteLine($"  Generic    : official={mo.HasGenericParameters}  prod={mp.HasGenericParameters}");
        // MethodImpl 表: 两边所有指向/来自此方法的记录
        Console.WriteLine("  MethodImpl(官方):");
        DumpMethodImpl(off, mo);
        Console.WriteLine("  MethodImpl(产物):");
        DumpMethodImpl(prod, mp);
        // MethodSemantics
        Console.WriteLine($"  Semantics(官方): {(mo.SemanticsAttributes != 0 ? "has" : "none")}");
        Console.WriteLine($"  Semantics(产物): {(mp.SemanticsAttributes != 0 ? "has" : "none")}");
        return 0;
    }

    static void DumpMethodImpl(ModuleDef mod, MethodDef m)
    {
        int n = 0;
        foreach (var t in mod.GetTypes())
            foreach (var mm in t.Methods)
            {
                if (!mm.HasImplMap && mm.HasBody)
                {
                    foreach (var ov in mm.Overrides ?? Enumerable.Empty<MethodOverride>())
                    {
                        if (ov.MethodBody == m || ov.MethodDeclaration == m)
                        { Console.WriteLine($"    {t.FullName}::{mm.Name} -> body={(ov.MethodBody as MethodDef)?.Name} decl={(ov.MethodDeclaration as MethodDef)?.Name}"); n++; }
                    }
                }
            }
        if (n == 0) Console.WriteLine("    (none)");
    }
}
