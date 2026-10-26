using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>scansem &lt;exe&gt; — 扫描跨类型的 Property/Event 语义残留与其他类型加载隐患。</summary>
public static class CmdScanSemantics
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: scansem <exe>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        int badProp = 0, badEvt = 0, badOverride = 0;
        foreach (var t in mod.GetTypes())
        {
            foreach (var p in t.Properties)
            {
                foreach (var m in new[] { p.GetMethod, p.SetMethod })
                {
                    if (m == null) continue;
                    var owner = m.DeclaringType;
                    if (owner == null) continue;
                    // 语义行挂在 t 上但方法属于别的类型 → CLR TypeLoad
                    if (!ReferenceEquals(owner, t))
                    {
                        badProp++;
                        if (badProp <= 8)
                            Console.WriteLine("[bad-prop] {0} :: {1} getter/setter {2} (owner={3})",
                                t.FullName, p.Name, m.Name, owner.FullName);
                    }
                }
            }
            foreach (var e in t.Events)
            {
                foreach (var m in new[] { e.AddMethod, e.RemoveMethod, e.InvokeMethod })
                {
                    if (m == null) continue;
                    var owner = m.DeclaringType;
                    if (owner == null) continue;
                    if (!ReferenceEquals(owner, t))
                    {
                        badEvt++;
                        if (badEvt <= 8)
                            Console.WriteLine("[bad-evt] {0} :: {1} addon {2} (owner={3})",
                                t.FullName, e.Name, m.Name, owner.FullName);
                    }
                }
            }
            foreach (var m in t.Methods)
            {
                foreach (var ov in m.Overrides)
                {
                    var owner = ov.MethodBody ?? ov.MethodDeclaration;
                    var od = (owner as IMethod)?.DeclaringType;
                    if (od != null && !ReferenceEquals(od, t))
                    {
                        badOverride++;
                        if (badOverride <= 8)
                            Console.WriteLine("[bad-override] {0} :: {1} overrides {2}::{3}",
                                t.FullName, m.Name, od.FullName, (ov.MethodBody ?? ov.MethodDeclaration)?.Name);
                    }
                }
            }
        }
        Console.WriteLine("[scansem] bad-prop={0} bad-evt={1} bad-override={2}", badProp, badEvt, badOverride);
        return 0;
    }
}
