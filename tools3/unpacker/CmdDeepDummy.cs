using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>deepdummy &lt;exe&gt; — dummy_ptr.{GUID} 的 MethodImpl/GP/Property/Event/接口 深查 + 引用解析。</summary>
public static class CmdDeepDummy
{
    public static int Run(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: deepdummy <exe>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        foreach (var t in mod.GetTypes())
        {
            if (!t.FullName.Contains("dummy_ptr")) continue;
            Console.WriteLine("== {0} ==", t.FullName);
            int nOverrides = 0;
            foreach (var m in t.Methods) nOverrides += m.Overrides.Count;
            Console.WriteLine("  attrs={0} genericParams={1} ifaces={2} overrides={3} props={4} events={5}",
                t.Attributes, t.GenericParameters.Count, t.Interfaces.Count, nOverrides,
                t.Properties.Count, t.Events.Count);
            foreach (var gp in t.GenericParameters)
                Console.WriteLine("  type-GP: {0}", gp.Name);
            foreach (var m in t.Methods)
            {
                foreach (var ov in m.Overrides)
                {
                    var body = ov.MethodBody; var decl = ov.MethodDeclaration;
                    Console.WriteLine("  MI: m={0} body={1}({2:X8}) decl={3}({4:X8})",
                        m.Name, body?.Name ?? "null", (body as ITokenOperand)?.MDToken.Raw ?? 0,
                        decl?.Name ?? "null", (decl as ITokenOperand)?.MDToken.Raw ?? 0);
                }
            }
            foreach (var p in t.Properties)
                Console.WriteLine("  prop: {0} get={1} set={2}", p.Name,
                    p.GetMethod?.Name ?? "-", p.SetMethod?.Name ?? "-");
            foreach (var e in t.Events)
                Console.WriteLine("  event: {0} add={1} rm={2} fire={3}", e.Name,
                    e.AddMethod?.Name ?? "-", e.RemoveMethod?.Name ?? "-", e.InvokeMethod?.Name ?? "-");
            // 全部方法的 GP
            foreach (var m in t.Methods)
            {
                if (m.GenericParameters.Count > 0)
                    Console.WriteLine("  method {0}: genericParams={1}", m.Name, m.GenericParameters.Count);
            }
        }
        return 0;
    }
}
