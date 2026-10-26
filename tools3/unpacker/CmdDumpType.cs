using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>dumptype &lt;exe&gt; &lt;typeName substring&gt; — 打印类型完整定义细节。</summary>
public static class CmdDumpType
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: dumptype <exe> <name-substr>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        string pat = args[2];
        foreach (var t in mod.GetTypes())
        {
            if (!t.FullName.Contains(pat)) continue;
            Console.WriteLine("TYPE {0} base={1} attrs={2} ifaces={3} methods={4} fields={5} ca={6}",
                t.FullName, t.BaseType?.FullName ?? "null", t.Attributes,
                t.Interfaces.Count, t.Methods.Count, t.Fields.Count, t.CustomAttributes.Count);
            foreach (var ca in t.CustomAttributes.Take(5))
                Console.WriteLine("  typeCA: {0} blob={1}B", ca.TypeFullName, ca.ConstructorArguments.Count + ca.NamedArguments.Count);
            foreach (var f in t.Fields.Take(10))
                Console.WriteLine("  field {0} {1} attrs={2} ca={3}", f.Name, f.FieldSig?.ToString(), f.Attributes, f.CustomAttributes.Count);
            int shown = 0;
            foreach (var m in t.Methods)
            {
                bool interesting = m.CustomAttributes.Count > 0 || (m.ImplMap != null) ||
                    (m.Body != null && m.Body.Variables.Count > 100);
                if (!interesting && shown > 6) continue;
                Console.WriteLine("  method {0} static={1} sig={2} attrs={3} impl={4} body={5} ca={6} implMap={7}",
                    m.Name, m.IsStatic, m.MethodSig?.ToString() ?? "null", m.Attributes,
                    m.ImplAttributes, m.HasBody ? m.Body.Instructions.Count : -1,
                    m.CustomAttributes.Count, m.ImplMap != null ? m.ImplMap.Name : "-");
                shown++;
                if (shown > 40) { Console.WriteLine("  ..."); break; }
            }
            foreach (var m in t.Methods)
                foreach (var ca in m.CustomAttributes.Take(2))
                    Console.WriteLine("  methodCA: {0} :: {1} blob={2}B", m.Name, ca.TypeFullName, ca.ConstructorArguments.Count + ca.NamedArguments.Count);
        }
        return 0;
    }
}
