using System;
using System.Linq;
using dnlib.DotNet;

// licref <exe> — 全量列出含 Licensing 的 TypeDef/TypeRef/MemberRef/AssemblyRef
class LicRef {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        Console.WriteLine("== AssemblyRefs ==");
        foreach (var ar in mod.GetAssemblyRefs()) Console.WriteLine("   " + ar.FullName);
        Console.WriteLine("== TypeDef/TypeRef 含 Licensing ==");
        foreach (var t in mod.GetTypes()) {
            if (t.FullName.IndexOf("Licensing", StringComparison.OrdinalIgnoreCase) >= 0)
                Console.WriteLine("   TD " + t.MDToken.ToString() + " " + t.FullName);
        }
        foreach (var t in mod.GetTypeRefs()) {
            if (t.FullName.IndexOf("Licensing", StringComparison.OrdinalIgnoreCase) >= 0)
                Console.WriteLine("   TR " + t.MDToken.ToString() + " " + t.FullName + "  scope=" + t.ResolutionScope?.ToString());
        }
        Console.WriteLine("== MemberRef 含 Licensing ==");
        int n = 0;
        foreach (var mr in mod.GetMemberRefs()) {
            var c = mr.Class;
            string cn = c is ITypeDefOrRef tdr ? tdr.FullName : (c?.ToString() ?? "");
            if (cn.IndexOf("Licensing", StringComparison.OrdinalIgnoreCase) >= 0 || mr.FullName.IndexOf("Licensing", StringComparison.OrdinalIgnoreCase) >= 0) {
                Console.WriteLine("   " + mr.MDToken.ToString() + " " + mr.FullName);
                if (++n > 50) { Console.WriteLine("   ..."); break; }
            }
        }
        if (n == 0) Console.WriteLine("   (none)");
    }
}
