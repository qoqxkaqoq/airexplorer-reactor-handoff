using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class FindRes2 {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    var im = ins.Operand as IMethod;
                    if (im == null) continue;
                    var dn = im.DeclaringType == null ? "" : im.DeclaringType.FullName;
                    var mn = im.Name.String;
                    if (mn == "GetManifestResourceStream" || mn == "GetManifestResourceInfo" ||
                        dn.Contains("ResourceSet") || dn.Contains("ResourceReader") || dn.Contains("RuntimeResourceSet"))
                        Console.WriteLine("[load] " + t.FullName + "::" + m.Name + " → " + dn + "::" + mn);
                    // 解密常用 API
                    if (mn == "FromBase64String" || dn.Contains("SHA1") || dn.Contains("RC2") || dn.Contains("Rijndael") || dn.Contains("SymmetricAlgorithm"))
                        Console.WriteLine("[crypt] " + t.FullName + "::" + m.Name + " → " + dn + "::" + mn);
                }
            }
        // ldstr 含 ".resources" 或长度>20 的疑似资源名
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions)
                    if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string s && s.Contains(".resources"))
                        Console.WriteLine("[str] " + t.FullName + "::" + m.Name + " → \"" + s + "\"");
            }
        return 0;
    }
}
