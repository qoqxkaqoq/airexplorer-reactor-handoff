using System;
using dnlib.DotNet;

class EntryChk {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        Console.WriteLine("EntryPoint token: " + (mod.EntryPoint == null ? "无" : mod.EntryPoint.MDToken.Raw.ToString("X8") + " " + mod.EntryPoint.FullName));
        // 全模块搜 Main 方法
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (m.Name.String == "Main" && m.IsStatic) {
                    Console.WriteLine("Main: " + t.FullName + "::Main static=" + m.IsStatic + " body=" + m.HasBody + " token=" + m.MDToken.Raw.ToString("X8"));
                }
            }
        }
        return 0;
    }
}
