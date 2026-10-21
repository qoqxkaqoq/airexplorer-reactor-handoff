using System;
using dnlib.DotNet;

class RvaChk {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string want = a.Length > 1 ? a[1] : "VerifyCustomIteratorRunner";
        int noRva = 0, withRva = 0, stub = 0;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (m.Name.String != want) continue;
                if (!m.HasBody || m.RVA == 0) { noRva++; Console.WriteLine("[noRVA] " + t.FullName + "::" + m.Name); }
                else {
                    withRva++;
                    bool isStub = m.Body.Instructions.Count <= 4;
                    if (isStub) stub++;
                    Console.WriteLine("[ok " + m.Body.Instructions.Count + "] " + t.FullName + "::" + m.Name);
                }
            }
        Console.WriteLine("noRVA=" + noRva + " 有体=" + withRva + " 其中桩=" + stub);
        return 0;
    }
}
