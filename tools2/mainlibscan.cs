using System;
using System.Linq;
using System.Collections.Generic;
using dnlib.DotNet;

// mainlibscan <plain-assembly> — survey the decrypted main library.
// Prints assembly identity, type counts, and everything license/activation related.
class MainLibScan {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        Console.WriteLine($"assembly : {mod.Assembly?.FullName}");
        Console.WriteLine($"module   : {mod.FullName}");
        Console.WriteLine($"types    : {mod.GetTypes().Count()}");
        Console.WriteLine($"methods  : {mod.GetTypes().Sum(t => t.Methods.Count)}");
        Console.WriteLine($"resources: {mod.Resources.Count}");
        foreach (var r in mod.Resources.OfType<EmbeddedResource>())
            Console.WriteLine($"  res {r.Name}  {r.CreateReader().Length}B");

        string[] nameHits = { "License", "Licence", "Trial", "Activ", "Regist", "Expired",
                              "Watermark", "Purchase", "Pro", "Serial", "Key", "Auth" };
        string[] fieldHits = { "_IsDecoratorProvider", "m_IsScopeModel", "_IsModelRunner" };
        string[] methHits = { "SendFlexibleAttribute", "PlanRandomTag", "TestCollector",
                              "AssertValidLicense", "OpenScheduledResponder",
                              "ReceiveCentralInterpreter", "CheckCollector" };

        var seen = new HashSet<string>();
        foreach (var t in mod.GetTypes()) {
            bool typeHit = nameHits.Any(h => t.FullName.IndexOf(h, StringComparison.OrdinalIgnoreCase) >= 0);
            foreach (var f in t.Fields) {
                if (fieldHits.Any(h => f.Name.String == h)) {
                    var k = $"FIELD {t.FullName}::{f.Name} = 0x{f.MDToken.Raw:X8}";
                    if (seen.Add(k)) Console.WriteLine(k);
                }
            }
            foreach (var m in t.Methods) {
                if (methHits.Any(h => m.Name.String == h)) {
                    var k = $"METHOD {t.FullName}::{m.Name} = 0x{m.MDToken.Raw:X8} il={m.Body?.Instructions.Count ?? -1}";
                    if (seen.Add(k)) Console.WriteLine(k);
                }
            }
            if (typeHit) {
                var k = $"TYPE {t.FullName} ({t.Methods.Count}m {t.Fields.Count}f) = 0x{t.MDToken.Raw:X8}";
                if (seen.Add(k)) Console.WriteLine(k);
            }
        }
    }
}
