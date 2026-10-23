using System;
using dnlib.DotNet;

class ResList {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var r in mod.Resources) {
            var emb = r as EmbeddedResource;
            Console.WriteLine((emb == null ? r.GetType().Name : "Embedded") + " " + r.Name + (emb != null ? " len=" + emb.CreateReader().Length : ""));
        }
    }
}
