// findref.cs — 找某个字段被哪些方法读/写(ldsfld/stsfld/ldfld/stfld)
// 用法: findref <file.exe> <字段名关键字> [--type 类型名含关键字]
using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class FindRef {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string kw = a[1];
        string typeKw = null;
        for (int i = 2; i < a.Length - 1; i++)
            if (a[i] == "--type") typeKw = a[i + 1];

        int reads = 0, writes = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    var f = ins.Operand as IField;
                    if (f == null) continue;
                    if (!f.Name.String.Contains(kw)) continue;
                    if (typeKw != null && (f.DeclaringType == null || !f.DeclaringType.FullName.Contains(typeKw))) continue;
                    string kind = ins.OpCode.Code == Code.Ldsfld || ins.OpCode.Code == Code.Ldfld ? "READ " : "WRITE";
                    if (kind == "READ ") reads++; else writes++;
                    Console.WriteLine(string.Format("  {0} {1,-58} :: {2}::{3}",
                        kind, f.DeclaringType.FullName + "." + f.Name, t.FullName, m.Name));
                }
            }
        }
        Console.WriteLine();
        Console.WriteLine("[findref] " + kw + " -> 读 " + reads + " / 写 " + writes);
    }
}
