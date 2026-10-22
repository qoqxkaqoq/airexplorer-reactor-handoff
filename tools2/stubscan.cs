using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// stubscan: 统计目标模块里的"空桩方法"(≤4 条指令且只含 nop/ldnull/ldc.i4.x/ret),
// 并检查源模块(cilantro)里同名同签名的方法是否有真体, 输出可移植清单。
// 用法: stubscan <dst> <src> [--list] [--out file]
class StubScan {
    static void Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: stubscan <dst> <src> [--list] [--out file]"); return; }
        var dst = ModuleDefMD.Load(a[0]);
        var src = ModuleDefMD.Load(a[1]);
        bool list = a.Any(x => x == "--list");
        string outFile = null;
        for (int i = 2; i < a.Length; i++) if (a[i] == "--out" && i + 1 < a.Length) outFile = a[++i];

        var srcIndex = new Dictionary<string, List<MethodDef>>();
        foreach (var t in src.GetTypes())
            foreach (var m in t.Methods) {
                var k = t.FullName + "::" + m.Name + "/" + m.MethodSig;
                if (!srcIndex.ContainsKey(k)) srcIndex[k] = new List<MethodDef>();
                srcIndex[k].Add(m);
            }

        int total = 0, stub = 0, transplantable = 0, noSig = 0;
        var lines = new List<string>();
        foreach (var t in dst.GetTypes()) {
            foreach (var m in t.Methods) {
                total++;
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                if (ins.Count > 6) continue;
                bool isStub = ins.All(x => x.OpCode.Code == Code.Nop || x.OpCode.Code == Code.Ldnull
                    || x.OpCode.Code == Code.Ldc_I4_0 || x.OpCode.Code == Code.Ldc_I4_1
                    || x.OpCode.Code == Code.Ldc_I4 || x.OpCode.Code == Code.Ret
                    || x.OpCode.Code == Code.Br_S || x.OpCode.Code == Code.Br);
                if (!isStub) continue;
                stub++;
                var key = t.FullName + "::" + m.Name + "/" + m.MethodSig;
                if (srcIndex.TryGetValue(key, out var cands)) {
                    var real = cands.FirstOrDefault(x => x.HasBody && x.Body.Instructions.Count > 4);
                    if (real != null) {
                        transplantable++;
                        lines.Add("T|" + t.FullName + "|" + m.Name + "|dst=" + ins.Count + "|src=" + real.Body.Instructions.Count);
                        if (list) Console.WriteLine("[T] " + t.FullName + "::" + m.Name + "  dst=" + ins.Count + " src=" + real.Body.Instructions.Count);
                        continue;
                    }
                }
                noSig++;
                lines.Add("X|" + t.FullName + "|" + m.Name + "|" + ins.Count);
                if (list) Console.WriteLine("[X] " + t.FullName + "::" + m.Name + "  (" + ins.Count + ") 源无真体");
            }
        }
        Console.WriteLine("total=" + total + " stub=" + stub + " transplantable=" + transplantable + " noSrcBody=" + noSig);
        if (outFile != null) { System.IO.File.WriteAllLines(outFile, lines); Console.WriteLine("wrote " + outFile); }
    }
}
