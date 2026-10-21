// cmpasm — 全量对比两个模块的方法体 (操作码序列 + 操作数指纹), 统计被改动的范围
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class CmpAsm {
    static int Main(string[] a) {
        var A = ModuleDefMD.Load(a[0]);
        var B = ModuleDefMD.Load(a[1]);
        int same = 0, diff = 0, onlyA = 0, onlyB = 0, both0 = 0;
        var samples = new List<string>();
        var byType = new Dictionary<string, int>();
        foreach (var ta in A.GetTypes()) {
            var tb = B.Find(ta.FullName, false);
            if (tb == null) continue;
            foreach (var ma in ta.Methods) {
                var mb = tb.Methods.FirstOrDefault(x => x.Name == ma.Name && SameSig(x, ma));
                if (mb == null) { onlyA++; continue; }
                bool ha = ma.HasBody, hb = mb.HasBody;
                if (!ha && !hb) { both0++; continue; }
                if (ha != hb) { diff++; Add(byType, ta.FullName, 1); continue; }
                if (Fingerprint(ma).SequenceEqual(Fingerprint(mb))) { same++; continue; }
                diff++;
                Add(byType, ta.FullName, 1);
                if (samples.Count < 25) samples.Add(ta.FullName + "::" + ma.Name + "  A=" + ma.Body.Instructions.Count + " B=" + mb.Body.Instructions.Count);
            }
        }
        Console.WriteLine("same=" + same + " diff=" + diff + " onlyInA=" + onlyA + " bothNoBody=" + both0);
        Console.WriteLine("--- 改动最多的类型 ---");
        foreach (var kv in byType.OrderByDescending(k => k.Value).Take(15))
            Console.WriteLine("  " + kv.Value + "\t" + kv.Key);
        Console.WriteLine("--- 样例 ---");
        foreach (var s in samples) Console.WriteLine("  " + s);
        return 0;
    }

    static void Add(Dictionary<string, int> d, string k, int v) { d[k] = d.TryGetValue(k, out var c) ? c + v : v; }

    static bool SameSig(MethodDef x, MethodDef y) {
        if (x.MethodSig == null || y.MethodSig == null) return false;
        if (x.MethodSig.Params.Count != y.MethodSig.Params.Count) return false;
        if (x.MethodSig.RetType.FullName != y.MethodSig.RetType.FullName) return false;
        if (x.GenericParameters.Count != y.GenericParameters.Count) return false;
        return true;
    }

    static string[] Fingerprint(MethodDef m) {
        var r = new List<string>(m.Body.Instructions.Count + 4);
        foreach (var i in m.Body.Instructions)
            r.Add(i.OpCode.Code + "|" + Norm(i.Operand));
        r.Add("locals:" + string.Join(",", m.Body.Variables.Select(v => v.Type.FullName)));
        return r.ToArray();
    }

    static string Norm(object op) {
        if (op == null) return "";
        if (op is Instruction ins) return "IL_" + ins.Offset.ToString("X4");
        if (op is Instruction[] arr) return "SW" + arr.Length;
        if (op is Local loc) return "V" + loc.Index;
        if (op is Parameter p) return "A" + p.Index;
        var s = op.ToString();
        return s.Length > 70 ? s.Substring(0, 70) : s;
    }
}
