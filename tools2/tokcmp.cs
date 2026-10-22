using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;

// tokcmp: 比较两个模块里同一批 metadata token 解析出的成员是否一致
// 用法: tokcmp <a.exe> <b.exe> <token> [token...]   或   tokcmp <a.exe> <b.exe> --auto N
class TokCmp {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: tokcmp <a> <b> <token...> | tokcmp <a> <b> --auto N"); return; }
        var ma = ModuleDefMD.Load(a[0]);
        var mb = ModuleDefMD.Load(a[1]);
        var toks = new List<uint>();
        if (a[2] == "--auto") {
            int n = a.Length > 3 ? int.Parse(a[3]) : 100;
            // 取 a 的 MethodDef 前 n 个
            foreach (var m in ma.GetTypes().SelectMany(t => t.Methods).Take(n)) toks.Add(m.MDToken.Raw);
        } else {
            for (int i = 2; i < a.Length; i++) toks.Add(Convert.ToUInt32(a[i].Replace("0x", ""), 16));
        }
        int same = 0, diff = 0;
        foreach (var tk in toks) {
            string na = Name(ma, tk), nb = Name(mb, tk);
            bool eq = na == nb;
            if (eq) same++; else diff++;
            Console.WriteLine((eq ? "OK  " : "DIFF") + "  0x" + tk.ToString("X8") + "  A=" + na + "   B=" + nb);
        }
        Console.WriteLine("same=" + same + " diff=" + diff);
    }
    static string Name(ModuleDef m, uint tk) {
        try {
            var o = m.ResolveToken(tk);
            if (o == null) return "<null>";
            if (o is IMethod im) return "M " + im.FullName;
            if (o is IField f) return "F " + f.FullName;
            if (o is IType t) return "T " + t.FullName;
            return o.GetType().Name + " " + o;
        } catch (Exception e) { return "<err " + e.GetType().Name + ">"; }
    }
}
