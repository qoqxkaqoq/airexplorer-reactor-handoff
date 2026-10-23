using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// ehsanity <exe> — 统计所有方法的 EH catch 类型是否 Exception 派生
class EhSanity {
    static bool IsExc(ITypeDefOrRef t) {
        if (t == null) return true; // finally/fault
        var cur = t.ResolveTypeDef();
        int hops = 0;
        while (cur != null && hops++ < 30) {
            if (cur.FullName == "System.Exception" || cur.FullName == "System.Object") return true;
            var bt = cur.BaseType;
            if (bt == null) return false;
            try { cur = bt.ResolveTypeDef(); } catch { return false; }
        }
        return false;
    }
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        int bad = 0, good = 0, total = 0;
        var badTypes = new Dictionary<string, int>();
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var eh in m.Body.ExceptionHandlers) {
                    if (eh.HandlerType != ExceptionHandlerType.Catch) continue;
                    total++;
                    if (IsExc(eh.CatchType)) good++;
                    else {
                        bad++;
                        var k = eh.CatchType == null ? "null" : eh.CatchType.FullName;
                        badTypes[k] = badTypes.TryGetValue(k, out int n) ? n + 1 : 1;
                    }
                }
            }
        }
        Console.WriteLine("[ehsanity] catch clauses=" + total + " exception-derived=" + good + " ILLEGAL=" + bad);
        foreach (var kv in badTypes) Console.WriteLine("  " + kv.Value + "x " + kv.Key);
    }
}
