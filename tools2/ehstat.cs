using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// ehstat: 统计所有 catch 子句的 CatchType 分布, 判断 EH 是否整体损坏
// 合法 catch 类型应是 System.Exception 派生(名字含 Exception) 或 System.Object
class EhStat {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var cnt = new Dictionary<string, int>();
        int total = 0, bad = 0;
        var badSample = new List<string>();
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var eh in m.Body.ExceptionHandlers) {
                    if (eh.HandlerType != ExceptionHandlerType.Catch) continue;
                    total++;
                    var n = eh.CatchType == null ? "<null>" : eh.CatchType.FullName;
                    if (!cnt.ContainsKey(n)) cnt[n] = 0;
                    cnt[n]++;
                    if (!IsOk(n)) {
                        bad++;
                        if (badSample.Count < 15) badSample.Add(t.FullName + "::" + m.Name + "  catch=" + n);
                    }
                }
            }
        }
        Console.WriteLine("catch 子句总数=" + total + "  可疑=" + bad);
        Console.WriteLine("--- 前 12 个最常见 ---");
        foreach (var kv in cnt.OrderByDescending(x => x.Value).Take(12))
            Console.WriteLine("  " + kv.Value + "  " + kv.Key + (IsOk(kv.Key) ? "" : "   <-- 可疑"));
        Console.WriteLine("--- 可疑样例 ---");
        foreach (var s in badSample) Console.WriteLine("  " + s);
    }
    static bool IsOk(string n) {
        if (n == "<null>") return false;
        if (n == "System.Object" || n == "System.Exception" || n == "System.SystemException") return true;
        var simple = n.Contains("/") ? n.Substring(n.LastIndexOf('/') + 1) : (n.Contains(".") ? n.Substring(n.LastIndexOf('.') + 1) : n);
        if (simple.StartsWith("<>")) return false;
        if (simple.Contains("Exception")) return true;
        return false;
    }
}
