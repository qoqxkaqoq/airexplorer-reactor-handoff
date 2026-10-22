using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// fixeh: 修 catch 子句的 CatchType。
// 现象: v47 里 1721 个 catch 有 1515 个类型可疑(783 个是 ExtendedProxy/<>c,
// 586 个是 ClientClient/LogicalFieldClient), 导致 catch 永远不生效, 异常直接冒泡。
// 根因: nbjit dump 的 EH 结构里 ClassToken 字段取错(或 clause 步长不是 28),
//       而 EH 是"数据"不是"代码", 只能靠 cilantro 的同名方法校正。
//
// 用法: fixeh <src(cilantro)> <dst> <out> [--dump]
class FixEh {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: fixeh <src> <dst> <out> [--dump]"); return; }
        var src = ModuleDefMD.Load(a[0]);
        var dst = ModuleDefMD.Load(a[1]);
        bool dump = a.Any(x => x == "--dump");
        var importer = new Importer(dst, ImporterOptions.TryToUseDefs);
        var excType = dst.CorLibTypes.GetTypeRef("System", "Exception");

        var idx = new Dictionary<string, MethodDef>();
        foreach (var t in src.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var k = t.FullName + "::" + m.Name + "/" + SigKey(m.MethodSig);
                if (!idx.ContainsKey(k)) idx[k] = m;
            }

        int fixedBySrc = 0, fixedToEx = 0, already = 0, noSrc = 0, noClause = 0;
        foreach (var t in dst.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var ehs = m.Body.ExceptionHandlers;
                if (ehs.Count == 0) continue;
                var k = t.FullName + "::" + m.Name + "/" + SigKey(m.MethodSig);
                MethodDef sm;
                idx.TryGetValue(k, out sm);
                var sehs = (sm != null && sm.HasBody) ? sm.Body.ExceptionHandlers : null;
                for (int i = 0; i < ehs.Count; i++) {
                    var eh = ehs[i];
                    if (eh.HandlerType != ExceptionHandlerType.Catch) continue;
                    string cur = eh.CatchType == null ? "<null>" : eh.CatchType.FullName;
                    if (Ok(cur)) { already++; continue; }
                    // 1) 从源的同序号子句取
                    if (sehs != null && i < sehs.Count && sehs[i].HandlerType == ExceptionHandlerType.Catch
                        && sehs[i].CatchType != null && Ok(sehs[i].CatchType.FullName)) {
                        eh.CatchType = importer.Import(sehs[i].CatchType);
                        fixedBySrc++;
                        if (dump) Console.WriteLine("[src] " + t.FullName + "::" + m.Name + "  #" + i + "  " + cur + " -> " + eh.CatchType.FullName);
                        continue;
                    }
                    // 2) 兜底: catch(Exception)
                    eh.CatchType = excType;
                    fixedToEx++;
                    if (dump) Console.WriteLine("[exc] " + t.FullName + "::" + m.Name + "  #" + i + "  " + cur + " -> System.Exception");
                }
                if (sehs == null) noSrc++;
                else if (sehs.Count == 0) noClause++;
            }
        }
        Console.WriteLine("[fixeh] bySrc=" + fixedBySrc + " toException=" + fixedToEx + " alreadyOk=" + already
            + " noSrcMethod=" + noSrc + " srcNoClause=" + noClause);
        var wopt = new ModuleWriterOptions(dst);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        dst.Write(a[2], wopt);
        Console.WriteLine("[out] " + a[2]);
    }
    static string SigKey(MethodSig ms) {
        if (ms == null) return "0:";
        var parts = new List<string>();
        foreach (var p in ms.Params) {
            var n = p == null ? "?" : (p.TypeName ?? "?");
            int i = n.LastIndexOf('.');
            if (i >= 0) n = n.Substring(i + 1);
            int j = n.IndexOf('<');
            if (j > 0) n = n.Substring(0, j);
            parts.Add(n);
        }
        return ms.Params.Count + ":" + string.Join(",", parts);
    }
    static bool Ok(string n) {
        if (string.IsNullOrEmpty(n) || n == "<null>") return false;
        if (n == "System.Object" || n == "System.Exception" || n == "System.SystemException") return true;
        var simple = n.Contains("/") ? n.Substring(n.LastIndexOf('/') + 1) : (n.Contains(".") ? n.Substring(n.LastIndexOf('.') + 1) : n);
        if (simple.StartsWith("<>")) return false;
        return simple.Contains("Exception");
    }
}
