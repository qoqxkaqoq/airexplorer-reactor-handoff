using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// fixcatch <in.exe> <out.exe> — catch 类型非 Exception 派生 → 替换 System.Object
class FixCatch {
    static bool IsExc(ITypeDefOrRef t) {
        if (t == null) return true;
        var cur = t.ResolveTypeDef();
        int hops = 0;
        while (cur != null && hops++ < 30) {
            if (cur.FullName == "System.Exception") return true;
            var bt = cur.BaseType;
            if (bt == null) return false;                       // 链走到顶(object) 无 Exception
            if (bt.FullName == "System.Object") return false;   // object 是终点且无 Exception
            try { cur = bt.ResolveTypeDef(); if (cur == null) return false; } catch { return false; }
        }
        return false;
    }
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        int fixedN = 0, ok = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var eh in m.Body.ExceptionHandlers) {
                    if (eh.HandlerType != ExceptionHandlerType.Catch) continue;
                    if (IsExc(eh.CatchType)) { ok++; continue; }
                    eh.CatchType = mod.CorLibTypes.Object.TypeDefOrRef;
                    fixedN++;
                }
            }
        }
        Console.WriteLine("[fixcatch] ok=" + ok + " fixed->System.Object=" + fixedN);
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], opts);
        Console.WriteLine("[fixcatch] wrote " + a[1]);
    }
}
