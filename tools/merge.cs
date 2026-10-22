// merge — 以原版为骨架, 把「被掏空(nop;nop;nop;ret)」的方法体从各候选版本中择优回填
// 用法: merge <base.exe> <out.exe> <cand1> [cand2 ...]
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class Merge {
    static ModuleDef dst;
    static int Main(string[] a) {
        var baseMod = ModuleDefMD.Load(a[0]);
        dst = baseMod;
        var cands = new List<ModuleDef>();
        foreach (var c in a.Skip(2)) cands.Add(ModuleDefMD.Load(c));
        var importer = new Importer(baseMod);

        int hollow = 0, filled = 0, still = 0;
        var unresolved = new Dictionary<string, int>();
        foreach (var t in baseMod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                if (!IsHollow(m.Body.Instructions)) continue;
                hollow++;
                MethodDef best = null; int bestN = 0;
                foreach (var cm in cands) {
                    var ct = cm.Find(t.FullName, false);
                    if (ct == null) continue;
                    var sm = ct.Methods.FirstOrDefault(x => x.Name == m.Name && x.HasBody && Sig(x) == Sig(m));
                    if (sm == null) continue;
                    int n = sm.Body.Instructions.Count;
                    if (IsHollow(sm.Body.Instructions) || n <= 4) continue;
                    if (n > bestN) { bestN = n; best = sm; }
                }
                if (best == null) { still++; Add(unresolved, t.FullName); continue; }
                try { Transplant(m, best, importer); filled++; }
                catch (Exception e) { still++; Add(unresolved, t.FullName + " [" + e.Message + "]"); }
            }
        }
        Console.WriteLine("hollow=" + hollow + " filled=" + filled + " stillHollow=" + still);
        foreach (var kv in unresolved.OrderByDescending(k => k.Value).Take(12))
            Console.WriteLine("  unresolved " + kv.Value + "  " + kv.Key);

        var opts = new ModuleWriterOptions(baseMod);
        opts.Logger = DummyLogger.NoThrowInstance;
        baseMod.Write(a[1], opts);
        Console.WriteLine("wrote " + a[1]);
        return 0;
    }

    static void Add(Dictionary<string, int> d, string k) { d[k] = d.TryGetValue(k, out var c) ? c + 1 : 1; }

    static string Sig(MethodDef m) {
        if (m.MethodSig == null) return "?";
        return m.MethodSig.RetType.FullName + "(" + string.Join(",", m.MethodSig.Params.Select(p => p.FullName)) + ")" + (m.IsStatic ? "S" : "I");
    }

    public static bool IsHollow(IList<Instruction> ins) {
        if (ins.Count > 4) return false;
        bool ret = false;
        foreach (var i in ins) {
            if (i.OpCode.Code == Code.Ret) ret = true;
            else if (i.OpCode.Code != Code.Nop) return false;
        }
        return ret;
    }

    static void Transplant(MethodDef d, MethodDef s, Importer imp) {
        var sb = s.Body;
        var body = new CilBody();
        body.InitLocals = sb.InitLocals;
        body.MaxStack = Math.Max(sb.MaxStack, (ushort)64);
        var lmap = new Dictionary<Local, Local>();
        foreach (var l in sb.Variables) {
            var nl = new Local(imp.Import(l.Type));
            body.Variables.Add(nl);
            lmap[l] = nl;
        }
        var imap = new Dictionary<Instruction, Instruction>();
        foreach (var i in sb.Instructions) { var ni = new Instruction(i.OpCode); imap[i] = ni; body.Instructions.Add(ni); }
        foreach (var i in sb.Instructions) {
            var ni = imap[i]; var op = i.Operand; if (op == null) continue;
            if (op is Instruction t) ni.Operand = imap[t];
            else if (op is Instruction[] ts) { var arr = new Instruction[ts.Length]; for (int k = 0; k < ts.Length; k++) arr[k] = imap[ts[k]]; ni.Operand = arr; }
            else if (op is Local l2) ni.Operand = lmap[l2];
            else if (op is Parameter p) ni.Operand = p;
            else if (op is ITypeDefOrRef tdr) ni.Operand = imp.Import(tdr);
            else if (op is IMethod im) ni.Operand = imp.Import(im);
            else if (op is IField fi) ni.Operand = imp.Import(fi);
            else if (op is TypeSig sig) ni.Operand = imp.Import(sig);
            else ni.Operand = op;
        }
        foreach (var eh in sb.ExceptionHandlers) {
            var neh = new ExceptionHandler(eh.HandlerType);
            neh.TryStart = imap[eh.TryStart];
            neh.TryEnd = eh.TryEnd == null ? null : imap[eh.TryEnd];
            neh.HandlerStart = imap[eh.HandlerStart];
            neh.HandlerEnd = eh.HandlerEnd == null ? null : imap[eh.HandlerEnd];
            if (eh.FilterStart != null) neh.FilterStart = imap[eh.FilterStart];
            neh.CatchType = eh.CatchType == null ? null : imp.Import(eh.CatchType);
            body.ExceptionHandlers.Add(neh);
        }
        d.Body = body;
    }
}
