using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// verifyil — 栈深模拟验证器: 对每个方法 walk IL, 检查 CFG 汇合点栈深一致性
// (InvalidProgramException 的主流成因), 输出非法方法清单。
// 用法: verifyil <exe> [--max N]
class VerifyIl {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string dumpTok = a.Length > 2 && a[1] == "--dump" ? a[2] : null;
        _dumpTokStatic = dumpTok;
        int bad = 0, ok = 0, noWalk = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody || m.Body.Instructions.Count == 0) continue;
                if (dumpTok != null && m.MDToken.Raw.ToString("X8") != dumpTok) continue;
                if (dumpTok != null) {
                    Console.WriteLine("[dump] " + m.MDToken.Raw.ToString("X8") + " instrs=" + m.Body.Instructions.Count + " maxstack=" + m.Body.MaxStack + " eh=" + m.Body.ExceptionHandlers.Count);
                    foreach (var ins in m.Body.Instructions) Console.WriteLine("   @" + ins.Offset.ToString("X4") + " " + ins.OpCode + " " + (ins.Operand == null ? "" : ins.Operand.ToString()));
                }
                string msg;
                try { msg = Verify(m.Body); }
                catch (Exception ex) { msg = "walk-ex:" + ex.Message; }
                if (msg == null) ok++;
                else { bad++; if (bad <= 60) Console.WriteLine("[BAD] " + m.MDToken.Raw.ToString("X8") + " " + t.FullName + "::" + m.Name + "  " + msg); }
            }
        }
        Console.WriteLine("[verifyil] ok=" + ok + " bad=" + bad);
    }

    static void logStep(string m) { Console.WriteLine("    [walk] " + m); }
    static string _dumpTokStatic;
    static bool Trace => _dumpTokStatic != null;
    // 返回 null=合法, 否则问题描述
    static string Verify(CilBody body) {
        var instrs = body.Instructions;
        int n = instrs.Count;
        // 每条指令的栈深; -1 = 未定
        var depth = new int[n];
        for (int i = 0; i < n; i++) depth[i] = -1;
        var work = new Stack<int>();
        work.Push(0);
        depth[0] = 0;
        var ehStarts = new HashSet<int>();      // handler/filter 入口(栈清零)
        foreach (var eh in body.ExceptionHandlers) {
            if (eh.HandlerStart != null) ehStarts.Add(instrs.IndexOf(eh.HandlerStart));
            if (eh.FilterStart != null) ehStarts.Add(instrs.IndexOf(eh.FilterStart));
        }
        bool trace = _dumpTokStatic != null;
        while (work.Count > 0) {
            int idx = work.Pop();
            int d = depth[idx];
            var ins = instrs[idx];
            if (trace) logStep("pop #" + idx + " @" + ins.Offset.ToString("X4") + " " + ins.OpCode + " d=" + d);
            int push = 0, pop = 0;
            try {
                pop = Pops(ins);
                push = Pushes(ins);
            } catch (Exception ex) { return "op-eval @" + ins.Offset.ToString("X4") + " " + ins.OpCode + ": " + ex.Message; }
            if (trace) logStep("  pops=" + pop + " pushes=" + push + " nd=" + (d - pop + push));
            if (d < pop) return "stack-underflow @" + ins.Offset.ToString("X4") + " " + ins.OpCode;
            int nd = d - pop + push;

            var nexts = new List<int>();
            if (ins.OpCode.OperandType == OperandType.InlineBrTarget || ins.OpCode.OperandType == OperandType.ShortInlineBrTarget) {
                var t = ins.Operand as Instruction;
                if (t == null) return "null-br @" + ins.Offset.ToString("X4");
                nexts.Add(instrs.IndexOf(t));
                if (ins.OpCode.Code != Code.Br && ins.OpCode.Code != Code.Br_S
                    && ins.OpCode.Code != Code.Leave && ins.OpCode.Code != Code.Leave_S) nexts.Add(idx + 1);
            } else if (ins.OpCode.OperandType == OperandType.InlineSwitch) {
                var ts = ins.Operand as Instruction[];
                if (ts == null) return "null-switch @" + ins.Offset.ToString("X4");
                foreach (var t in ts) nexts.Add(instrs.IndexOf(t));
                nexts.Add(idx + 1);
            } else if (ins.OpCode.FlowControl == FlowControl.Return || ins.OpCode.FlowControl == FlowControl.Throw) {
                // 终止
            } else {
                nexts.Add(idx + 1);
            }
            foreach (var nx in nexts) {
                if (nx < 0 || nx >= n) return "branch-out-of-range @" + ins.Offset.ToString("X4") + " -> #" + nx;
                // EH handler/filter 入口: 异常进入时栈被清空, 栈深独立起算且不与普通汇合比对
                bool isEhEntry = ehStarts.Contains(nx);
                if (depth[nx] == -1) { depth[nx] = isEhEntry ? 0 : nd; work.Push(nx); }
                else if (!isEhEntry && depth[nx] != nd) return "stack-merge-mismatch @" + ins.Offset.ToString("X4") + " -> #" + nx + " (" + nd + " vs " + depth[nx] + ") " + ins.OpCode;
            }
        }
        return null;
    }

    static dnlib.DotNet.MethodSig Sig(Instruction ins) {
        try {
            if (ins.Operand is MethodSpec ms) {
                if (ms.Method is MethodDef md2 && md2.MethodSig != null) return md2.MethodSig;
                if (ms.Method is MemberRef mr2 && mr2.MethodSig != null) return mr2.MethodSig;
            }
            if (ins.Operand is MemberRef mr && mr.MethodSig != null) return mr.MethodSig;
            if (ins.Operand is IMethod im && im.MethodSig != null) return im.MethodSig;
        } catch { }
        return null;
    }

    static int Pops(Instruction ins) {
        // call 家族: 签名感知(参数 + instance this)
        if (ins.OpCode.Code == Code.Call || ins.OpCode.Code == Code.Callvirt || ins.OpCode.Code == Code.Calli) {
            var sig = Sig(ins);
            if (sig != null) {
                int p = sig.Params.Count;
                if (sig.ExplicitThis) p += 1;
                else if (sig.ImplicitThis && ins.OpCode.Code != Code.Call) p += 1;
                return p;
            }
            return 0;
        }
        var sb = ins.OpCode.StackBehaviourPop.ToString();
        switch (sb) {
            case "Pop0": return 0;
            case "Pop1": case "PopI": case "PopI8": case "PopR4": case "PopR8": case "PopRef": case "Popi": case "Popref": return 1;
            case "Varpop": return 0; // call/ret 简化: call 参数无法精确(需签名), call 用 0 不影响汇合正确性? 会影响!
            case "Pop1_pop1": case "PopI_pop1": case "PopI_popI": case "PopRef_popI": case "PopRef_pop1": case "Popi_pop1": case "Popi_popi": case "Popref_pop1": case "Popref_popi": return 2;
            case "PopI_popI8": case "PopI_popR4": case "PopI_popR8": case "Popi_popi8": case "Popi_popr4": case "Popi_popr8": return 2;
            case "PopI_popI_popI": case "PopI_pop1_pop1": case "PopRef_popI_popI": case "PopRef_popI_popI8":
            case "PopRef_popI_popR4": case "PopRef_popI_popR8": case "PopRef_popI_popRef":
            case "Popi_popi_popi": case "Popi_pop1_pop1": case "Popref_popi_popi": case "Popref_popi_popi8":
            case "Popref_popi_popr4": case "Popref_popi_popr8": case "Popref_popi_popref": case "Popref_popi_pop1": return 3;
            case "PopAll": return 0;
            default: Console.WriteLine("[unk-pop] " + sb); return 0;
        }
    }
    static int Pushes(Instruction ins) {
        if (ins.OpCode.Code == Code.Call || ins.OpCode.Code == Code.Callvirt || ins.OpCode.Code == Code.Calli) {
            var sig = Sig(ins);
            if (sig != null) return sig.RetType.FullName == "System.Void" ? 0 : 1;
            return 0;
        }
        var sb = ins.OpCode.StackBehaviourPush.ToString();
        switch (sb) {
            case "Push0": return 0;
            case "Push1": case "PushI": case "PushI8": case "PushR4": case "PushR8": case "PushRef": case "Pushi": case "Pushi8": case "Pushr4": case "Pushr8": case "Pushref": return 1;
            case "Push1_push1": return 2;
            case "Varpush": return 0;
            default: Console.WriteLine("[unk-push] " + sb); return 0;
        }
    }
}
