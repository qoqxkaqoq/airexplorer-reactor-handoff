// stackchk.cs — 控制流感知的 IL 栈验证器, 找出会被 CLR 判定为 InvalidProgram 的方法
//
// 本样本的实际故障: 回植真体后启动即崩, 退出码 0xE0434352, 堆栈显示
//   InvalidProgramException at VerifyCombinedStateRequest(), called by DefineEfficientProfiler()
// InvalidProgramException 的两个最常见来源:
//   1) 方法头 MaxStack 小于实际需要的栈深度
//   2) 某条路径上栈下溢/类型错配(本工具先抓 1, 以及路径上的栈深不一致)
// 逐条线性扫描会误报(分支汇合处栈深不同是合法的), 所以这里做基本块级的数据流传播。
//
// 用法: stackchk <file.exe> [--fix <out.exe>] [--top N]
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class StackChk {
    static void Main(string[] a) {
        string file = a[0];
        bool fix = a.Contains("--fix");
        string outPath = null;
        int topN = 40;
        for (int i = 1; i < a.Length; i++) {
            if (a[i] == "--fix" && i + 1 < a.Length) outPath = a[i + 1];
            if (a[i] == "--top" && i + 1 < a.Length) int.TryParse(a[i + 1], out topN);
        }
        var mod = ModuleDefMD.Load(file);

        var bad = new List<Tuple<int, string, int, int>>();   // (need, name, il, declaredMax)
        int total = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                total++;
                var r = Analyze(m);
                if (r == null) continue;
                bad.Add(Tuple.Create(r.Item1, t.FullName + "::" + m.Name, m.Body.Instructions.Count, r.Item2));
            }
        }

        Console.WriteLine("方法(有体)=" + total);
        Console.WriteLine("=== MaxStack 不足的方法: " + bad.Count + " ===");
        foreach (var b in bad.OrderByDescending(x => x.Item1).Take(topN))
            Console.WriteLine(string.Format("  需要{0,-5} 声明{1,-4} il={2,-6} {3}", b.Item1, b.Item4, b.Item3, b.Item2));
        if (bad.Count > topN) Console.WriteLine("  ...共 " + bad.Count + " 个");

        if (!fix || bad.Count == 0) return;
        int fixedN = 0;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var r = Analyze(m);
                if (r == null) continue;
                m.Body.MaxStack = (ushort)Math.Min(65535, r.Item1 + 8);
                m.Body.KeepOldMaxStack = true;
                fixedN++;
            }
        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, wopt);
        Console.WriteLine("[stackchk] 修正 " + fixedN + " 个方法的 MaxStack -> " + outPath);
    }

    // 返回 (实际需要的最大栈深, 声明的 MaxStack); 不需要修则 null
    static Tuple<int, int> Analyze(MethodDef m) {
        var instrs = m.Body.Instructions;
        if (instrs.Count == 0) return null;
        int declared = m.Body.MaxStack;

        // 入口栈深 0; 各异常处理入口: catch/filter 为 1(异常对象), finally/fault 为 0
        var entryDepth = new Dictionary<int, int>();
        entryDepth[0] = 0;
        foreach (var eh in m.Body.ExceptionHandlers) {
            if (eh.HandlerStart != null) {
                int hi = instrs.IndexOf(eh.HandlerStart);
                if (hi >= 0) {
                    int d = (eh.HandlerType == ExceptionHandlerType.Catch || eh.HandlerType == ExceptionHandlerType.Filter) ? 1 : 0;
                    if (!entryDepth.ContainsKey(hi)) entryDepth[hi] = d;
                }
            }
            if (eh.FilterStart != null) {
                int fi = instrs.IndexOf(eh.FilterStart);
                if (fi >= 0 && !entryDepth.ContainsKey(fi)) entryDepth[fi] = 1;
            }
        }
        // 分支目标不预设栈深, 由传播得到

        var work = new Queue<int>();
        var visited = new Dictionary<int, int>();   // 指令索引 -> 入口栈深
        foreach (var kv in entryDepth) { visited[kv.Key] = kv.Value; work.Enqueue(kv.Key); }

        int maxDepth = 0;
        bool conflict = false;

        while (work.Count > 0) {
            int idx = work.Dequeue();
            int depth = visited[idx];
            for (int i = idx; i < instrs.Count; i++) {
                var ins = instrs[i];
                // 如果某条跳转边给了不同的入口深度, 用较大的(保守), 并标记冲突
                if (i != idx && visited.ContainsKey(i)) {
                    if (visited[i] > depth) { depth = visited[i]; }
                    else if (visited[i] < depth) { visited[i] = depth; }
                }
                if (depth < 0) { conflict = true; depth = 0; }
                if (depth > maxDepth) maxDepth = depth;

                var op = ins.OpCode;
                int pop = PopCount(ins);
                int push = PushCount(ins);
                if (pop > depth) conflict = true;
                int nd = depth - pop + push;
                if (nd > maxDepth) maxDepth = nd;

                // 后继
                var nexts = new List<int>();
                if (op.Code == Code.Switch) {
                    foreach (var tg in (Instruction[])ins.Operand) {
                        int ti = instrs.IndexOf(tg);
                        if (ti >= 0) nexts.Add(ti);
                    }
                } else if (ins.Operand is Instruction brt) {
                    int ti = instrs.IndexOf(brt);
                    if (ti >= 0) nexts.Add(ti);
                    if (op.FlowControl == FlowControl.Cond_Branch || op.Code == Code.Leave || op.Code == Code.Leave_S)
                        nexts.Add(i + 1);
                    // br 无 fallthrough
                } else if (op.FlowControl == FlowControl.Return || op.Code == Code.Rethrow ||
                           op.Code == Code.Endfinally || op.Code == Code.Endfilter) {
                    // 终止
                } else {
                    nexts.Add(i + 1);
                }

                foreach (int n in nexts) {
                    if (n < 0 || n >= instrs.Count) continue;
                    if (!visited.ContainsKey(n)) { visited[n] = nd; work.Enqueue(n); }
                    else if (visited[n] != nd) {
                        // 汇合处深度不同: 取大者, 并重扫这条路径
                        int bigger = Math.Max(visited[n], nd);
                        if (bigger != visited[n]) { visited[n] = bigger; work.Enqueue(n); }
                        else { depth = bigger; }
                    }
                }

                if (op.FlowControl == FlowControl.Return || op.Code == Code.Rethrow ||
                    op.Code == Code.Endfinally || op.Code == Code.Endfilter ||
                    op.FlowControl == FlowControl.Branch || op.Code == Code.Leave || op.Code == Code.Endfilter)
                    break;
                if (op.FlowControl == FlowControl.Cond_Branch && false) break;
                depth = nd;
                if (op.FlowControl == FlowControl.Branch) break;
            }
        }

        if (maxDepth > declared || conflict) return Tuple.Create(maxDepth, declared);
        return null;
    }

    static int PopCount(Instruction ins) {
        // 先处理变长的: 调用类指令靠签名算
        var code = ins.OpCode.Code;
        if (code == Code.Call || code == Code.Callvirt || code == Code.Newobj || code == Code.Calli) {
            var ms = ins.Operand as IMethod;
            if (ms != null) {
                int n = ms.MethodSig == null ? 0 : ms.MethodSig.Params.Count;
                if (ms.MethodSig != null && ms.MethodSig.HasThis && code != Code.Newobj) { /* HasThis 已在 Callvirt/实例 call 中 */ }
                var mr = ms as MemberRef;
                var md = ms as MethodDef;
                bool hasThis = false;
                if (md != null) hasThis = md.MethodSig != null && md.MethodSig.HasThis;
                else if (mr != null) hasThis = mr.MethodSig != null && mr.MethodSig.HasThis;
                else if (ms.MethodSig != null) hasThis = ms.MethodSig.HasThis;
                if (code == Code.Newobj) return n;
                if (hasThis) n++;
                if (code == Code.Calli) n++;      // 函数指针
                return n;
            }
            return 0;
        }
        if (code == Code.Ret) return 0;   // ret 的栈行为在 PushCount/终止判断里处理
        return PopMap(ins.OpCode.StackBehaviourPop.ToString());
    }

    static readonly Dictionary<string, int> PopCounts = new Dictionary<string, int> {
        {"Pop0",0},{"Pop1",1},{"PopI",1},{"PopRef",1},{"Pop1_pop1",2},{"PopI_pop1",2},
        {"PopI_popI",2},{"PopI_popI8",2},{"PopI_popR4",2},{"PopI_popR8",2},{"PopI_popI_popI",3},
        {"PopI_pop1_pop1",3},{"PopRef_pop1",2},{"PopRef_popI",2},{"PopRef_popI_popI",3},
        {"PopRef_popI_popI8",3},{"PopRef_popI_popR4",3},{"PopRef_popI_popR8",3},
        {"PopRef_popI_popRef",3},{"Varpop",0},{"PopAll",0},
    };
    static int PopMap(string n) {
        int v;
        return PopCounts.TryGetValue(n, out v) ? v : 0;
    }
    static readonly Dictionary<string, int> PushCounts = new Dictionary<string, int> {
        {"Push0",0},{"Push1",1},{"PushI",1},{"PushI8",1},{"PushR4",1},{"PushR8",1},
        {"PushRef",1},{"Push1_push1",2},{"Varpush",0},
    };
    static int PushMap(string n) {
        int v;
        return PushCounts.TryGetValue(n, out v) ? v : 0;
    }

    static int PushCount(Instruction ins) {
        var code = ins.OpCode.Code;
        if (code == Code.Call || code == Code.Callvirt || code == Code.Calli) {
            var ms = ins.Operand as IMethod;
            if (ms != null && ms.MethodSig != null && ms.MethodSig.RetType != null)
                return ms.MethodSig.RetType.FullName == "System.Void" ? 0 : 1;
            return 0;
        }
        if (code == Code.Newobj) return 1;
        if (code == Code.Ret) return 0;
        return PushMap(ins.OpCode.StackBehaviourPush.ToString());
    }
}
