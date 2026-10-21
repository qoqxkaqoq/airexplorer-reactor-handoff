// merge3.cs — 用 dst(Krypton 产物) 里被桩化成 ret 的方法, 回填 src(depfix2) 的真体
//
// 两条产物各有缺口, 正好互补:
//   Krypton 产物: 0 陷阱 / 去平坦化 / 保护运行时已中和 / cctor 已清空,
//                 但它把还原不了的方法桩化成了 `ret`(例如 AggregateAdaptableCalc
//                 从 16663 指令变成 1 条), 这些是纯功能缺失。
//   depfix2     : 业务方法体是 nb_slayer dump 的真体(且已补掉 129 个陷阱),
//                 但残留 Reactor 保护运行时、启动即 InvalidProgramException。
// 本工具只回填"dst 是极简桩 且 src 是真体"的方法, 且**跳过有意置空的目标**:
//   <Module>::.cctor 与 JIT hook(6 参返回 uint)——那两个是 Krypton 专门中和掉的, 不能补回来。
//
// 用法: merge3 <src=depfix2> <dst=krypton> <out> [--list]
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class Merge3 {
    static ModuleDef curDst;
    static Importer importer;

    static void Main(string[] a) {
        string srcPath = a[0], dstPath = a[1], outPath = a[2];
        bool list = a.Contains("--list");
        var src = ModuleDefMD.Load(srcPath);
        var dst = ModuleDefMD.Load(dstPath);
        curDst = dst;
        importer = new Importer(dst);

        int filled = 0, skippedIntentional = 0, noSrc = 0, failed = 0;
        foreach (var st in src.GetTypes()) {
            string tf = st.FullName;
            foreach (var sm in st.Methods) {
                if (!sm.HasBody) continue;
                var dt = FindType(dst, tf);
                if (dt == null) { noSrc++; continue; }
                var dm = dt.Methods.FirstOrDefault(x => x.Name.String == sm.Name.String &&
                                                        x.MethodSig != null && sm.MethodSig != null &&
                                                        x.MethodSig.ToString() == sm.MethodSig.ToString());
                if (dm == null || !dm.HasBody) { noSrc++; continue; }

                // 只补 dst 侧是"极简桩"的
                if (!IsStub(dm)) continue;
                // 有意置空的目标不补
                if (IsIntentionalEmpty(dm)) { skippedIntentional++; continue; }
                // src 侧必须明显更完整, 且不能是陷阱
                if (sm.Body.Instructions.Count <= 4) continue;
                if (IsTrap(sm.Body.Instructions, sm.Body.Variables)) continue;

                if (list) {
                    Console.WriteLine("[可补] " + tf + "::" + sm.Name + "  src=" + sm.Body.Instructions.Count +
                                      " -> dst=" + dm.Body.Instructions.Count);
                    filled++;
                    continue;
                }
                try { TransplantBody(dm, sm); RebindRefs(dm, dst); filled++; }
                catch (Exception ex) { failed++; Console.WriteLine("[补] 失败 " + sm.Name + ": " + ex.Message); }
            }
        }

        Console.WriteLine();
        Console.WriteLine("[merge3] 回填 " + filled + " / 有意置空跳过 " + skippedIntentional +
                          " / dst 无此成员 " + noSrc + " / 失败 " + failed);
        if (list || filled == 0) return;
        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(dst);
        wopt.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        dst.Write(outPath, wopt);
        Console.WriteLine("[merge3] 写出: " + outPath);
    }

    static bool IsStub(MethodDef m) {
        var ops = m.Body.Instructions.Select(x => x.OpCode.Code).ToList();
        if (ops.Count <= 2 && ops.All(c => c == Code.Nop || c == Code.Ret)) return true;
        if (ops.SequenceEqual(new[] { Code.Ldnull, Code.Ret })) return true;
        if (ops.SequenceEqual(new[] { Code.Ldc_I4_0, Code.Ret })) return true;
        return false;
    }

    // <Module>::.cctor 和 DNR 的 JIT hook 是 Krypton 专门中和掉的, 不能补回来
    static bool IsIntentionalEmpty(MethodDef m) {
        if (m.DeclaringType != null && m.DeclaringType.IsGlobalModuleType && m.Name.String == ".cctor") return true;
        var sig = m.MethodSig;
        if (sig != null && sig.Params.Count == 6 && sig.RetType.FullName == "System.UInt32") return true;
        return false;
    }

    static TypeDef FindType(ModuleDef mod, string full) {
        foreach (var t in mod.GetTypes())
            if (t.FullName == full) return t;
        return null;
    }

    static void TransplantBody(MethodDef dst, MethodDef src) {
        var sb = src.Body;
        var body = new CilBody();
        body.InitLocals = sb.InitLocals;
        body.KeepOldMaxStack = true;
        body.MaxStack = sb.MaxStack;
        if (sb.Instructions.Count > 60 && sb.MaxStack < 128) body.MaxStack = 512;

        var localMap = new Dictionary<Local, Local>();
        foreach (var l in sb.Variables) {
            var nl = new Local(importer.Import(l.Type));
            body.Variables.Add(nl);
            localMap[l] = nl;
        }
        var instrMap = new Dictionary<Instruction, Instruction>();
        foreach (var i in sb.Instructions) {
            var ni = new Instruction(i.OpCode);
            instrMap[i] = ni;
            body.Instructions.Add(ni);
        }
        foreach (var i in sb.Instructions) {
            var ni = instrMap[i];
            var op = i.Operand;
            if (op == null) continue;
            if (op is Instruction t) ni.Operand = instrMap[t];
            else if (op is Instruction[] ts) {
                var arr = new Instruction[ts.Length];
                for (int k = 0; k < ts.Length; k++) arr[k] = instrMap[ts[k]];
                ni.Operand = arr;
            } else if (op is Local l2) ni.Operand = localMap[l2];
            else if (op is ITypeDefOrRef tdr) ni.Operand = importer.Import(tdr);
            else if (op is IMethod im) ni.Operand = importer.Import(im);
            else if (op is IField fi) ni.Operand = importer.Import(fi);
            else if (op is TypeSig sig) ni.Operand = importer.Import(sig);
            else ni.Operand = op;
        }
        foreach (var eh in sb.ExceptionHandlers) {
            var neh = new ExceptionHandler(eh.HandlerType);
            if (eh.TryStart != null) neh.TryStart = instrMap[eh.TryStart];
            if (eh.TryEnd != null) neh.TryEnd = instrMap[eh.TryEnd];
            if (eh.HandlerStart != null) neh.HandlerStart = instrMap[eh.HandlerStart];
            if (eh.HandlerEnd != null) neh.HandlerEnd = instrMap[eh.HandlerEnd];
            if (eh.FilterStart != null) neh.FilterStart = instrMap[eh.FilterStart];
            if (eh.CatchType != null) neh.CatchType = importer.Import(eh.CatchType);
            body.ExceptionHandlers.Add(neh);
        }
        dst.Body = body;
    }

    static void RebindRefs(MethodDef dstM, ModuleDef dstMod) {
        foreach (var ins in dstM.Body.Instructions) {
            if (ins.Operand is MemberRef mr && mr.MethodSig != null) {
                bool bad;
                try { bad = mr.ResolveMethodDef() == null && mr.Class is TypeRef; } catch { bad = mr.Class is TypeRef; }
                if (!bad) continue;
                var tr = (TypeRef)mr.Class;
                var dstT = dstMod.Find(tr.FullName.Replace('+', '/'), false);
                if (dstT == null) continue;
                string rsig = mr.MethodSig.ToString();
                var target = dstT.Methods.FirstOrDefault(x => x.Name.String == mr.Name.String &&
                                                              x.MethodSig != null && x.MethodSig.ToString() == rsig);
                if (target != null) ins.Operand = target;
                else ins.Operand = new MemberRefUser(dstMod, mr.Name, mr.MethodSig, dstT);
            }
        }
    }

    // ===== 陷阱判定(与 trapscan 同判据) =====
    static bool IsTrap(IList<Instruction> instrs, IList<Local> vars) {
        var off2idx = new Dictionary<uint, int>();
        for (int i = 0; i < instrs.Count; i++) off2idx[instrs[i].Offset] = i;
        foreach (var sw in instrs.Where(x => x.OpCode.Code == Code.Switch)) {
            int i = instrs.IndexOf(sw);
            int loopHead = -1;
            for (int k = i - 1; k >= 0 && k >= i - 8; k--) {
                var ins = instrs[k];
                if (ins.IsLdloc()) { loopHead = k; break; }
                if (ins.OpCode.FlowControl != FlowControl.Next) break;
            }
            if (loopHead < 0) continue;
            var idxLocal = instrs[loopHead].GetLocal(vars);
            if (idxLocal == null) continue;
            if (instrs.Count(x => x.IsStloc() && x.GetLocal(vars) == idxLocal) > 1) continue;
            var targets = sw.Operand as Instruction[];
            if (targets == null) continue;
            foreach (var tg in targets.Distinct()) {
                if (!off2idx.TryGetValue(tg.Offset, out int si)) continue;
                if (Reaches(instrs, off2idx, si, loopHead, idxLocal, vars)) return true;
            }
        }
        return false;
    }

    static bool Reaches(IList<Instruction> instrs, Dictionary<uint, int> off2idx, int startIdx,
                        int loopHead, Local idxLocal, IList<Local> vars) {
        var seen = new HashSet<int>();
        var q = new Queue<int>();
        q.Enqueue(startIdx); seen.Add(startIdx);
        while (q.Count > 0) {
            int idx = q.Dequeue();
            var ins = instrs[idx];
            bool hit = false;
            var nexts = new List<int>();
            if (ins.OpCode.Code == Code.Switch) {
                foreach (var tg in (Instruction[])ins.Operand)
                    if (off2idx.TryGetValue(tg.Offset, out int ti)) nexts.Add(ti);
            } else if (ins.Operand is Instruction brt) {
                if (off2idx.TryGetValue(brt.Offset, out int ti)) nexts.Add(ti);
                if (ins.OpCode.FlowControl == FlowControl.Cond_Branch) nexts.Add(idx + 1);
            } else if (ins.OpCode.Code == Code.Ret || ins.OpCode.Code == Code.Throw ||
                       ins.OpCode.Code == Code.Rethrow || ins.OpCode.Code == Code.Endfinally) {
            } else nexts.Add(idx + 1);
            foreach (int n in nexts) {
                if (n == loopHead) hit = true;
                if (n < 0 || n >= instrs.Count || !seen.Add(n)) continue;
                var ni = instrs[n];
                if (ni.IsStloc() && ni.GetLocal(vars) == idxLocal) continue;
                q.Enqueue(n);
            }
            if (hit) return true;
        }
        return false;
    }
}
