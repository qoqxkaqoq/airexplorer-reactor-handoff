// merge2.cs — 精准补体: 只把"dst 里被判定为陷阱的方法"用 src 里的正常体替换
//
// 用法链:
//   depfix      = nb_original(业务真体) + e8runnable 的初始化链真体  -> 修好 cctor, 但还有 112 个业务陷阱
//   cilantro    = 反编译重建版, 那 112 个业务方法在它里面是正常体
//   本工具       = depfix + cilantro 的那 112 个正常体 -> 全部修好
//
// 判据: 只有当 dst 方法体本身是"必然死循环陷阱"、且 src 对应方法体不是陷阱、也不是空桩时才替换。
// 用法: merge2 <src> <dst> <out> [--report-only] [--list]
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class Merge2 {
    static ModuleDef curDst;
    static Importer importer;

    static void Main(string[] a) {
        string srcPath = a[0], dstPath = a[1], outPath = a[2];
        bool reportOnly = a.Contains("--report-only");
        bool listOnly = a.Contains("--list");
        var srcMod = ModuleDefMD.Load(srcPath);
        var dstMod = ModuleDefMD.Load(dstPath);
        curDst = dstMod;
        importer = new Importer(dstMod);

        int n = 0, badSrc = 0, stubSrc = 0, noDst = 0, failed = 0, dstTraps = 0;

        foreach (var st in srcMod.GetTypes()) {
            string tf = st.FullName;
            foreach (var sm in st.Methods) {
                if (!sm.HasBody) continue;
                var dt = FindType(dstMod, tf);
                if (dt == null) { noDst++; continue; }
                var dm = dt.Methods.FirstOrDefault(x => x.Name.String == sm.Name.String &&
                                                        x.MethodSig != null && sm.MethodSig != null &&
                                                        x.MethodSig.ToString() == sm.MethodSig.ToString());
                if (dm == null || !dm.HasBody) { noDst++; continue; }

                var dstInstrs = dm.Body.Instructions;
                if (!IsTrap(dstInstrs, dm.Body.Variables)) continue;
                dstTraps++;

                if (IsStub(sm)) { stubSrc++; continue; }
                if (IsTrap(sm.Body.Instructions, sm.Body.Variables)) { badSrc++; continue; }

                if (listOnly || reportOnly) {
                    Console.WriteLine("[可补] " + tf + "::" + sm.Name + "  src=" + sm.Body.Instructions.Count +
                                      " 指令 -> dst=" + dstInstrs.Count + " 指令(陷阱)");
                    n++;
                    continue;
                }
                try {
                    TransplantBody(dm, sm);
                    RebindRefs(dm, dstMod);
                    n++;
                    Console.WriteLine("[fix] " + tf + "::" + sm.Name + "  " + sm.Body.Instructions.Count + " 指令");
                } catch (Exception ex) {
                    failed++;
                    Console.WriteLine("[fix] 失败 " + sm.Name + ": " + ex.Message);
                }
            }
        }

        Console.WriteLine();
        Console.WriteLine("[merge2] dst 侧陷阱 " + dstTraps + " 个 / 已补 " + n +
                          " / src 也是陷阱 " + badSrc + " / src 是空桩 " + stubSrc + " / 失败 " + failed);
        if (reportOnly || listOnly || n == 0) return;

        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(dstMod);
        wopt.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        dstMod.Write(outPath, wopt);
        Console.WriteLine("[merge2] 写出: " + outPath);
    }

    static bool IsStub(MethodDef m) {
        var ops = m.Body.Instructions.Select(x => x.OpCode.Code).ToList();
        if (ops.Count <= 4 && ops.All(c => c == Code.Nop || c == Code.Ret)) return true;
        if (ops.SequenceEqual(new[] { Code.Ldnull, Code.Ret })) return true;
        if (ops.SequenceEqual(new[] { Code.Ldc_I4_0, Code.Ret })) return true;
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
            else if (op is IMethod im) ni.Operand = ImportSmart(im);
            else if (op is IField fi) ni.Operand = ImportSmart(fi);
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

    static object ImportSmart(object op) {
        var im = op as IMethod;
        if (im != null) {
            var md = im.ResolveMethodDef();
            bool isGlobal = md != null && md.DeclaringType != null && md.DeclaringType.IsGlobalModuleType;
            bool looksGlobal = im.DeclaringType != null && !UTF8String.IsNullOrEmpty(im.DeclaringType.Name) &&
                               im.DeclaringType.Name.String.StartsWith("<Module>");
            if (isGlobal || looksGlobal) {
                var gt = curDst.GlobalType;
                if (gt != null) {
                    var fm = gt.Methods.FirstOrDefault(x => x.Name.String == im.Name.String);
                    if (fm != null) return fm;
                }
            }
            return importer.Import(im);
        }
        if (op is IField fi2) return importer.Import(fi2);
        return op;
    }

    static void RebindRefs(MethodDef dstM, ModuleDef dstMod) {
        int nfix = 0;
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
                if (target != null) { ins.Operand = target; nfix++; }
                else { ins.Operand = new MemberRefUser(dstMod, mr.Name, mr.MethodSig, dstT); nfix++; }
            } else if (ins.Operand is MemberRef fr && fr.FieldSig != null) {
                bool bad;
                try { bad = fr.ResolveFieldDef() == null && fr.Class is TypeRef; } catch { bad = fr.Class is TypeRef; }
                if (!bad) continue;
                var tr = (TypeRef)fr.Class;
                var dstT = dstMod.Find(tr.FullName.Replace('+', '/'), false);
                if (dstT == null) continue;
                var target = dstT.Fields.FirstOrDefault(x => x.Name.String == fr.Name.String);
                if (target != null) { ins.Operand = target; nfix++; }
            }
        }
        if (nfix > 0) Console.WriteLine("        (重绑定 " + nfix + " 处)");
    }

    // ===== 陷阱判定(与 trapscan/trapstub 同一判据) =====
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
                // 终止
            } else {
                nexts.Add(idx + 1);
            }
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
