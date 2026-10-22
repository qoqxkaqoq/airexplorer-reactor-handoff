// trapstub.cs — 把"必死循环陷阱体"替换成最小桩,让程序至少不会被卡死
//
// 陷阱体是反篡改改写过的: 状态变量的写入被换成垃圾变量的写入,方法一旦被调用就无限循环。
// 真体暂时拿不到的情况下,先换成桩: 卡死(进程存活无窗口) -> 功能缺失(可能能出 UI)。
// 桩的生成按返回类型: void->ret, 引用类型->ldnull;ret, 整数/布尔->ldc.i4.0;ret。
//
// 用法: trapstub <in.exe> <out.exe> [minIl=60] [--report-only]
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class TrapStub {
    static void Main(string[] a) {
        string inPath = a[0], outPath = a[1];
        int minIl = 60;
        bool reportOnly = a.Contains("--report-only");
        for (int i = 2; i < a.Length; i++)
            if (int.TryParse(a[i], out int v)) minIl = v;

        var mod = ModuleDefMD.Load(inPath);
        var traps = new List<MethodDef>();

        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var instrs = m.Body.Instructions;
                if (instrs.Count < minIl) continue;
                if (IsTrap(instrs, m.Body.Variables)) traps.Add(m);
            }
        }

        Console.WriteLine("[trapstub] 检出陷阱体 " + traps.Count + " 个");
        int done = 0;
        foreach (var m in traps) {
            var sig = m.MethodSig;
            string rt = sig == null ? "System.Void" : sig.RetType.FullName;
            var body = new CilBody();
            if (rt == "System.Void") {
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            } else if (rt == "System.Int32" || rt == "System.Boolean" || rt == "System.UInt32" ||
                       rt == "System.Int64" || rt == "System.UInt64" || rt == "System.Byte" ||
                       rt == "System.Char" || rt == "System.Int16" || rt == "System.UInt16" ||
                       rt == "System.SByte" || rt == "System.Single" || rt == "System.Double") {
                body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
                if (rt == "System.Int64" || rt == "System.UInt64") body.Instructions.Add(Instruction.Create(OpCodes.Conv_I8));
                if (rt == "System.Single") body.Instructions.Add(Instruction.Create(OpCodes.Conv_R4));
                if (rt == "System.Double") body.Instructions.Add(Instruction.Create(OpCodes.Conv_R8));
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            } else {
                body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            }
            body.MaxStack = 2;
            m.Body = body;
            done++;
            Console.WriteLine("[trapstub] 桩化 " + m.DeclaringType.FullName + "::" + m.Name + "  (返回 " + rt + ")");
        }

        if (reportOnly || done == 0) { Console.WriteLine(reportOnly ? "[trapstub] 仅报告,不写盘" : "[trapstub] 无改动"); return; }
        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        // PreserveAll 很关键: dnlib 默认写入会重排元数据行号(RID), 而 Reactor 的
            // VM/解密 blob 里存的是**原始** token, 运行时靠 ResolveMethod/ResolveField 解析。
            // 一旦重排, 就会解析到错误成员并触发 anti-tamper 异常(AutoReaktor v3 记的头号坑)。
            wopt.MetadataOptions.Flags = dnlib.DotNet.Writer.MetadataFlags.PreserveAll
                                       | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, wopt);
        Console.WriteLine("[trapstub] 写出: " + outPath + " (桩化 " + done + " 个方法)");
    }

    // 与 trapscan 同样的判据: 大 switch + 索引变量只写一次 + 存在回到分发点的回边
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
