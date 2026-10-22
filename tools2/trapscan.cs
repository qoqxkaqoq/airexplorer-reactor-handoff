// trapscan.cs — 精确判定"反篡改陷阱体"(必然死循环)
// 判据(三个条件同时成立才算确证,避免一次性 switch 分发的假阳性):
//   1. 方法体够大(默认 >=60 指令)
//   2. 存在 switch,其索引局部变量在整个方法里被写 <=1 次
//   3. 从某个 case 目标块出发,存在一条可达路径跳回"switch 分发点"(形成回边),
//      且这条路径上没有重写过该索引变量  => 循环里索引永远不更新 => 必死循环
// 用法: trapscan <file.exe> [最小指令数] [topN]
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class TrapScan {
    class Hit {
        public string Who; public int Il; public string SwitchOff; public int Targets;
        public string VarName; public int Writes; public string LoopHead; public string FromCase;
    }

    static void Main(string[] a) {
        string file = a[0];
        int minIl = a.Length > 1 ? int.Parse(a[1]) : 60;
        int topN = a.Length > 2 ? int.Parse(a[2]) : 40;
        var mod = ModuleDefMD.Load(file);
        var hits = new List<Hit>();
        int total = 0, scanned = 0;

        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                total++;
                var instrs = m.Body.Instructions;
                if (instrs.Count < minIl) continue;
                var swList = instrs.Where(x => x.OpCode.Code == Code.Switch).ToList();
                if (swList.Count == 0) continue;
                scanned++;

                var off2idx = new Dictionary<uint, int>();
                for (int i = 0; i < instrs.Count; i++) off2idx[instrs[i].Offset] = i;

                foreach (var sw in swList) {
                    int i = instrs.IndexOf(sw);
                    // 1) switch 的索引变量 = switch 之前最近的 ldloc
                    Local idxLocal = null; int loopHead = -1;
                    for (int k = i - 1; k >= 0 && k >= i - 8; k--) {
                        var ins = instrs[k];
                        if (ins.IsLdloc()) { idxLocal = ins.GetLocal(m.Body.Variables); loopHead = k; break; }
                        if (ins.OpCode.FlowControl != FlowControl.Next) break;
                    }
                    if (idxLocal == null || loopHead < 0) continue;

                    // 2) 索引变量被写次数
                    int writes = instrs.Count(x => x.IsStloc() && x.GetLocal(m.Body.Variables) == idxLocal);
                    if (writes > 1) continue;

                    // 3) 回边可达性: 从每个 case 目标 BFS,看能否回到 loopHead,且路径上没写过索引变量
                    var targets = sw.Operand as Instruction[];
                    if (targets == null) continue;
                    foreach (var tg in targets.Distinct()) {
                        if (!off2idx.TryGetValue(tg.Offset, out int startIdx)) continue;
                        if (Reaches(instrs, off2idx, startIdx, loopHead, idxLocal, m.Body.Variables)) {
                            hits.Add(new Hit {
                                Who = t.FullName + "::" + m.Name, Il = instrs.Count,
                                SwitchOff = sw.Offset.ToString("X4"), Targets = targets.Length,
                                VarName = "V_" + idxLocal.Index, Writes = writes,
                                LoopHead = instrs[loopHead].Offset.ToString("X4"),
                                FromCase = tg.Offset.ToString("X4")
                            });
                            break;
                        }
                    }
                }
            }
        }

        Console.WriteLine("总方法(有体)=" + total + "  含 switch 且 >" + minIl + " 指令=" + scanned);
        Console.WriteLine("=== 确证必死循环体: " + hits.Count + " 个方法 ===");
        foreach (var h in hits.OrderByDescending(h => h.Il).Take(topN))
            Console.WriteLine("  il={0,-6} switch@{1} 目标={2,-4} 索引={3}(写{4}次) 回边@{5}<-case@{6}  {7}",
                h.Il, h.SwitchOff, h.Targets, h.VarName, h.Writes, h.LoopHead, h.FromCase, h.Who);
        if (hits.Count > topN) Console.WriteLine("  ...(共 " + hits.Count + " 个,仅显示前 " + topN + ")");

        // 按命名空间聚合,看污染分布
        Console.WriteLine();
        Console.WriteLine("=== 污染分布(按命名空间) ===");
        foreach (var g in hits.GroupBy(h => {
            var s = h.Who.Split(':')[0];
            var p = s.Split('.');
            return p.Length >= 2 ? p[0] + "." + p[1] : s;
        }).OrderByDescending(g => g.Count()))
            Console.WriteLine("  {0,4}  {1}", g.Count(), g.Key);
    }

    // 从 startIdx 出发 BFS,能否到达 loopHead(不含起点),且沿途不写 idxLocal
    static bool Reaches(IList<Instruction> instrs, Dictionary<uint, int> off2idx, int startIdx,
                        int loopHead, Local idxLocal, IList<Local> vars) {
        var seen = new HashSet<int>();
        var q = new Queue<int>();
        q.Enqueue(startIdx);
        seen.Add(startIdx);
        while (q.Count > 0) {
            int idx = q.Dequeue();
            var ins = instrs[idx];
            bool hitLoopHead = false;

            // 后继: fallthrough + 跳转目标
            var nexts = new List<int>();
            if (ins.OpCode.Code == Code.Switch) {
                foreach (var tg in (Instruction[])ins.Operand)
                    if (off2idx.TryGetValue(tg.Offset, out int ti)) nexts.Add(ti);
            } else if (ins.Operand is Instruction brt) {
                if (off2idx.TryGetValue(brt.Offset, out int ti)) nexts.Add(ti);
                // 条件分支还要走 fallthrough
                if (ins.OpCode.FlowControl == FlowControl.Cond_Branch) nexts.Add(idx + 1);
            } else if (ins.OpCode.Code == Code.Ret || ins.OpCode.Code == Code.Throw ||
                       ins.OpCode.Code == Code.Rethrow || ins.OpCode.Code == Code.Endfinally) {
                // 终止
            } else {
                nexts.Add(idx + 1);
            }

            foreach (int n in nexts) {
                if (n == loopHead) hitLoopHead = true;
                if (n < 0 || n >= instrs.Count || !seen.Add(n)) continue;
                // 沿途不能重写索引变量
                var ni = instrs[n];
                if (ni.IsStloc() && ni.GetLocal(vars) == idxLocal) continue;
                q.Enqueue(n);
            }
            if (hitLoopHead) return true;
        }
        return false;
    }
}
