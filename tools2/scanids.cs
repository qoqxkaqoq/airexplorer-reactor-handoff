using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// scanids <rebuilt.exe> <itpTokHex> <outIds> — 收集 call ITP 的常量 id
// 模式: [值生产块] call ITP; 块 = ldc/xor/add/sub/and/or/not + <Module>{...} 恒0字段读取
class ScanIds {
    static void Main(string[] a) {
        uint itpTok = 0x06000000u | Convert.ToUInt32(a[1], 16);
        var mod = ModuleDefMD.Load(a[0]);
        var ids = new SortedSet<long>();
        int sites = 0, unknown = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var il = m.Body.Instructions;
                for (int i = 0; i < il.Count; i++) {
                    if (il[i].OpCode.Code != Code.Call) continue;
                    if (!(il[i].Operand is IMethod im) || im.MDToken.Raw != itpTok) continue;
                    sites++;
                    // 正向收集: 从 call 向左找连续值生产块(最多 12 条)
                    var block = new List<Instruction>();
                    int j = i - 1;
                    while (j >= 0 && block.Count < 12) {
                        var ins = il[j];
                        if (IsValueOp(ins)) { block.Add(ins); j--; continue; }
                        break;
                    }
                    block.Reverse();
                    var st = new Stack<long?>();
                    bool ok = true;
                    foreach (var ins in block) { if (!Eval(ins, st)) { ok = false; break; } }
                    if (ok && st.Count == 1 && st.Peek().HasValue) ids.Add(st.Peek().Value);
                    else unknown++;
                }
            }
        }
        Console.WriteLine("[scanids] call-sites=" + sites + " known-ids=" + ids.Count + " unknown=" + unknown);
        File.WriteAllLines(a[2], ids.Select(x => x.ToString()));
    }

    static bool IsValueOp(Instruction ins) {
        switch (ins.OpCode.Code) {
            case Code.Ldc_I4: case Code.Ldc_I4_S: case Code.Ldc_I4_0: case Code.Ldc_I4_1:
            case Code.Ldc_I4_2: case Code.Ldc_I4_3: case Code.Ldc_I4_4: case Code.Ldc_I4_5:
            case Code.Ldc_I4_6: case Code.Ldc_I4_7: case Code.Ldc_I4_8: case Code.Ldc_I4_M1:
            case Code.Xor: case Code.Add: case Code.Sub: case Code.And: case Code.Or: case Code.Not:
            case Code.Nop: return true;
            case Code.Ldsfld: case Code.Ldfld:
                return (ins.Operand?.ToString() ?? "").Contains("<Module>{");
            default: return false;
        }
    }

    static bool Eval(Instruction ins, Stack<long?> st) {
        switch (ins.OpCode.Code) {
            case Code.Ldc_I4: st.Push(Convert.ToInt64(ins.Operand)); return true;
            case Code.Ldc_I4_S: st.Push(Convert.ToInt64(ins.Operand)); return true;
            case Code.Ldc_I4_0: st.Push(0L); return true;
            case Code.Ldc_I4_1: st.Push(1L); return true;
            case Code.Ldc_I4_2: st.Push(2L); return true;
            case Code.Ldc_I4_3: st.Push(3L); return true;
            case Code.Ldc_I4_4: st.Push(4L); return true;
            case Code.Ldc_I4_5: st.Push(5L); return true;
            case Code.Ldc_I4_6: st.Push(6L); return true;
            case Code.Ldc_I4_7: st.Push(7L); return true;
            case Code.Ldc_I4_8: st.Push(8L); return true;
            case Code.Ldc_I4_M1: st.Push(-1L); return true;
            case Code.Xor: case Code.Add: case Code.Sub: case Code.And: case Code.Or: {
                if (st.Count < 2) return false;
                var bb = st.Pop(); var aa = st.Pop();
                if (!aa.HasValue || !bb.HasValue) { st.Push(null); return true; }
                long v = ins.OpCode.Code == Code.Xor ? aa.Value ^ bb.Value
                       : ins.OpCode.Code == Code.Add ? aa.Value + bb.Value
                       : ins.OpCode.Code == Code.Sub ? aa.Value - bb.Value
                       : ins.OpCode.Code == Code.And ? aa.Value & bb.Value : aa.Value | bb.Value;
                st.Push(v); return true;
            }
            case Code.Not: { if (st.Count < 1) return false; var aa = st.Pop(); st.Push(aa.HasValue ? ~aa.Value : (long?)null); return true; }
            case Code.Ldsfld: st.Push(0L); return true;  // <Module>{...} 恒0静态字段
            case Code.Ldfld: { if (st.Count < 1) return false; st.Pop(); st.Push(0L); return true; }  // 弹容器ref, 压恒0值 — 净栈0
            case Code.Nop: return true;
            default: return false;
        }
    }
}
