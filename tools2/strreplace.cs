using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// strreplace <in.exe> <strings.json> <out.exe> — call ITP(id) → ldstr 明文
// 复用 scanids 的正向块求值; 查得到映射才替换, 查不到保留原 call
class StrReplace {
    static uint ItpTok;
    static Dictionary<string, long> fv = new Dictionary<string, long>();
    static Dictionary<long, string> maps = new Dictionary<long, string>();

    static void Main(string[] a) {
        ItpTok = 0x06000000u | Convert.ToUInt32(a[1], 16);
        foreach (var ln in File.ReadAllLines(a[2])) {
            int eq = ln.IndexOf('=');
            if (eq <= 0) continue;
            var k = ln.Substring(0, eq); var v = ln.Substring(eq + 1);
            long n; if (k.StartsWith("m_") && long.TryParse(v, out n)) fv[k] = n;
        }
        // TSV: id\tvalue (python 预转换, 值内 tab/换行已替换为空格)
        foreach (var ln in File.ReadAllLines(a[3])) {
            int t1 = ln.IndexOf('\t');
            if (t1 <= 0) continue;
            long kn;
            if (long.TryParse(ln.Substring(0, t1), out kn)) maps[kn] = ln.Substring(t1 + 1);
        }
        Console.WriteLine("[strreplace] maps=" + maps.Count + " fv=" + fv.Count);

        var mod = ModuleDefMD.Load(a[0]);
        int sites = 0, replaced = 0, kept = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var il = m.Body.Instructions;
                for (int i = 0; i < il.Count; i++) {
                    if (il[i].OpCode.Code != Code.Call) continue;
                    if (!(il[i].Operand is IMethod im) || im.MDToken.Raw != ItpTok) continue;
                    sites++;
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
                    if (ok && st.Count == 1 && st.Peek().HasValue && maps.TryGetValue(st.Peek().Value, out var s)) {
                        // 替换: 块指令 Nop 化(保留对象, 防分支/EH 悬空), call → ldstr
                        for (int k = 0; k < block.Count; k++) { block[k].OpCode = OpCodes.Nop; block[k].Operand = null; }
                        il[i].OpCode = OpCodes.Ldstr;
                        il[i].Operand = s;
                        replaced++;
                    } else kept++;
                }
            }
        }
        Console.WriteLine("[strreplace] sites=" + sites + " replaced=" + replaced + " kept=" + kept);
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[4], opts);
        Console.WriteLine("[strreplace] wrote " + a[4]);
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
            case Code.Ldsfld: st.Push(0L); return true;
            case Code.Ldfld: { if (st.Count < 1) return false; st.Pop();
                var fn = (ins.Operand?.ToString() ?? "");
                int cc = fn.IndexOf("::");
                var fname = cc >= 0 ? fn.Substring(cc + 2) : fn;
                st.Push(fv.TryGetValue(fname, out var vv) ? vv : (long?)null);
                return true;
            }
            case Code.Nop: return true;
            default: return false;
        }
    }
}
