using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// flat — linearize a control-flow-flattened (switch state machine) method body from a dump file.
// usage: flat <exe> <dumpFile> [stateVarIdx] [switchVarIdx]   (default: 37 25)
class Flat {
    static ModuleDef mod;
    class Ins { public OpCode op; public int offset; public string txt; }

    static Dictionary<int, long> vars = new Dictionary<int, long>();

    static void Main(string[] a) {
        mod = ModuleDefMD.Load(a[0]);
        string dumpFile = a[1];
        int stateVar = a.Length > 2 ? int.Parse(a[2]) : 37;
        int swVar = a.Length > 3 ? int.Parse(a[3]) : 25;
        var bin = File.ReadAllBytes(dumpFile);
        int ilSize = BitConverter.ToInt32(bin, 4);
        var il = new byte[ilSize];
        Array.Copy(bin, 24, il, 0, ilSize);
        // parse instructions
        var ins = new List<Ins>();
        var byOff = new SortedDictionary<int, Ins>();
        int i2 = 0;
        while (i2 < il.Length) {
            int off = i2;
            byte b = il[i2];
            OpCode oc; int hdr;
            if (b == 0xFE) { oc = OpCodes.TwoByteOpCodes[il[i2+1]]; hdr = 2; }
            else { oc = OpCodes.OneByteOpCodes[b]; hdr = 1; }
            if (oc == null) { Console.WriteLine($"?? bad opcode {b:X2} at IL_{off:X4}"); break; }
            int pos = i2 + hdr;
            string operand;
            int sz = OpSize(oc, il, pos, out operand);
            ins.Add(new Ins { op = oc, offset = off, txt = oc.Name + (operand.Length > 0 ? " " + operand : "") });
            byOff[off] = ins[^1];
            i2 = pos + sz;
            if (sz == 0 && oc.OperandType != OperandType.InlineNone) i2 = pos;
        }
        // find dispatch switch
        Console.Error.WriteLine($"parsed ins={ins.Count} il={il.Length}");
        Ins switchIns = ins.FirstOrDefault(x => x.op == OpCodes.Switch);
        if (switchIns == null) { Console.WriteLine("no switch found"); return; }
        int swOff = switchIns.offset;
        int swPos = swOff + (il[swOff] == 0xFE ? 2 : 1);
        int n = BitConverter.ToInt32(il, swPos);
        Console.Error.WriteLine($"switch at IL_{swOff:X4} n={n}");
        var swTargets = new int[n];
        for (int k = 0; k < n; k++) swTargets[k] = swPos + 4 + n * 4 + BitConverter.ToInt32(il, swPos + 4 + k * 4);
        g_offs = new List<int>(byOff.Keys);
        g_prev = new int[il.Length + 1];
        int lastPrev = -1;
        for (int k = 0; k < ins.Count; k++) { g_prev[ins[k].offset] = lastPrev; lastPrev = ins[k].offset; }

        var outp = new List<string>();
        var sw = new StreamWriter("/tmp/428A_flat.txt") { AutoFlush = false };
        var emitted = new HashSet<int>();
        // dispatch offset = instruction immediately before the switch
        int dispOff = -1;
        for (int k = 1; k < ins.Count; k++) if (ins[k] == switchIns) { dispOff = ins[k-1].offset; break; }
        var pending = new Stack<(int off, string why)>();
        pending.Push((0, "entry"));
        int guard = 400000;
        bool first = true;
        while (pending.Count > 0 && guard-- > 0) {
            var (start, why) = pending.Pop();
            if (emitted.Contains(start)) continue;
            if (!first) outp.Add($"=== BLOCK IL_{start:X4} ({why}) ===");
            emitted.Add(start);
            first = false;
            int ip = start;
            while (true) {
                // dispatch point: ldloc v25 followed by switch -> jump to computed target inline
                if (byOff.TryGetValue(ip, out var I0) && I0 != null && IsLdloc(I0.txt, swVar)
                    && byOff.TryGetValue(ip + ILen(il, byOff, ip), out var nx0) && nx0 != null && nx0.op == OpCodes.Switch) {
                    if (vars.TryGetValue(swVar, out long sv) && sv >= 0 && sv < n) {
                        int next = swTargets[sv];
                        outp.Add($";; dispatch v{swVar}={sv} -> IL_{next:X4}");
                        if (outp.Count % 200 == 0) Console.Error.WriteLine($"progress: blocks={emitted.Count} outp={outp.Count} ip=IL_{ip:X4} -> IL_{next:X4}");
                        if (emitted.Contains(next)) { outp.Add("  ;; back-edge to visited block, stop"); break; }
                        emitted.Add(next);
                        outp.Add($"=== BLOCK IL_{next:X4} ===");
                        ip = next;
                        continue;
                    } else { outp.Add("  !! dispatch with unknown v" + swVar); break; }
                }
                if (ip >= il.Length || !byOff.TryGetValue(ip, out var I) || I == null) { outp.Add("  <end>"); break; }
                var t = I.txt;
                // stloc <stateVar|swVar>: try constant-fold the stored value
                if (IsStloc(t, out int si) && (si == stateVar || si == swVar)) {
                    if (TryEval(il, byOff, ip, out long val)) vars[si] = val;
                    else { vars.Remove(si); outp.Add($"  [{t}] ;; UNKNOWN -> deoptimize"); ip += ILen(il, byOff, ip); continue; }
                    ip += ILen(il, byOff, ip);
                    continue;
                }
                // all branch-form instructions (short/long targets), incl. leave
                if (I.op.OperandType == OperandType.InlineBrTarget || I.op.OperandType == OperandType.ShortInlineBrTarget) {
                    int sp = t.LastIndexOf(' ');
                    string opnd = sp >= 0 ? t.Substring(sp + 1) : "";
                    if (!opnd.StartsWith("IL_")) { outp.Add($"  {t}"); ip += ILen(il, byOff, ip); continue; }
                    int tgt = Convert.ToInt32(opnd.Substring(3), 16);
                    bool cond = I.op == OpCodes.Brtrue || I.op == OpCodes.Brtrue_S || I.op == OpCodes.Brfalse || I.op == OpCodes.Brfalse_S;
                    outp.Add($"  (real) {t}");
                    int nxt = ip + ILen(il, byOff, ip);
                    if (cond) {
                        // follow target inline, defer fallthrough
                        pending.Push((nxt, "fallthrough"));
                        if (emitted.Contains(tgt) || tgt == dispOff) { outp.Add($"  ;; join IL_{tgt:X4}"); break; }
                        emitted.Add(tgt);
                        outp.Add($"=== BLOCK IL_{tgt:X4} (branch-target) ===");
                        ip = tgt;
                        continue;
                    } else {
                        if (tgt == dispOff) continue;   // jump to dispatch: handled at top of loop
                        if (emitted.Contains(tgt)) { outp.Add($"  ;; join visited IL_{tgt:X4}"); break; }
                        emitted.Add(tgt);
                        outp.Add($"=== BLOCK IL_{tgt:X4} (branch-target) ===");
                        ip = tgt;
                        continue;
                    }
                }
                if (I.op == OpCodes.Ret || I.op == OpCodes.Throw) {
                    outp.Add($"  (real) {t}");
                    break;
                }
                outp.Add($"  {t}");
                sw.WriteLine(outp[^1]);
                if (outp.Count % 500 == 0) sw.Flush();
                ip += ILen(il, byOff, ip);
                if (outp.Count > 120000) { outp.Add("!! outp cap"); goto done; }
            }
        }
        done:
        sw.Flush(); sw.Dispose();
        if (guard <= 0) outp.Add("!! guard hit");
        File.WriteAllLines("/tmp/428A_flat.txt", outp);
        Console.WriteLine($"emitted {outp.Count} lines -> /tmp/428A_flat.txt; blocks={emitted.Count}/{n}; total ins={ins.Count}");
    }

    static bool IsLdloc(string t, int vi) {
        if (!t.StartsWith("ldloc")) return false;
        int sp = t.LastIndexOf(' ');
        return sp > 0 && t.Substring(sp + 1) == "v" + vi;
    }
    static bool IsStloc(string t, out int vi) {
        vi = -1;
        if (!t.StartsWith("stloc")) return false;
        int sp = t.LastIndexOf(' ');
        if (sp <= 0 || t[sp+1] != 'v') return false;
        return int.TryParse(t.Substring(sp + 2), out vi);
    }

    static int Consumes(OpCode oc) {
        switch (oc.Code) {
            case Code.Add: case Code.Sub: case Code.Xor: case Code.And: case Code.Or: case Code.Mul: return 2;
            case Code.Neg: case Code.Dup: return 1;
            case Code.Ldc_I4: case Code.Ldc_I4_S: case Code.Ldc_I8:
            case Code.Ldloc: case Code.Ldloc_S:
            case Code.Ldc_I4_0: case Code.Ldc_I4_1: case Code.Ldc_I4_2: case Code.Ldc_I4_3:
            case Code.Ldc_I4_4: case Code.Ldc_I4_5: case Code.Ldc_I4_6: case Code.Ldc_I4_7:
            case Code.Ldc_I4_8: case Code.Ldc_I4_M1: case Code.Ldnull: return 0;
            default: return -1;
        }
    }

    static int ILen(byte[] il, SortedDictionary<int, Ins> byOff, int off) {
        var I = byOff[off];
        int hdr = il[off] == 0xFE ? 2 : 1;
        int pos = off + hdr;
        string op; int sz = OpSize(I.op, il, pos, out op);
        return hdr + (sz == 0 && I.op.OperandType != OperandType.InlineNone ? 0 : sz);
    }

    // walk back from the stloc at ip, collecting the full const expression via operand-deficit tracking
    static List<int> g_offs;
    static int[] g_prev;
    static bool TryEval(byte[] il, SortedDictionary<int, Ins> byOff, int stOff, out long val) {
        val = 0;
        var offs = g_offs;
        // collect candidate chain backward
        var chainRev = new List<Ins>();
        int ip = stOff;
        int deficit = 1;
        for (int k = 0; k < 14; k++) {
            int prev = ip > 0 && ip < g_prev.Length ? g_prev[ip] : -1;
            if (prev < 0) return false;
            var I = byOff[prev];
            if (I.txt.StartsWith("stloc") || I.op == OpCodes.Switch) return false;
            int consumes = Consumes(I.op);
            if (consumes < 0) return false;
            chainRev.Add(I);
            deficit = deficit - 1 + consumes;
            ip = prev;
            if (deficit == 0) break;
        }
        if (deficit != 0) return false;
        var st = new Stack<long>();
        foreach (var I in chainRev.Reverse<Ins>()) {
            var t = I.txt;
            int sp = t.IndexOf(' ');
            string opname = sp > 0 ? t.Substring(0, sp) : t;
            string opnd = sp > 0 ? t.Substring(sp + 1) : "";
            switch (opname) {
                case "ldc.i4": case "ldc.i4.s": if (long.TryParse(opnd, out long n)) st.Push(n & 0xFFFFFFFF); else return false; break;
                case "ldc.i4.m1": st.Push(0xFFFFFFFF); break;
                case "ldc.i4.0": st.Push(0); break;
                case "ldc.i4.1": st.Push(1); break;
                case "ldc.i4.2": st.Push(2); break;
                case "ldc.i4.3": st.Push(3); break;
                case "ldc.i4.4": st.Push(4); break;
                case "ldc.i4.5": st.Push(5); break;
                case "ldc.i4.6": st.Push(6); break;
                case "ldc.i4.7": st.Push(7); break;
                case "ldc.i4.8": st.Push(8); break;
                case "ldloc": case "ldloc.s": {
                    if (!opnd.StartsWith("v") || !int.TryParse(opnd.Substring(1), out int vi)) return false;
                    if (vars.TryGetValue(vi, out long vv)) st.Push(vv & 0xFFFFFFFF); else return false;
                    break;
                }
                case "add": { if (st.Count < 2) return false; var b = st.Pop(); var x = st.Pop(); st.Push((x + b) & 0xFFFFFFFF); break; }
                case "sub": { if (st.Count < 2) return false; var b = st.Pop(); var x = st.Pop(); st.Push((x - b) & 0xFFFFFFFF); break; }
                case "xor": { if (st.Count < 2) return false; var b = st.Pop(); var x = st.Pop(); st.Push((x ^ b) & 0xFFFFFFFF); break; }
                case "and": { if (st.Count < 2) return false; var b = st.Pop(); var x = st.Pop(); st.Push(x & b); break; }
                case "or":  { if (st.Count < 2) return false; var b = st.Pop(); var x = st.Pop(); st.Push(x | b); break; }
                case "neg": { if (st.Count < 1) return false; var x = st.Pop(); st.Push((-x) & 0xFFFFFFFF); break; }
                case "mul": { if (st.Count < 2) return false; var b = st.Pop(); var x = st.Pop(); st.Push((x * b) & 0xFFFFFFFF); break; }
                default: return false;
            }
        }
        if (st.Count != 1) return false;
        val = st.Pop();
        return true;
    }

    static int OpSize(OpCode oc, byte[] il, int pos, out string operand) {
        operand = "";
        if (pos >= il.Length) return 0;
        switch (oc.OperandType) {
            case OperandType.InlineNone: return 0;
            case OperandType.ShortInlineBrTarget: { sbyte d = (sbyte)il[pos]; operand = "IL_" + (pos + 1 + d).ToString("X4"); return 1; }
            case OperandType.InlineBrTarget: { int d4 = BitConverter.ToInt32(il, pos); operand = "IL_" + (pos + 4 + d4).ToString("X4"); return 4; }
            case OperandType.ShortInlineI: operand = il[pos].ToString(); return 1;
            case OperandType.InlineI: operand = BitConverter.ToInt32(il, pos).ToString(); return 4;
            case OperandType.InlineI8: operand = BitConverter.ToInt64(il, pos).ToString(); return 8;
            case OperandType.ShortInlineR: operand = BitConverter.ToSingle(il, pos).ToString(); return 4;
            case OperandType.InlineR: operand = BitConverter.ToDouble(il, pos).ToString(); return 8;
            case OperandType.ShortInlineVar: operand = "v" + il[pos]; return 1;
            case OperandType.InlineVar: operand = "v" + BitConverter.ToUInt16(il, pos); return 2;
            case OperandType.InlineString: { uint t = BitConverter.ToUInt32(il, pos); operand = "\"" + UsStr(t) + "\""; return 4; }
            case OperandType.InlineSwitch: {
                int n = BitConverter.ToInt32(il, pos);
                operand = "(" + n + " targets)"; return 4 + n * 4;
            }
            case OperandType.InlineMethod: case OperandType.InlineField: case OperandType.InlineTok:
            case OperandType.InlineType: case OperandType.InlineSig: { uint t = BitConverter.ToUInt32(il, pos); operand = ResolveTok(t); return 4; }
            default: return 0;
        }
    }
    static string UsStr(uint tok) {
        try { var s = ((ModuleDefMD)mod).ReadUserString(tok & 0x00FFFFFF); return s == null ? "<us?" + tok.ToString("X8") + ">" : s; }
        catch { return "<us?" + tok.ToString("X8") + ">"; }
    }
    static string ResolveTok(uint t) {
        try {
            var m = mod.ResolveToken(t) as IMDTokenProvider;
            if (m == null) return $"tok {t:X8}";
            string s = m.GetType().Name switch { "MemberRef" => ((MemberRef)m).FullName, "MethodDef" => ((MethodDef)m).FullName, "Field" => ((FieldDef)m).FullName, "TypeDef" => ((TypeDef)m).FullName, "TypeRef" => ((TypeRef)m).FullName, _ => m.GetType().Name };
            return $"{t:X8} {s}";
        } catch { return $"tok {t:X8}"; }
    }
}
