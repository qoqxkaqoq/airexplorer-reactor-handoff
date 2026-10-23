using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// bodyswap — 对指定 token 的方法做「官方体 + 官方 locals + 官方 EH」三件套一体替换。
//
// 动机: v66 架构 = 绕过 Reactor + cilantro 重组体。官方 .loc/.eh 与 cilantro 体
// 语义错位(locsig 单换签名会炸, v68b 教训)。唯三件套同换才自洽 —— 相当于在 v66
// 上对指定方法做 nbrestore 单点手术, 其余部分保持 v66 已验证状态。
//
// 用法: bodyswap <dumpDir> <in.exe> <out.exe> <tokensFile>
//   tokensFile: 每行一个 0600XXXX
class BodySwap {
    static Dictionary<ushort, OpCode> opMap;
    static ModuleDef mod;
    static Importer imp;

    static void Main(string[] a) {
        if (a.Length < 4) { Console.WriteLine("usage: bodyswap <dumpDir> <in> <out> <tokensFile>"); return; }
        string dumpDir = a[0];
        mod = ModuleDefMD.Load(a[1]);
        imp = new Importer(mod);
        BuildOpMap();

        var tokens = new HashSet<string>();
        foreach (var ln in File.ReadAllLines(a[3]))
            if (!string.IsNullOrWhiteSpace(ln)) tokens.Add(ln.Trim().ToUpperInvariant());
        Console.WriteLine("[bodyswap] targets=" + tokens.Count);

        int ok = 0, fail = 0, same = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                string tok = m.MDToken.Raw.ToString("X8");
                if (!tokens.Contains(tok)) continue;

                string bp = Path.Combine(dumpDir, "m_" + tok + ".bin");
                string lp = Path.Combine(dumpDir, "m_" + tok + ".loc");
                string ep = Path.Combine(dumpDir, "m_" + tok + ".eh");
                if (!File.Exists(bp)) { Console.WriteLine("[no-bin] " + tok); fail++; continue; }
                var d = File.ReadAllBytes(bp);
                if (d.Length < 24) { fail++; continue; }
                int ilSize = (int)BitConverter.ToUInt32(d, 4);
                int maxStack = (int)BitConverter.ToUInt32(d, 8);
                int ehCount = (int)BitConverter.ToUInt32(d, 12);
                if (ilSize <= 0 || 24 + ilSize > d.Length) { fail++; continue; }
                var il = new byte[ilSize];
                Array.Copy(d, 24, il, 0, ilSize);

                // 官方 locals(.loc) —— 必须有, 否则 IL 的 ldloc 无从绑定
                if (!File.Exists(lp)) { Console.WriteLine("[no-loc] " + tok); fail++; continue; }
                var lines = File.ReadAllLines(lp).Where(x => x.Trim().Length > 0).ToList();
                var vars = new List<Local>();
                bool lok = true;
                foreach (var ln in lines) {
                    var p = ln.Split('|');
                    if (p.Length < 3) { lok = false; break; }
                    var sig = ParseType(p[2]);
                    if (sig == null) { lok = false; Console.WriteLine("[missType] " + tok + " " + p[2]); break; }
                    vars.Add(new Local(imp.Import(sig)));
                }
                if (!lok) { fail++; continue; }

                int needStack;
                Dictionary<int, Instruction> offMap;
                List<Instruction> instrs;
                try { instrs = ParseIl(il, vars, out needStack, out offMap); }
                catch (Exception ex) { Console.WriteLine("[parse] " + tok + " : " + ex.Message); fail++; continue; }

                if (ehCount > 0 && !File.Exists(ep)) { Console.WriteLine("[no-eh] " + tok); fail++; continue; }

                var body = new CilBody();
                body.InitLocals = vars.Count > 0;
                int ms = Math.Max(Math.Max(maxStack, needStack + 2), 8);
                body.MaxStack = (ushort)Math.Min(ms, 65535);
                body.KeepOldMaxStack = true;
                foreach (var v in vars) body.Variables.Add(v);
                foreach (var ins in instrs) body.Instructions.Add(ins);
                if (ehCount > 0) AttachEh(body, File.ReadAllBytes(ep), offMap, ilSize);

                string bad = Validate(body);
                if (bad != null) { Console.WriteLine("[bad-operand] " + tok + " : " + bad); fail++; continue; }

                m.Body = body;
                ok++;
                Console.WriteLine("[swap] " + tok + " " + t.FullName + "::" + m.Name + " instrs=" + instrs.Count + " vars=" + vars.Count);
            }
        }
        Console.WriteLine("[bodyswap] swapped=" + ok + " fail=" + fail);
        if (ok == 0) { Console.WriteLine("[bodyswap] 无改动, 不写盘"); return; }
        var wopt = new ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[2], wopt);
        Console.WriteLine("[out] " + a[2]);
    }

    // ---------- 以下来自 nbrestore.cs / locsig.cs ----------

    static void BuildOpMap() {
        opMap = new Dictionary<ushort, OpCode>();
        foreach (var f in typeof(OpCodes).GetFields()) {
            if (f.FieldType != typeof(OpCode)) continue;
            var op = (OpCode)f.GetValue(null);
            opMap[(ushort)op.Value] = op;
        }
    }

    static readonly Dictionary<string, int> PopN = new Dictionary<string, int> {
        {"Pop0",0},{"Pop1",1},{"PopI",1},{"PopRef",1},{"Pop1_pop1",2},{"PopI_pop1",2},
        {"PopI_popI",2},{"PopI_popI8",2},{"PopI_popR4",2},{"PopI_popR8",2},{"PopI_popI_popI",3},
        {"PopI_pop1_pop1",3},{"PopRef_pop1",2},{"PopRef_popI",2},{"PopRef_popI_popI",3},
        {"PopRef_popI_popI8",3},{"PopRef_popI_popR4",3},{"PopRef_popI_popR8",3},
        {"PopRef_popI_popRef",3},{"Varpop",0},{"PopAll",0},
    };
    static readonly Dictionary<string, int> PushN = new Dictionary<string, int> {
        {"Push0",0},{"Push1",1},{"PushI",1},{"PushI8",1},{"PushR4",1},{"PushR8",1},
        {"PushRef",1},{"Push1_push1",2},{"Varpush",0},
    };

    static List<Instruction> ParseIl(byte[] il, IList<Local> vars, out int maxDepth, out Dictionary<int, Instruction> offsetMap) {
        var list = new List<Instruction>();
        var off2idx = new Dictionary<int, int>();
        var branchFix = new List<Tuple<int, int>>();
        var switchFix = new List<Tuple<int, int[]>>();
        int p = 0, depth = 0, maxd = 0;

        while (p < il.Length) {
            int start = p;
            ushort code = il[p++];
            if (code == 0xFE) {
                if (p >= il.Length) throw new Exception("truncated 0xFE");
                code = (ushort)(0xFE00 | il[p++]);
            }
            OpCode op;
            if (!opMap.TryGetValue(code, out op)) throw new Exception("unknown opcode 0x" + code.ToString("X4") + " at " + start);

            object operand = null;
            switch (op.OperandType) {
                case OperandType.InlineNone: break;
                case OperandType.ShortInlineI:
                    operand = op.Code == Code.Ldc_I4_S ? (object)(sbyte)il[p] : il[p];
                    p += 1; break;
                case OperandType.InlineI: operand = BitConverter.ToInt32(il, p); p += 4; break;
                case OperandType.InlineI8: operand = BitConverter.ToInt64(il, p); p += 8; break;
                case OperandType.ShortInlineR: operand = BitConverter.ToSingle(il, p); p += 4; break;
                case OperandType.InlineR: operand = BitConverter.ToDouble(il, p); p += 8; break;
                case OperandType.ShortInlineVar: {
                    int idx = il[p]; p += 1;
                    if (idx >= vars.Count) throw new Exception("local idx " + idx + " >= " + vars.Count);
                    operand = vars[idx]; break;
                }
                case OperandType.InlineVar: {
                    int idx = BitConverter.ToUInt16(il, p); p += 2;
                    if (idx >= vars.Count) throw new Exception("local idx " + idx + " >= " + vars.Count);
                    operand = vars[idx]; break;
                }
                case OperandType.ShortInlineBrTarget: {
                    sbyte off = (sbyte)il[p]; p += 1;
                    branchFix.Add(Tuple.Create(list.Count, p + off));
                    operand = null; break;
                }
                case OperandType.InlineBrTarget: {
                    int off = BitConverter.ToInt32(il, p); p += 4;
                    branchFix.Add(Tuple.Create(list.Count, p + off));
                    operand = null; break;
                }
                case OperandType.InlineSwitch: {
                    int n = BitConverter.ToInt32(il, p); p += 4;
                    if (n < 0 || n > 100000) throw new Exception("bad switch count " + n);
                    int baseOff = p + 4 * n;
                    var targets = new int[n];
                    for (int k = 0; k < n; k++) { targets[k] = baseOff + BitConverter.ToInt32(il, p); p += 4; }
                    switchFix.Add(Tuple.Create(list.Count, targets));
                    operand = null; break;
                }
                case OperandType.InlineString: {
                    uint t = BitConverter.ToUInt32(il, p); p += 4;
                    var u8 = ((ModuleDefMD)mod).USStream.Read(t & 0x00FFFFFF);
                    operand = u8 ?? ""; break;
                }
                case OperandType.InlineMethod:
                case OperandType.InlineField:
                case OperandType.InlineType:
                case OperandType.InlineTok:
                case OperandType.InlineSig: {
                    uint t = BitConverter.ToUInt32(il, p); p += 4;
                    operand = mod.ResolveToken(t); break;
                }
                default: throw new Exception("unhandled operand type " + op.OperandType);
            }

            int pop; PopN.TryGetValue(op.StackBehaviourPop.ToString(), out pop);
            depth -= pop; if (depth < 0) depth = 0;
            int push; PushN.TryGetValue(op.StackBehaviourPush.ToString(), out push);
            depth += push; if (depth > maxd) maxd = depth;

            off2idx[start] = list.Count;
            list.Add(new Instruction(op, operand));
        }
        if (p != il.Length) throw new Exception("IL length mismatch: consumed " + p + " of " + il.Length);

        foreach (var bf in branchFix) {
            int ti;
            if (!off2idx.TryGetValue(bf.Item2, out ti))
                throw new Exception("branch target offset " + bf.Item2 + " not on instruction boundary");
            list[bf.Item1].Operand = list[ti];
        }
        foreach (var sf in switchFix) {
            var arr = new Instruction[sf.Item2.Length];
            for (int k = 0; k < arr.Length; k++) {
                int ti;
                if (!off2idx.TryGetValue(sf.Item2[k], out ti))
                    throw new Exception("switch target offset " + sf.Item2[k] + " not on boundary");
                arr[k] = list[ti];
            }
            list[sf.Item1].Operand = arr;
        }

        maxDepth = maxd;
        offsetMap = new Dictionary<int, Instruction>();
        foreach (var kv in off2idx) offsetMap[kv.Key] = list[kv.Value];
        return list;
    }

    static void AttachEh(CilBody body, byte[] eh, Dictionary<int, Instruction> offMap, int ilSize) {
        if (eh.Length < 4) return;
        uint cnt = BitConverter.ToUInt32(eh, 0);
        if (cnt == 0 || eh.Length < 4 + cnt * 28) return;
        bool needSentinel = false;
        for (int i = 0; i < cnt; i++) {
            int b0 = 4 + i * 28;
            uint t0 = BitConverter.ToUInt32(eh, b0 + 4), l0 = BitConverter.ToUInt32(eh, b0 + 8);
            uint h0 = BitConverter.ToUInt32(eh, b0 + 12), l0b = BitConverter.ToUInt32(eh, b0 + 16);
            if ((int)(t0 + l0) == ilSize || (int)(h0 + l0b) == ilSize) needSentinel = true;
        }
        if (needSentinel && !offMap.ContainsKey(ilSize)) {
            var sentinel = OpCodes.Nop.ToInstruction();
            body.Instructions.Add(sentinel);
            offMap[ilSize] = sentinel;
        }
        int dropped = 0;
        for (int i = 0; i < cnt; i++) {
            int b = 4 + i * 28;
            uint flags = BitConverter.ToUInt32(eh, b + 0);
            uint tryOff = BitConverter.ToUInt32(eh, b + 4);
            uint tryLen = BitConverter.ToUInt32(eh, b + 8);
            uint hOff = BitConverter.ToUInt32(eh, b + 12);
            uint hLen = BitConverter.ToUInt32(eh, b + 16);
            uint cls = BitConverter.ToUInt32(eh, b + 20);

            Instruction ts, te, hs, he;
            if (!offMap.TryGetValue((int)tryOff, out ts)) { dropped++; continue; }
            if (!offMap.TryGetValue((int)hOff, out hs)) { dropped++; continue; }
            offMap.TryGetValue((int)(tryOff + tryLen), out te);
            offMap.TryGetValue((int)(hOff + hLen), out he);

            var neh = new ExceptionHandler(ExceptionHandlerType.Catch);
            if (flags == 1) neh.HandlerType = ExceptionHandlerType.Filter;
            else if (flags == 2) neh.HandlerType = ExceptionHandlerType.Finally;
            else if (flags == 3 || flags == 4) neh.HandlerType = ExceptionHandlerType.Fault;

            if (neh.HandlerType == ExceptionHandlerType.Catch) {
                var ct = cls == 0 ? null : (mod.ResolveToken(cls) as ITypeDefOrRef);
                if (ct == null) { dropped++; continue; }
                neh.CatchType = ct;
            }
            if (neh.HandlerType == ExceptionHandlerType.Filter) {
                if (!offMap.TryGetValue((int)cls, out var fs)) { dropped++; continue; }
                neh.FilterStart = fs;
            }
            neh.TryStart = ts; neh.TryEnd = te;
            neh.HandlerStart = hs; neh.HandlerEnd = he;
            body.ExceptionHandlers.Add(neh);
        }
        var ordered = body.ExceptionHandlers
            .OrderBy(h => h.TryStart == null ? int.MaxValue : h.TryStart.Offset)
            .ThenByDescending(h => (h.TryEnd == null || h.TryStart == null) ? 0 : h.TryEnd.Offset - h.TryStart.Offset)
            .ToList();
        body.ExceptionHandlers.Clear();
        foreach (var h in ordered) body.ExceptionHandlers.Add(h);
        if (dropped > 0) Console.WriteLine("    [eh] " + dropped + " clause(s) dropped");
    }

    static string Validate(CilBody body) {
        int n = 0;
        foreach (var ins in body.Instructions) {
            n++;
            var ot = ins.OpCode.OperandType;
            var o = ins.Operand;
            if (ot == OperandType.InlineNone) continue;
            if (o == null) return "null operand at #" + n + " " + ins.OpCode;
            switch (ot) {
                case OperandType.InlineString: if (!(o is string)) return "InlineString got " + o.GetType().Name + " at #" + n; break;
                case OperandType.InlineMethod: if (!(o is IMethod)) return "InlineMethod got " + o.GetType().Name + " at #" + n; break;
                case OperandType.InlineField: if (!(o is IField)) return "InlineField got " + o.GetType().Name + " at #" + n; break;
                case OperandType.InlineType: if (!(o is ITypeDefOrRef)) return "InlineType got " + o.GetType().Name + " at #" + n; break;
                case OperandType.InlineTok: if (!(o is IMemberRef || o is ITypeDefOrRef || o is MethodDef || o is FieldDef)) return "InlineTok got " + o.GetType().Name + " at #" + n; break;
                case OperandType.InlineSig: if (!(o is byte[])) return "InlineSig got " + o.GetType().Name + " at #" + n; break;
                case OperandType.InlineVar: case OperandType.ShortInlineVar: if (!(o is Local)) return "var got " + o.GetType().Name + " at #" + n; break;
                case OperandType.InlineBrTarget: case OperandType.ShortInlineBrTarget: if (!(o is Instruction)) return "br got " + o.GetType().Name + " at #" + n; break;
                case OperandType.InlineSwitch: if (!(o is Instruction[])) return "switch got " + o.GetType().Name + " at #" + n; break;
                case OperandType.ShortInlineI: if (!(o is sbyte) && !(o is byte)) return "short-i got " + o.GetType().Name + " at #" + n; break;
                case OperandType.InlineI: if (!(o is int)) return "i4 got " + o.GetType().Name + " at #" + n; break;
                case OperandType.InlineI8: if (!(o is long)) return "i8 got " + o.GetType().Name + " at #" + n; break;
                case OperandType.ShortInlineR: if (!(o is float)) return "r4 got " + o.GetType().Name + " at #" + n; break;
                case OperandType.InlineR: if (!(o is double)) return "r8 got " + o.GetType().Name + " at #" + n; break;
            }
        }
        return null;
    }

    // ---------- locsig 的类型解析(归一化 '+'->'/') ----------

    static TypeSig ParseType(string s) {
        s = s.Trim();
        if (s.EndsWith("[]")) { var e = ParseType(s.Substring(0, s.Length - 2)); return e == null ? null : new SZArraySig(e); }
        if (s.EndsWith("&")) { var e = ParseType(s.Substring(0, s.Length - 1)); return e == null ? null : new ByRefSig(e); }
        if (s.EndsWith("*")) { var e = ParseType(s.Substring(0, s.Length - 1)); return e == null ? null : new PtrSig(e); }
        int bt = s.IndexOf('`');
        if (bt > 0 && s.Contains("[[")) {
            int bracket = s.IndexOf("[[");
            string head = s.Substring(0, bracket);
            int arity = 0;
            int.TryParse(head.Substring(bt + 1), out arity);
            var args = new List<TypeSig>();
            int i = bracket;
            while (i < s.Length - 1) {
                if (s[i] == '[' && s[i + 1] == '[') {
                    int depth = 0, j = i;
                    for (; j < s.Length; j++) {
                        if (s[j] == '[') depth++;
                        else if (s[j] == ']') { depth--; if (depth == 0) { j++; break; } }
                    }
                    if (depth != 0) return null;
                    string block = s.Substring(i + 2, j - i - 4);
                    int kdepth = 0, comma = -1;
                    for (int k = 0; k < block.Length; k++) {
                        if (block[k] == '[') kdepth++;
                        else if (block[k] == ']') kdepth--;
                        else if (block[k] == ',' && kdepth == 0) { comma = k; break; }
                    }
                    string typeName = comma > 0 ? block.Substring(0, comma).Trim() : block.Trim();
                    args.Add(ParseType(typeName));
                    i = j;
                } else i++;
            }
            if (args.Any(x => x == null)) return null;
            if (arity > 0 && args.Count != arity) return null;
            var gsig = ResolveRefSig(head) as ClassOrValueTypeSig;
            if (gsig == null) return null;
            return new GenericInstSig(gsig, args);
        }
        return ResolveRefSig(s);
    }

    static TypeSig ResolveRefSig(string full) {
        var td = FindType(full);
        if (td != null) return td.ToTypeSig(td.IsValueType);
        var tdr = FindRef(full);
        if (tdr != null) {
            bool st = IsKnownValueType(full);
            if (!st) {
                var res = tdr.ResolveTypeDef();
                if (res != null) return res.ToTypeSig(res.IsValueType);
            }
            return st ? (TypeSig)new ValueTypeSig(tdr) : new ClassSig(tdr);
        }
        return CorLibSig(full);
    }

    static bool IsKnownValueType(string full) {
        int dot = full.LastIndexOf('.');
        string nm = dot > 0 ? full.Substring(dot + 1) : full;
        switch (nm) {
            case "Nullable`1": case "DateTime": case "TimeSpan": case "DateTimeOffset":
            case "Guid": case "Decimal": case "KeyValuePair`2": case "Tuple`1":
            case "Tuple`2": case "Tuple`3": case "Tuple`4":
                return true;
        }
        return false;
    }

    static Dictionary<string, TypeDef> _byFull;
    static Dictionary<string, ITypeDefOrRef> _byRefFull;
    static TypeDef FindType(string full) {
        if (_byFull == null) {
            _byFull = new Dictionary<string, TypeDef>();
            foreach (var t in mod.GetTypes())
                if (!_byFull.ContainsKey(t.FullName)) _byFull[t.FullName] = t;
            _byRefFull = new Dictionary<string, ITypeDefOrRef>();
            foreach (var tr in mod.GetTypeRefs())
                if (!_byRefFull.ContainsKey(tr.FullName)) _byRefFull[tr.FullName] = tr;
        }
        if (_byFull.TryGetValue(full, out var td)) return td;
        string alt = full.Replace('+', '/');
        if (_byFull.TryGetValue(alt, out var td2)) return td2;
        return null;
    }

    static ITypeDefOrRef FindRef(string full) {
        if (_byFull == null) FindType(full);   // 触发构建
        if (_byRefFull.TryGetValue(full, out var r)) return r;
        int dot = full.LastIndexOf('.');
        if (dot <= 0) return null;
        var ns = full.Substring(0, dot);
        var nm = full.Substring(dot + 1);
        var asmRef = ns.StartsWith("System.Windows.Forms")
            ? mod.GetAssemblyRefs().FirstOrDefault(x => x.Name == "System.Windows.Forms")
            : null;
        if (asmRef == null) asmRef = mod.CorLibTypes.AssemblyRef;
        var trNew = new TypeRefUser(mod, ns, nm, asmRef);
        _byRefFull[full] = trNew;
        return trNew;
    }

    static TypeSig CorLibSig(string full) {
        var cor = mod.CorLibTypes;
        int dot = full.LastIndexOf('.');
        if (dot > 0) {
            var ns = full.Substring(0, dot);
            var nm = full.Substring(dot + 1);
            if (ns == "System") {
                switch (nm) {
                    case "Int32": return cor.Int32;
                    case "UInt32": return cor.UInt32;
                    case "Int64": return cor.Int64;
                    case "UInt64": return cor.UInt64;
                    case "Int16": return cor.Int16;
                    case "UInt16": return cor.UInt16;
                    case "Byte": return cor.Byte;
                    case "SByte": return cor.SByte;
                    case "Boolean": return cor.Boolean;
                    case "Char": return cor.Char;
                    case "Single": return cor.Single;
                    case "Double": return cor.Double;
                    case "String": return cor.String;
                    case "Object": return cor.Object;
                    case "IntPtr": return cor.IntPtr;
                    case "UIntPtr": return cor.UIntPtr;
                    case "TypedReference": return cor.TypedReference;
                }
            }
        }
        return null;
    }
}
