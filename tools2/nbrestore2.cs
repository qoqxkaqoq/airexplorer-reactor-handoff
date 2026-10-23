// nbrestore.cs — 把 JIT 入口收割到的 NecroBit 真身写回 PE
//
// 输入: nbjitdump.py 产出的 m_<token>.bin
//   24 字节头: token(u32) ilSize(u32) maxStack(u32) ehCount(u32) options(u32) localsTok(u32)
//   随后是 raw CIL 字节 (长度 = ilSize)
//   m_<token>.eh: [u32 count][count x 28B CORINFO_EH_CLAUSE]
//     每个 clause = 7 x u32: flags, tryOff, tryLen, handlerOff, handlerLen, classTok|filterOff, (reserved)
//     flags: 0=Catch(typed) 1=Filter 2=Finally 4=Fault
//
// 关键: localsTok 恒为 0 —— NecroBit 只加密方法体, 不动 StandAloneSig。
// 所以局部变量**必须复用原方法自己的 Variables**(顺序完全一致), 不能新建。
// (AutoReaktor 的 nbilmerge 在这里填 0 + 偏移匹配, 导致 37KB/105 locals 的大方法
//  有 3971 处 local 操作数 bind 失败, 最终 CreateCilBody 返回 null, 那种方法就没写回。)
//
// 用法: nbrestore <orig.exe> <dumpdir> <out.exe> [--only TOKEN]
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class NbRestore2 {
    static Dictionary<ushort, OpCode> opMap;
    static ModuleDef mod;
    static Importer imp;

    static void Main(string[] a) {
        string origPath = a[0], dumpDir = a[1], outPath = a[2];
        uint only = 0;
        for (int i = 3; i < a.Length - 1; i++)
            if (a[i] == "--only") uint.TryParse(a[i + 1].Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out only);

        mod = ModuleDefMD.Load(origPath);
        // 第二个模块只用来取局部变量: 原版 NecroBit 方法是空壳(locals=0),
        // 而 nb_original 的 locals 签名完好, 但它的 token 布局被 nb_slayer 改过,
        // 所以 token 认原版、locals 按 FullName 去 nb_original 找。
        var localsMod = a.Length > 3 && a[3] != "--only" ? ModuleDefMD.Load(a[3]) : null;
        var localsByName = new Dictionary<string, MethodDef>();
        if (localsMod != null)
            foreach (var t in localsMod.GetTypes())
                foreach (var mm in t.Methods)
                    if (mm.HasBody) localsByName[t.FullName + "::" + mm.Name.String] = mm;
        imp = new Importer(mod);
        BuildOpMap();

        var files = Directory.GetFiles(dumpDir, "m_*.bin");
        // --onlylist <file>: 只处理清单里列出的 token(每行一个十六进制 RID),
        // 省掉每次调用都遍历上万个 dump 文件的开销
        for (int i = 3; i < a.Length - 1; i++) {
            if (a[i] == "--onlylist") {
                var set = new HashSet<string>();
                foreach (var ln in File.ReadAllLines(a[i + 1]))
                    if (!string.IsNullOrWhiteSpace(ln)) set.Add(ln.Trim().TrimStart('0').ToUpperInvariant());
                files = files.Where(f => set.Contains(
                    Path.GetFileNameWithoutExtension(f).Substring(2).TrimStart('0').ToUpperInvariant())).ToArray();
                Console.WriteLine("[nbrestore] onlylist -> " + files.Length + " files");
                break;
            }
        }
        int ok = 0, skipNoMethod = 0, skipParse = 0, skipNoLocals = 0, locMissType = 0, locUsed = 0;

        foreach (var f in files.OrderBy(x => x)) {
            byte[] d;
            try { d = File.ReadAllBytes(f); } catch { continue; }
            if (d.Length < 24) continue;

            uint tok = BitConverter.ToUInt32(d, 0);
            int ilSize = (int)BitConverter.ToUInt32(d, 4);
            int maxStack = (int)BitConverter.ToUInt32(d, 8);
            int ehCount = (int)BitConverter.ToUInt32(d, 12);
            if (only != 0 && tok != only) continue;
            if (ilSize <= 0 || 24 + ilSize > d.Length) continue;

            var m = mod.ResolveToken(tok) as MethodDef;
            if (m == null) { skipNoMethod++; continue; }

            byte[] il = new byte[ilSize];
            Array.Copy(d, 24, il, 0, ilSize);

            // locals(v2): 官方 .loc 第一优先(与 .bin 同源, 序号语义严格一致);
            // 方法自己的 vars 次之; nb_original 按名兜底
            IList<Local> oldVars = null;
            string locFile = Path.Combine(Path.GetDirectoryName(f) ?? ".", "m_" + tok.ToString("X8") + ".loc");
            if (File.Exists(locFile)) {
                try {
                    var parsed = new List<Local>();
                    bool lok2 = true;
                    foreach (var ln in File.ReadAllLines(locFile)) {
                        if (ln.Trim().Length == 0) continue;
                        var pp = ln.Split('|');
                        if (pp.Length < 3) { lok2 = false; break; }
                        var sig2 = ParseType(pp[2]);
                        if (sig2 == null) { lok2 = false; locMissType++; if (locMissType <= 8) Console.WriteLine("[loc-missType] " + tok.ToString("X8") + " " + pp[2]); break; }
                        parsed.Add(new Local(imp.Import(sig2)));
                    }
                    if (lok2 && parsed.Count > 0) oldVars = parsed;
                } catch { }
            }
            if (oldVars == null) oldVars = m.HasBody ? m.Body.Variables : new List<Local>();
            if (oldVars.Count == 0 && localsByName.Count > 0) {
                var key = (m.DeclaringType == null ? "" : m.DeclaringType.FullName) + "::" + m.Name.String;
                MethodDef lm;
                if (localsByName.TryGetValue(key, out lm) && lm.HasBody && lm.Body.Variables.Count > 0) {
                    oldVars = new List<Local>();
                    foreach (var lv in lm.Body.Variables) oldVars.Add(new Local(lv.Type));
                }
            }

            List<Instruction> instrs;
            int needStack;
            Dictionary<int, Instruction> offMap = null;
            try {
                instrs = ParseIl(il, oldVars, out needStack, out offMap);
            } catch (Exception ex) {
                skipParse++;
                if (skipParse <= 5) Console.WriteLine("[skip-parse] " + f + " : " + ex.Message);
                continue;
            }
            if (instrs == null || instrs.Count == 0) { skipParse++; continue; }

            var body = new CilBody();
            // InitLocals 必须和"有没有局部变量签名"一致:
            // 声明了 initlocals 却没有 LocalVarSigTok, 运行时会判非法(表现为 BadImageFormat: Bad IL range)。
            body.InitLocals = oldVars.Count > 0;
            int ms = Math.Max(Math.Max(maxStack, needStack + 2), 8);
            body.MaxStack = (ushort)Math.Min(ms, 65535);
            body.KeepOldMaxStack = true;
            foreach (var v in oldVars) body.Variables.Add(v);   // 复用同一批 Local 对象
            foreach (var ins in instrs) body.Instructions.Add(ins);

            // EH
            string ehFile = Path.ChangeExtension(f, ".eh");
            if (File.Exists(ehFile) && offMap != null) AttachEh(body, File.ReadAllBytes(ehFile), offMap, ilSize);

            // 写盘前校验操作数类型, 免得 dnlib 在 WriteOperand 处才炸且不给位置
            string bad = Validate(body);
            if (bad != null) {
                skipParse++;
                if (skipParse <= 8) Console.WriteLine("[bad-operand] m_" + tok.ToString("X8") + " : " + bad);
                continue;
            }
            m.Body = body;
            ok++;
            if (oldVars.Count > 0 && File.Exists(locFile)) locUsed++;
        }

        Console.WriteLine("[nbrestore2] 写回 " + ok + " (官方.loc=" + locUsed + ", locMissType=" + locMissType + ") / 无对应方法 " + skipNoMethod + " / 解析失败 " + skipParse);
        if (ok == 0) return;
        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags = dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, wopt);
        Console.WriteLine("[nbrestore] 写出: " + outPath);
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

    static void BuildOpMap() {
        opMap = new Dictionary<ushort, OpCode>();
        foreach (var f in typeof(OpCodes).GetFields()) {
            if (f.FieldType != typeof(OpCode)) continue;
            var op = (OpCode)f.GetValue(null);
            opMap[(ushort)op.Value] = op;
        }
    }

    static readonly Dictionary<string,int> PopN = new Dictionary<string,int> {
        {"Pop0",0},{"Pop1",1},{"PopI",1},{"PopRef",1},{"Pop1_pop1",2},{"PopI_pop1",2},
        {"PopI_popI",2},{"PopI_popI8",2},{"PopI_popR4",2},{"PopI_popR8",2},{"PopI_popI_popI",3},
        {"PopI_pop1_pop1",3},{"PopRef_pop1",2},{"PopRef_popI",2},{"PopRef_popI_popI",3},
        {"PopRef_popI_popI8",3},{"PopRef_popI_popR4",3},{"PopRef_popI_popR8",3},
        {"PopRef_popI_popRef",3},{"Varpop",0},{"PopAll",0},
    };
    static readonly Dictionary<string,int> PushN = new Dictionary<string,int> {
        {"Push0",0},{"Push1",1},{"PushI",1},{"PushI8",1},{"PushR4",1},{"PushR8",1},
        {"PushRef",1},{"Push1_push1",2},{"Varpush",0},
    };

    // 两遍: 先逐条建 Instruction 并记录 offset, 再回填分支目标
    static List<Instruction> ParseIl(byte[] il, IList<Local> vars, out int maxDepth, out Dictionary<int, Instruction> offsetMap) {
        var list = new List<Instruction>();
        var off2idx = new Dictionary<int, int>();
        var branchFix = new List<Tuple<int, int>>();   // (instrIndex, targetOffset)
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
                    // 注意: StringsStream.Read 返回 dnlib 的 UTF8String, 不是 string。
                    // WriteInlineString 只认 string, 直接塞 UTF8String 会
                    // "Invalid instruction operand" / "InlineString got UTF8String"。
                    // 关键: ldstr 的 token(0x70xxxxxx) 指向 **#US 用户字符串堆**,
                    // 不是 #Strings(元数据名字堆)。之前误用 StringsStream, 取到的是
                    // 元数据名字的碎片(例如 "ing>>-GetEnumerator>d__52"、"ources"),
                    // 于是所有字符串常量都是错的 —— 表现为按名字取资源拿到 null。
                    var u8 = ((ModuleDefMD)mod).USStream.Read(t & 0x00FFFFFF);   // 直接返回 string
                    operand = u8 ?? ""; break;
                }
                case OperandType.InlineMethod:
                case OperandType.InlineField:
                case OperandType.InlineType:
                case OperandType.InlineTok:
                case OperandType.InlineSig: {
                    uint t = BitConverter.ToUInt32(il, p); p += 4;
                    operand = ResolveTok(t, op.OperandType); break;
                }
                default: throw new Exception("unhandled operand type " + op.OperandType);
            }

            // 粗略栈深(只为 maxStack 兜底)
            int pop; PopN.TryGetValue(op.StackBehaviourPop.ToString(), out pop);
            depth -= pop; if (depth < 0) depth = 0;
            int push; PushN.TryGetValue(op.StackBehaviourPush.ToString(), out push);
            depth += push; if (depth > maxd) maxd = depth;

            off2idx[start] = list.Count;
            list.Add(new Instruction(op, operand));
        }
        if (p != il.Length) throw new Exception("IL length mismatch: consumed " + p + " of " + il.Length);

        // 回填
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

    static object ResolveTok(uint token, OperandType ot) {
        try {
            var o = mod.ResolveToken(token);
            if (o != null) return o;
        } catch { }
        // 兜底: 包成 MemberRef, 让 dnlib 自己解析
        try {
            var asType = mod.ResolveToken(token) as ITypeDefOrRef;
            if (asType != null) return asType;
        } catch { }
        return null;
    }

    static void AttachEh(CilBody body, byte[] eh, Dictionary<int, Instruction> offMap, int ilSize) {
        if (eh.Length < 4) return;
        uint cnt = BitConverter.ToUInt32(eh, 0);
        if (cnt == 0 || eh.Length < 4 + cnt * 28) return;
        // 结束偏移 == 代码长度 的子句没有对应指令; 不补哨兵的话 dnlib 会写出 end<start 的非法区间,
        // 运行时就是 BadImageFormatException: Bad IL range。
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
            offMap.TryGetValue((int)(tryOff + tryLen), out te);   // 末尾 -> null(dnlib 允许)
            offMap.TryGetValue((int)(hOff + hLen), out he);

            var neh = new ExceptionHandler(ExceptionHandlerType.Catch);
            if (flags == 1) neh.HandlerType = ExceptionHandlerType.Filter;
            else if (flags == 2) neh.HandlerType = ExceptionHandlerType.Finally;
            else if (flags == 4) neh.HandlerType = ExceptionHandlerType.Fault;

            if (neh.HandlerType == ExceptionHandlerType.Catch) {
                var ct = cls == 0 ? null : (mod.ResolveToken(cls) as ITypeDefOrRef);
                if (ct == null) { dropped++; continue; }   // 无 catch 类型的 catch 是非法的
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
        // ECMA 要求子句按 try 起点升序、同起点时区间长的在前(外层先)
        var ordered = body.ExceptionHandlers
            .OrderBy(h => h.TryStart == null ? int.MaxValue : h.TryStart.Offset)
            .ThenByDescending(h => (h.TryEnd == null || h.TryStart == null) ? 0 : h.TryEnd.Offset - h.TryStart.Offset)
            .ToList();
        body.ExceptionHandlers.Clear();
        foreach (var h in ordered) body.ExceptionHandlers.Add(h);
        if (dropped > 0) Console.WriteLine("    [eh] " + dropped + " clause(s) dropped");
    }


    // ---------- locsig 的类型解析(v2 新增, 官方 .loc -> Local) ----------
    static Dictionary<string, TypeDef> _locByFull;
    static Dictionary<string, ITypeDefOrRef> _locByRefFull;

    static TypeSig ParseType(string s) {
        s = s.Trim();
        if (s.EndsWith("[]")) { var e = ParseType(s.Substring(0, s.Length - 2)); return e == null ? null : new SZArraySig(e); }
        if (s.EndsWith("&")) { var e = ParseType(s.Substring(0, s.Length - 1)); return e == null ? null : new ByRefSig(e); }
        if (s.EndsWith("*")) { var e = ParseType(s.Substring(0, s.Length - 1)); return e == null ? null : new PtrSig(e); }
        int bt = s.IndexOf('`');
        if (bt > 0 && s.Contains("[[")) {
            // CLR 泛型名真实格式: Head`N[[Arg1, asm],[Arg2, asm]]
            // 外层 [ 是参数列表, 每个参数一层 [TypeName, asm] —— 旧实现按"每参数 [[..]]"切, 参数永远少一个!
            int gpStart = s.IndexOf('[', bt + 1);
            if (gpStart < 0) return null;
            string head = s.Substring(0, gpStart);
            int arity = 0;
            int.TryParse(head.Substring(bt + 1), out arity);
            int depth = 0, end = -1;
            for (int j = gpStart; j < s.Length; j++) {
                if (s[j] == '[') depth++;
                else if (s[j] == ']') { depth--; if (depth == 0) { end = j; break; } }
            }
            if (end < 0) return null;
            string list = s.Substring(gpStart + 1, end - gpStart - 1);
            var args = new List<TypeSig>();
            int i = 0;
            while (i < list.Length) {
                if (list[i] != '[') { i++; continue; }
                int d2 = 0, k = i;
                for (; k < list.Length; k++) {
                    if (list[k] == '[') d2++;
                    else if (list[k] == ']') { d2--; if (d2 == 0) { k++; break; } }
                }
                string block = list.Substring(i + 1, k - i - 2);
                int kd = 0, cm = -1;
                for (int q = 0; q < block.Length; q++) {
                    if (block[q] == '[') kd++;
                    else if (block[q] == ']') kd--;
                    else if (block[q] == ',' && kd == 0) { cm = q; break; }
                }
                string tn = cm > 0 ? block.Substring(0, cm).Trim() : block.Trim();
                args.Add(ParseType(tn));
                i = k;
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
                // ResolveTypeDef 在新建 TypeRefUser/坏元数据上会抛异常(官方原版基座 TypeRef
                // 表近乎空, 606 个 Dictionary\`2 missType 的根因) → 捕获后按名字判 class
                try {
                    var res = tdr.ResolveTypeDef();
                    if (res != null) return res.ToTypeSig(res.IsValueType);
                } catch { }
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
            case "Guid": case "Decimal": case "KeyValuePair`2":
                return true;
        }
        return false;
    }

    static TypeDef FindType(string full) {
        if (_locByFull == null) {
            _locByFull = new Dictionary<string, TypeDef>();
            foreach (var t in mod.GetTypes())
                if (!_locByFull.ContainsKey(t.FullName)) _locByFull[t.FullName] = t;
            _locByRefFull = new Dictionary<string, ITypeDefOrRef>();
            foreach (var tr in mod.GetTypeRefs())
                if (!_locByRefFull.ContainsKey(tr.FullName)) _locByRefFull[tr.FullName] = tr;
        }
        if (_locByFull.TryGetValue(full, out var td)) return td;
        string alt = full.Replace('+', '/');
        if (_locByFull.TryGetValue(alt, out var td2)) return td2;
        return null;
    }

    static ITypeDefOrRef FindRef(string full) {
        if (_locByFull == null) FindType(full);
        if (_locByRefFull.TryGetValue(full, out var r)) return r;
        int dot = full.LastIndexOf('.');
        if (dot <= 0) return null;
        var ns = full.Substring(0, dot);
        var nm = full.Substring(dot + 1);
        var asmRef = ns.StartsWith("System.Windows.Forms")
            ? mod.GetAssemblyRefs().FirstOrDefault(x => x.Name == "System.Windows.Forms")
            : null;
        if (asmRef == null) asmRef = mod.CorLibTypes.AssemblyRef;
        var trNew = new TypeRefUser(mod, ns, nm, asmRef);
        _locByRefFull[full] = trNew;
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
