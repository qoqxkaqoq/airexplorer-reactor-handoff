using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using dnlib.DotNet;

// dscan <official.exe> <dumpDir> [strings_tsv]
// 扫 16598 官方真体 dump（m_*.bin, 24B 头后为 IL）：
//   BC    = BouncyCastle TypeRef/MemberRef 命中（RSA 验证点候选）
//   GFP   = Environment::GetFolderPath 命中（便携化改造点，带 SpecialFolder 值）
//   STR   = 激活特征字符串 id 命中（先发现解密器：ldc.i4 <id>; call <dec>）
//   GATE  = 门控方法 xref（call/ldftn）
//   CAT   = REG/TIMER/NET/PROC/DIAG/ENV 引用（暗桩候选清单）
class DScan {
    struct Ins { public int off; public string op; public long arg; public int size; }

    static readonly Dictionary<string, uint[]> catKeys = new Dictionary<string, uint[]> {
        { "REG",   new[] { 0x0A000159u } }, // 占位，下面按名字填
    };

    static void Main(string[] a) {
        if (a.Length > 0 && a[0] == "one") { OneMain(a); return; }
        if (a.Length > 0 && a[0] == "enum") { EnumMain(a); return; }
        if (a.Length > 0 && a[0] == "mrf") { MrfMain(a); return; }
        var mod = ModuleDefMD.Load(a[0]);
        string dumpDir = a[1];

        // ---- 名字表 ----
        var nameOf = new Dictionary<uint, string>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
                nameOf[m.MDToken.Raw] = t.FullName + "::" + m.Name;

        Func<uint, string> res = tok => {
            if (nameOf.TryGetValue(tok, out var n)) return n;
            try { if (mod.ResolveToken(tok) is IMemberRef mr) return mr.FullName; } catch { }
            return "?0x" + tok.ToString("X8");
        };

        // ---- 分类 MemberRef 集合 ----
        var bcMr = new Dictionary<uint, string>();
        var catMr = new Dictionary<string, Dictionary<uint, string>>();
        foreach (var k in new[] { "REG", "TIMER", "NET", "PROC", "DIAG", "ENV" })
            catMr[k] = new Dictionary<uint, string>();
        foreach (var mr in mod.GetMemberRefs()) {
            string cn = mr.Class is ITypeDefOrRef t ? t.FullName : "";
            string full = mr.FullName;
            uint tok = mr.MDToken.Raw;
            if (cn.IndexOf("BouncyCastle", StringComparison.OrdinalIgnoreCase) >= 0) { bcMr[tok] = full; continue; }
            if (cn.StartsWith("Microsoft.Win32")) { catMr["REG"][tok] = full; continue; }
            if (cn.IndexOf("SystemEvents") >= 0) { catMr["TIMER"][tok] = full; continue; }
            if (cn.EndsWith(".Timer") || cn.IndexOf("DispatcherTimer") >= 0) { catMr["TIMER"][tok] = full; continue; }
            if (cn.IndexOf("WebRequest") >= 0 || cn.IndexOf("WebClient") >= 0 || cn.IndexOf("HttpClient") >= 0
                || cn.IndexOf("HttpWebRequest") >= 0 || cn.IndexOf("ServicePoint") >= 0 || cn.IndexOf("Dns.") >= 0
                || cn.IndexOf("TcpClient") >= 0 || cn.IndexOf("WebBrowser") >= 0) { catMr["NET"][tok] = full; continue; }
            if (cn.StartsWith("System.Diagnostics.Process")) { catMr["PROC"][tok] = full; continue; }
            if (cn.IndexOf("Debugger") >= 0 || cn.IndexOf("StackTrace") >= 0 || cn.IndexOf("ManagementObject") >= 0
                || cn.IndexOf("GetTickCount") >= 0 || cn.IndexOf("kernel32") >= 0 || cn.IndexOf("ntdll") >= 0) { catMr["DIAG"][tok] = full; continue; }
            if (cn.StartsWith("System.Environment")) { catMr["ENV"][tok] = full; continue; }
        }
        // BouncyCastle TypeRef（castclass/isinst/newarr/ldtoken 会引用类型 token）
        var bcTr = new Dictionary<uint, string>();
        foreach (var tr in mod.GetTypeRefs()) {
            string fn = tr.FullName;
            if (fn.IndexOf("BouncyCastle", StringComparison.OrdinalIgnoreCase) >= 0) bcTr[tr.MDToken.Raw] = fn;
        }
        Console.WriteLine("[INFO] bcMemberRef=" + bcMr.Count + " bcTypeRef=" + bcTr.Count +
            " REG=" + catMr["REG"].Count + " TIMER=" + catMr["TIMER"].Count + " NET=" + catMr["NET"].Count +
            " PROC=" + catMr["PROC"].Count + " DIAG=" + catMr["DIAG"].Count + " ENV=" + catMr["ENV"].Count);

        var sets = new List<Tuple<string, HashSet<uint>>> {
            Tuple.Create("BC", new HashSet<uint>(bcMr.Keys.Concat(bcTr.Keys))),
            Tuple.Create("GFP", new HashSet<uint> { 0x0A000159u }),
            Tuple.Create("REG", new HashSet<uint>(catMr["REG"].Keys)),
            Tuple.Create("TIMER", new HashSet<uint>(catMr["TIMER"].Keys)),
            Tuple.Create("NET", new HashSet<uint>(catMr["NET"].Keys)),
            Tuple.Create("PROC", new HashSet<uint>(catMr["PROC"].Keys)),
            Tuple.Create("DIAG", new HashSet<uint>(catMr["DIAG"].Keys)),
        };
        var gateSet = new HashSet<uint> { 0x06000CEEu, 0x06002127u, 0x06002128u, 0x06002154u, 0x06002155u, 0x06003AC8u, 0x06003AC9u };

        // 许可相关：① 所有名为 TestCollector/SaveModularProcessor 的 call 目标（含 MemberRef 经基类调用）
        //           ② 许可状态字段的 stfld/ldfld
        var licCall = new HashSet<uint>(gateSet);
        foreach (var mr in mod.GetMemberRefs())
            if (mr.Name == "TestCollector" || mr.Name == "SaveModularProcessor") licCall.Add(mr.MDToken.Raw);
        var licFld = new HashSet<uint> { 0x04000C3Du, 0x04000C4Au, 0x04000C4Bu };

        // ---- 字符串 id 空间 ----
        var tsvIds = new HashSet<uint>();
        var tsvStr = new Dictionary<uint, string>();
        if (a.Length > 2) {
            foreach (var ln in File.ReadAllLines(a[2])) {
                int sp = ln.IndexOf('\t');
                if (sp <= 0) continue;
                if (int.TryParse(ln.Substring(0, sp), out int v)) {
                    uint u = unchecked((uint)v);
                    tsvIds.Add(u); tsvStr[u] = ln.Substring(sp + 1);
                }
            }
        }
        var licIds = new HashSet<uint>();
        foreach (var id in new[] { 76744, 36920, 36994, 36664, 36746, 36514, 36382, 25116, 25136 })
            licIds.Add(unchecked((uint)id));

        // ---- 扫描结果容器 ----
        var catHits = new Dictionary<string, Dictionary<uint, List<uint>>>(); // cat -> mTok -> refToks
        foreach (var s in sets) catHits[s.Item1] = new Dictionary<uint, List<uint>>();
        catHits["LICCALL"] = new Dictionary<uint, List<uint>>();
        catHits["LICFLD"] = new Dictionary<uint, List<uint>>();
        var gateHits = new List<uint>();
        var decCnt = new Dictionary<uint, int>();                       // callTok -> 出现次数
        var decIds = new Dictionary<uint, HashSet<uint>>();             // callTok -> ids
        var immIds = new HashSet<uint>();                               // 所有 ldc.i4 立即数
        var licHit = new Dictionary<uint, List<uint>>();                // licId -> 方法 toks
        var licRaw = new Dictionary<uint, List<uint>>();                // licId -> 方法 toks（裸 imm）
        int files = 0, bodies = 0;

        foreach (var fp in Directory.GetFiles(dumpDir, "m_*.bin")) {
            files++;
            uint mTok;
            try { mTok = Convert.ToUInt32(Path.GetFileName(fp).Substring(2, 8), 16); } catch { continue; }
            var d = File.ReadAllBytes(fp);
            if (d.Length < 28) continue;
            int ilSize = (int)BitConverter.ToUInt32(d, 4);
            if (ilSize <= 0 || 24 + ilSize > d.Length) continue;
            var il = new byte[ilSize];
            Array.Copy(d, 24, il, 0, ilSize);
            bodies++;

            var ins = Decode(il);
            foreach (var s in sets) {
                var hits = ins.Where(x => IsCallLike(x.op) && x.arg > 0 && s.Item2.Contains(unchecked((uint)x.arg))).ToList();
                if (hits.Count == 0) continue;
                var list = new List<uint>(hits.Select(x => unchecked((uint)x.arg)).Distinct());
                catHits[s.Item1][mTok] = list;
                if (s.Item1 == "GFP") {
                    Console.WriteLine("\n[GFP-LIVE] 0x" + mTok.ToString("X8") + " " + Name(nameOf, mTok));
                    foreach (var i2 in Window(ins, hits[0].off, 14)) Console.WriteLine("      " + InsStr(i2, res, bcMr));
                }
            }
            var lhits = ins.Where(x => IsCallLike(x.op) && x.arg > 0 && licCall.Contains(unchecked((uint)x.arg))).ToList();
            if (lhits.Count > 0) catHits["LICCALL"][mTok] = lhits.Select(x => unchecked((uint)x.arg)).Distinct().ToList();
            var fhits = ins.Where(x => (x.op == "stfld" || x.op == "ldfld" || x.op == "ldsfld" || x.op == "stsfld") && licFld.Contains(unchecked((uint)x.arg))).ToList();
            if (fhits.Count > 0) catHits["LICFLD"][mTok] = fhits.Select(x => unchecked((uint)x.arg)).Distinct().ToList();
            if (ins.Any(x => IsCallLike(x.op) && gateSet.Contains(unchecked((uint)x.arg)))) gateHits.Add(mTok);

            // 通用常量表达式求值（覆盖 ldc.i4 单值与 xor/add/sub 链组合），遇 call 记录栈顶
            var estk = new Stack<uint>();
            for (int i = 0; i < ins.Count; i++) {
                var x = ins[i];
                if (x.op == "ldc.i4" || x.op == "ldc.i4.s") {
                    estk.Push(unchecked((uint)x.arg));
                    uint v = unchecked((uint)x.arg);
                    if (licIds.Contains(v)) (licRaw.TryGetValue(v, out var L) ? L : licRaw[v] = new List<uint>()).Add(mTok);
                } else if ((x.op == "xor" || x.op == "add" || x.op == "sub" || x.op == "and" || x.op == "or" || x.op == "shl") && estk.Count >= 2) {
                    uint b2 = estk.Pop(), a2 = estk.Pop();
                    estk.Push(x.op == "xor" ? a2 ^ b2 : x.op == "add" ? a2 + b2 : x.op == "sub" ? a2 - b2
                        : x.op == "and" ? a2 & b2 : x.op == "or" ? a2 | b2 : a2 << (int)(b2 & 31));
                } else if (x.op == "call" || x.op == "callvirt" || x.op == "newobj") {
                    if (estk.Count >= 1) {
                        uint v = estk.Peek(), ct = unchecked((uint)x.arg);
                        immIds.Add(v);
                        decCnt[ct] = decCnt.TryGetValue(ct, out int c) ? c + 1 : 1;
                        if (!decIds.TryGetValue(ct, out var set2)) decIds[ct] = set2 = new HashSet<uint>();
                        set2.Add(v);
                        if (licIds.Contains(v)) (licHit.TryGetValue(v, out var L2) ? L2 : licHit[v] = new List<uint>()).Add(mTok);
                    }
                    estk.Clear();
                } else if (x.op != "nop" && x.op != "dup" && x.op != "pop") {
                    estk.Clear();
                }
            }
        }

        Console.WriteLine("[INFO] files=" + files + " bodies=" + bodies);

        // ---- 输出 ----
        foreach (var s in sets) {
            var hs = catHits[s.Item1];
            Console.WriteLine("\n===== [" + s.Item1 + "] hitMethods=" + hs.Count + " =====");
            foreach (var kv in hs.Take(s.Item1 == "BC" ? 100 : 60)) {
                Console.Write("0x" + kv.Key.ToString("X8") + " " + Name(nameOf, kv.Key) + "  [");
                foreach (var r in kv.Value.Take(6)) Console.Write((s.Item1 == "BC" ? ShortBC(bcMr, bcTr, r) : Short(res(r))) + "; ");
                Console.WriteLine("]");
            }
        }
        Console.WriteLine("\n===== [GATE] callers of gate methods =====");
        foreach (var t in gateHits.Take(60)) Console.WriteLine("0x" + t.ToString("X8") + " " + Name(nameOf, t));
        foreach (var cn in new[] { "LICCALL", "LICFLD" }) {
            Console.WriteLine("\n===== [" + cn + "] hitMethods=" + catHits[cn].Count + " =====");
            foreach (var kv in catHits[cn].Take(80))
                Console.WriteLine("0x" + kv.Key.ToString("X8") + " " + Name(nameOf, kv.Key) + "  [" + string.Join("; ", kv.Value.Select(r => res(r))) + "]");
        }

        Console.WriteLine("\n===== [STRDEC] top10 (ldc.i4+call) =====");
        foreach (var kv in decCnt.OrderByDescending(x => x.Value).Take(10))
            Console.WriteLine("call 0x" + kv.Key.ToString("X8") + " " + Short(res(kv.Key)) + "  n=" + kv.Value +
                " distinctIds=" + (decIds.TryGetValue(kv.Key, out var s2) ? s2.Count : 0));
        var bestDec = decCnt.OrderByDescending(x => x.Value).FirstOrDefault();
        if (bestDec.Value > 0 && decIds.TryGetValue(bestDec.Key, out var bestSet)) {
            int xsec = bestSet.Count(tsvIds.Contains);
            Console.WriteLine("[STRDEC-XSEC] best=" + Short(res(bestDec.Key)) + " distinct=" + bestSet.Count + " xsecTsv=" + xsec);
            foreach (var id in bestSet.Take(5)) Console.WriteLine("   sample id=" + id + " tsv=" + (tsvStr.TryGetValue(id, out var sv) ? sv : "<no>"));
        }
        Console.WriteLine("\n===== [STR] license-id hits (imm+call) =====");
        foreach (var kv in licHit.OrderBy(x => x.Key))
            Console.WriteLine("id=" + (int)kv.Key + " \"" + (tsvStr.TryGetValue(kv.Key, out var sv2) ? sv2 : "?") + "\" -> " +
                string.Join(" ", kv.Value.Distinct().Take(20).Select(t => "0x" + t.ToString("X8") + "(" + Name(nameOf, t) + ")")));
        Console.WriteLine("\n===== [STRAW] license-id raw imm only =====");
        foreach (var kv in licRaw.OrderBy(x => x.Key)) {
            var onlyRaw = kv.Value.Where(t => !(licHit.TryGetValue(kv.Key, out var lh) && lh.Contains(t)));
            Console.WriteLine("id=" + (int)kv.Key + " rawOnly -> " + string.Join(" ", onlyRaw.Take(20).Select(t => "0x" + t.ToString("X8") + "(" + Name(nameOf, t) + ")")));
        }
    }

    // mrf <exe> <pattern> — 列出 MemberRef/TypeRef/TypeDef 名字匹配 pattern 的 token
    static void MrfMain(string[] a) {
        var mod = ModuleDefMD.Load(a[1]);
        foreach (var mr in mod.GetMemberRefs())
            if (mr.FullName.IndexOf(a[2], StringComparison.OrdinalIgnoreCase) >= 0)
                Console.WriteLine("MR 0x" + mr.MDToken.Raw.ToString("X8") + " " + mr.FullName);
        foreach (var tr in mod.GetTypeRefs())
            if (tr.FullName.IndexOf(a[2], StringComparison.OrdinalIgnoreCase) >= 0)
                Console.WriteLine("TR 0x" + tr.MDToken.Raw.ToString("X8") + " " + tr.FullName);
        foreach (var td in mod.GetTypes())
            if (td.FullName.IndexOf(a[2], StringComparison.OrdinalIgnoreCase) >= 0)
                Console.WriteLine("TD 0x" + td.MDToken.Raw.ToString("X8") + " " + td.FullName);
    }

    // enum <exe> <tok> — 打印枚举字段与常量值
    static void EnumMain(string[] a) {
        var mod = ModuleDefMD.Load(a[1]);
        var t = mod.ResolveToken(Convert.ToUInt32(a[2], 16)) as TypeDef;
        if (t == null) { Console.WriteLine("no type"); return; }
        Console.WriteLine("# " + t.FullName + " (base=" + t.BaseType?.FullName + ")");
        foreach (var f in t.Fields) {
            string v = "";
            if (f.Constant != null) v = " = " + f.Constant.Value;
            Console.WriteLine("  " + f.Name + v);
        }
    }

    // one <exe> <dumpDir> <tok>... — 单方法全量反汇编（带符号名解析）
    static void OneMain(string[] a) {
        var mod = ModuleDefMD.Load(a[1]);
        string dumpDir = a[2];
        foreach (var tk in a.Skip(3)) {
            uint tok = Convert.ToUInt32(tk, 16);
            Console.WriteLine("\n########## 0x" + tok.ToString("X8") + " ##########");
            try {
                if (mod.ResolveToken(tok) is MethodDef md)
                    Console.WriteLine("# sig: " + md.FullName + (md.IsStatic ? " static" : ""));
            } catch { }
            string fp = Path.Combine(dumpDir, "m_" + tok.ToString("X8") + ".bin");
            if (!File.Exists(fp)) { Console.WriteLine("# <no dump>"); continue; }
            var d = File.ReadAllBytes(fp);
            if (d.Length < 24) continue;
            int ilSize = (int)BitConverter.ToUInt32(d, 4);
            int ms = (int)BitConverter.ToUInt32(d, 8), eh = (int)BitConverter.ToUInt32(d, 12);
            Console.WriteLine("# ilSize=" + ilSize + " maxStack=" + ms + " ehCount=" + eh);
            var il = new byte[ilSize];
            Array.Copy(d, 24, il, 0, ilSize);
            var lp = Path.Combine(dumpDir, "m_" + tok.ToString("X8") + ".loc");
            if (File.Exists(lp)) Console.WriteLine("# locals: " + File.ReadAllText(lp).Replace("\r\n", " | ").Replace("\n", " | "));
            foreach (var x in Decode(il)) Console.WriteLine("  il_" + x.off.ToString("X4") + ": " + OneOp(mod, x));
        }
    }
    static string OneOp(ModuleDef mod, Ins x) {
        var sb = new StringBuilder(x.op);
        switch (x.op) {
            case "call": case "callvirt": case "newobj": case "ldftn": case "ldvirtftn": case "jmp":
                sb.Append(" " + Resolved(mod, (uint)x.arg)); break;
            case "ldstr": sb.Append(" <ldstr 0x" + ((uint)x.arg).ToString("X8") + ">"); break;
            case "ldfld": case "ldflda": case "stfld": case "ldsfld": case "ldsflda": case "stsfld":
                sb.Append(" " + Resolved(mod, (uint)x.arg)); break;
            case "castclass": case "isinst": case "newarr": case "box": case "unbox.any": case "ldtoken": case "ldelema":
                sb.Append(" " + Resolved(mod, (uint)x.arg)); break;
            case "br": case "br.s": case "brfalse": case "brfalse.s": case "brtrue": case "brtrue.s":
            case "beq": case "bge": case "bgt": case "ble": case "blt": case "bne.un": case "bge.un": case "bgt.un": case "ble.un": case "blt.un":
            case "beq.s": case "bge.s": case "bgt.s": case "ble.s": case "blt.s": case "bne.un.s": case "bge.un.s": case "bgt.un.s": case "ble.un.s": case "blt.un.s":
            case "leave": case "leave.s":
                sb.Append(" -> " + ((uint)x.arg).ToString("X4")); break;
            case "switch": sb.Append(" n=" + x.arg); break;
            default:
                if (x.arg != 0 || x.op == "ldc.i4") sb.Append(" " + x.arg + " (0x" + ((uint)x.arg).ToString("X") + ")");
                break;
        }
        return sb.ToString();
    }
    static string Resolved(ModuleDef mod, uint tok) {
        if (tok == 0x06004196) return "ITP<06004196>";
        try {
            var r = mod.ResolveToken(tok);
            if (r is MethodDef md2) return "0x" + tok.ToString("X8") + " " + md2.DeclaringType.FullName + "::" + md2.Name + (md2.IsStatic ? " [static]" : "");
            if (r is FieldDef fd2) return "0x" + tok.ToString("X8") + " fld " + fd2.DeclaringType?.FullName + "::" + fd2.Name;
            if (r is IMemberRef mr2) return "0x" + tok.ToString("X8") + " " + mr2.FullName;
            if (r != null) return "0x" + tok.ToString("X8") + " " + r.ToString();
        } catch { }
        return "0x" + tok.ToString("X8") + " <unresolved>";
    }

    static string Name(Dictionary<uint, string> nameOf, uint t) => nameOf.TryGetValue(t, out var n) ? n : "?0x" + t.ToString("X8");
    static string Short(string s) { int i = s.LastIndexOf('('); if (i > 0) s = s.Substring(0, i); var p = s.Split(':'); return p.Length > 1 ? p[p.Length - 2].Split('.').Last() + "::" + p.Last() : s; }
    static string ShortBC(Dictionary<uint, string> bcMr, Dictionary<uint, string> bcTr, uint t)
        => bcMr.TryGetValue(t, out var s) ? s.Substring(s.LastIndexOf(']') + 1) : (bcTr.TryGetValue(t, out var s2) ? s2 : "0x" + t.ToString("X8"));
    static bool IsCallLike(string op) => op == "call" || op == "callvirt" || op == "newobj" || op == "ldftn" || op == "ldvirtftn";

    static List<Ins> Window(List<Ins> ins, int off, int n) {
        int idx = ins.FindIndex(x => x.off == off);
        if (idx < 0) return new List<Ins>();
        return ins.Skip(Math.Max(0, idx - n)).Take(n * 2 + 1).ToList();
    }
    static string InsStr(Ins x, Func<uint, string> res, Dictionary<uint, string> bcMr) {
        var sb = new StringBuilder("il_" + x.off.ToString("X4") + ": " + x.op);
        if (x.op == "call" || x.op == "callvirt" || x.op == "newobj" || x.op == "ldftn") sb.Append(" 0x" + ((uint)x.arg).ToString("X8") + " " + Short(res((uint)x.arg)));
        else if (x.arg != 0 || x.op == "ldc.i4") sb.Append(" " + x.arg);
        return sb.ToString();
    }

    // ---- 线性反汇编（覆盖常用 opcode，未知则步进 1 并标记 ??）----
    static readonly Dictionary<int, Tuple<string, int>> T1 = new Dictionary<int, Tuple<string, int>>();
    static void Add(int b, string n, int o) => T1[b] = Tuple.Create(n, o);
    static DScan() {
        Add(0x00, "nop", 0); Add(0x01, "break", 0);
        for (int i = 0; i < 4; i++) { Add(0x02 + i, "ldarg." + i, 0); Add(0x06 + i, "ldloc." + i, 0); Add(0x0A + i, "stloc." + i, 0); }
        Add(0x0E, "ldarg.s", 1); Add(0x0F, "ldarga.s", 1); Add(0x10, "starg.s", 1);
        Add(0x11, "ldloc.s", 1); Add(0x12, "ldloca.s", 1); Add(0x13, "stloc.s", 1);
        Add(0x14, "ldnull", 0); Add(0x15, "ldc.i4.m1", 0);
        for (int i = 0; i <= 8; i++) Add(0x16 + i, "ldc.i4." + i, 0);
        Add(0x1F, "ldc.i4.s", 1); Add(0x20, "ldc.i4", 4); Add(0x21, "ldc.i8", 8);
        Add(0x22, "ldc.r4", 4); Add(0x23, "ldc.r8", 8);
        Add(0x25, "dup", 0); Add(0x26, "pop", 0); Add(0x27, "jmp", 4);
        Add(0x28, "call", 4); Add(0x29, "calli", 4); Add(0x2A, "ret", 0);
        Add(0x2B, "br.s", 1); Add(0x2C, "brfalse.s", 1); Add(0x2D, "brtrue.s", 1);
        Add(0x2E, "beq.s", 1); Add(0x2F, "bge.s", 1); Add(0x30, "bgt.s", 1); Add(0x31, "ble.s", 1); Add(0x32, "blt.s", 1);
        Add(0x33, "bne.un.s", 1); Add(0x34, "bge.un.s", 1); Add(0x35, "bgt.un.s", 1); Add(0x36, "ble.un.s", 1); Add(0x37, "blt.un.s", 1);
        Add(0x38, "br", 4); Add(0x39, "brfalse", 4); Add(0x3A, "brtrue", 4);
        Add(0x3B, "beq", 4); Add(0x3C, "bge", 4); Add(0x3D, "bgt", 4); Add(0x3E, "ble", 4); Add(0x3F, "blt", 4);
        Add(0x40, "bne.un", 4); Add(0x41, "bge.un", 4); Add(0x42, "bgt.un", 4); Add(0x43, "ble.un", 4); Add(0x44, "blt.un", 4);
        Add(0x45, "switch", -1);
        Add(0x46, "ldind.i1", 0); Add(0x47, "ldind.u1", 0); Add(0x48, "ldind.i2", 0); Add(0x49, "ldind.u2", 0);
        Add(0x4A, "ldind.i4", 0); Add(0x4B, "ldind.u4", 0); Add(0x4C, "ldind.i8", 0); Add(0x4D, "ldind.i", 0);
        Add(0x4E, "ldind.r4", 0); Add(0x4F, "ldind.r8", 0); Add(0x50, "ldind.ref", 0);
        Add(0x51, "stind.ref", 0); Add(0x52, "stind.i1", 0); Add(0x53, "stind.i2", 0); Add(0x54, "stind.i4", 0);
        Add(0x55, "stind.i8", 0); Add(0x56, "stind.r4", 0); Add(0x57, "stind.r8", 0);
        Add(0x58, "add", 0); Add(0x59, "sub", 0); Add(0x5A, "mul", 0); Add(0x5B, "div", 0); Add(0x5C, "div.un", 0);
        Add(0x5D, "rem", 0); Add(0x5E, "rem.un", 0); Add(0x5F, "and", 0); Add(0x60, "or", 0); Add(0x61, "xor", 0);
        Add(0x62, "shl", 0); Add(0x63, "shr", 0); Add(0x64, "shr.un", 0); Add(0x65, "neg", 0); Add(0x66, "not", 0);
        Add(0x67, "conv.i1", 0); Add(0x68, "conv.i2", 0); Add(0x69, "conv.i4", 0); Add(0x6A, "conv.i8", 0);
        Add(0x6B, "conv.r4", 0); Add(0x6C, "conv.r8", 0); Add(0x6D, "conv.u4", 0); Add(0x6E, "conv.u8", 0);
        Add(0x6F, "callvirt", 4); Add(0x70, "cpobj", 4); Add(0x71, "ldobj", 4); Add(0x72, "ldstr", 4);
        Add(0x73, "newobj", 4); Add(0x74, "castclass", 4); Add(0x75, "isinst", 4); Add(0x76, "conv.r.un", 0);
        Add(0x79, "unbox", 4); Add(0x7A, "throw", 0); Add(0x7B, "ldfld", 4); Add(0x7C, "ldflda", 4); Add(0x7D, "stfld", 4);
        Add(0x7E, "ldsfld", 4); Add(0x7F, "ldsflda", 4); Add(0x80, "stsfld", 4); Add(0x81, "stobj", 4);
        Add(0x82, "conv.ovf.i1.un", 0); Add(0x8C, "box", 4); Add(0x8D, "newarr", 4); Add(0x8E, "ldlen", 0);
        Add(0x8F, "ldelema", 4); Add(0x90, "ldelem.i1", 0); Add(0x91, "ldelem.u1", 0); Add(0x92, "ldelem.i2", 0);
        Add(0x93, "ldelem.u2", 0); Add(0x94, "ldelem.i4", 0); Add(0x95, "ldelem.u4", 0); Add(0x96, "ldelem.i8", 0);
        Add(0x97, "ldelem.i", 0); Add(0x98, "ldelem.r4", 0); Add(0x99, "ldelem.r8", 0); Add(0x9A, "ldelem.ref", 0);
        Add(0x9B, "stelem.i", 0); Add(0x9C, "stelem.i1", 0); Add(0x9D, "stelem.i2", 0); Add(0x9E, "stelem.i4", 0);
        Add(0x9F, "stelem.i8", 0); Add(0xA0, "stelem.r4", 0); Add(0xA1, "stelem.r8", 0); Add(0xA2, "stelem.ref", 0);
        Add(0xA3, "ldelem", 4); Add(0xA4, "stelem", 4); Add(0xA5, "unbox.any", 4);
        Add(0xC2, "refanyval", 4); Add(0xC6, "mkrefany", 4);
        Add(0xD0, "ldtoken", 4); Add(0xD1, "conv.u2", 0); Add(0xD2, "conv.u1", 0); Add(0xD3, "conv.i", 0);
        Add(0xDD, "leave", 4); Add(0xDE, "leave.s", 1); Add(0xDF, "stind.i", 0); Add(0xE0, "conv.u", 0);
        // FE 前缀
        Add(0xFE01, "ceq", 0); Add(0xFE02, "cgt", 0); Add(0xFE03, "cgt.un", 0); Add(0xFE04, "clt", 0); Add(0xFE05, "clt.un", 0);
        Add(0xFE06, "ldftn", 4); Add(0xFE07, "ldvirtftn", 4); Add(0xFE09, "ldarg", 2); Add(0xFE0A, "ldarga", 2);
        Add(0xFE0B, "starg", 2); Add(0xFE0C, "ldloc", 2); Add(0xFE0D, "stloc", 2); Add(0xFE0E, "localloc", 0);
        Add(0xFE11, "endfilter", 0); Add(0xFE12, "unaligned", 1); Add(0xFE13, "volatile", 0); Add(0xFE14, "tail", 0);
        Add(0xFE15, "initobj", 4); Add(0xFE16, "constrained", 4); Add(0xFE17, "cpblk", 0); Add(0xFE18, "initblk", 0);
        Add(0xFE19, "no.", 1); Add(0xFE1A, "rethrow", 0); Add(0xFE1C, "sizeof", 4); Add(0xFE1D, "refanytype", 0); Add(0xFE1E, "ckfinite", 0);
    }

    static List<Ins> Decode(byte[] il) {
        var l = new List<Ins>(il.Length / 2);
        int i = 0;
        while (i < il.Length) {
            int off = i;
            int b = il[i++];
            if (b == 0xFE) {
                if (i >= il.Length) break;
                int b2 = il[i++];
                int key = 0xFE00 | b2;
                if (T1.TryGetValue(key, out var e1)) {
                    int sz = e1.Item2;
                    if (sz < 0) { i += SwitchSkip(il, i) + 0; l.Add(new Ins { off = off, op = e1.Item1, arg = 0, size = i - off }); continue; }
                    long farg = ReadArg(il, ref i, sz, false);
                    l.Add(new Ins { off = off, op = e1.Item1, arg = farg, size = i - off });
                } else l.Add(new Ins { off = off, op = "??" + b2.ToString("X2"), arg = 0, size = i - off });
                continue;
            }
            if (!T1.TryGetValue(b, out var e)) { l.Add(new Ins { off = off, op = "??" + b.ToString("X2"), arg = 0, size = i - off }); continue; }
            int size = e.Item2;
            if (size < 0) { // switch
                int n = (int)ReadArg(il, ref i, 4, false);
                if (n < 0) n = 0;
                i += n * 4;
                if (i > il.Length) i = il.Length;
                l.Add(new Ins { off = off, op = e.Item1, arg = n, size = i - off });
                continue;
            }
            bool signed = e.Item1 == "ldc.i4.s" || e.Item1 == "br.s" || e.Item1.EndsWith(".s");
            long arg = ReadArg(il, ref i, size, signed && size == 1);
            if (size == 1 && !signed) arg = il.Length >= i ? il[i - 1] : 0; // unsigned byte operand (ldarg.s etc)
            l.Add(new Ins { off = off, op = e.Item1, arg = arg, size = i - off });
        }
        return l;
    }
    static int SwitchSkip(byte[] il, int i) {
        if (i + 4 > il.Length) return 0;
        int n = (int)BitConverter.ToUInt32(il, i);
        return 4 + n * 4;
    }
    static long ReadArg(byte[] il, ref int i, int size, bool signed) {
        if (i + size > il.Length) { i = il.Length; return 0; }
        long v = 0;
        for (int k = 0; k < size; k++) v |= (long)il[i + k] << (8 * k);
        i += size;
        if (signed && size == 1 && (v & 0x80) != 0) v -= 0x100;
        if (signed && size == 2 && (v & 0x8000) != 0) v -= 0x10000;
        return v;
    }
}
