using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// agscan <exe> [cmd...]
// 本地静态诊断工具 (dnlib, net8.0):
//   types <关键词>                 — 模糊列出类型全名+token+方法数(核查 AG/RW 真实全名)
//   ag                             — ArgumentGateway 类型全诊断: 全名/字段/方法(ilSize)
//   m <tokenHex>                   — 单方法转储: 全名/签名/局部/EH/指令数
//   il <tokenHex> <out.il>         — 单方法 IL 全文导出(含 switch 表)
//   type <全名>                    — 类型全成员转储
//   stubs                          — 全部 nop;nop;nop;ret 桩统计
class AgScan {
    static ModuleDefMD mod;
    static void Main(string[] a) {
        mod = ModuleDefMD.Load(a[0]);
        Console.WriteLine("[agscan] " + mod.Assembly.FullName + "  md5=" + Md5(a[0]));
        Console.WriteLine("[agscan] types=" + mod.GetTypes().Count() + " methods=" + mod.GetTypes().Sum(t => t.Methods.Count));
        if (a.Length < 2) return;
        switch (a[1]) {
            case "types": CmdTypes(a[2]); break;
            case "ag": CmdAg(); break;
            case "m": CmdM(a[2]); break;
            case "il": CmdIl(a[2], a[3]); break;
            case "type": CmdType(a[2]); break;
            case "stubs": CmdStubs(); break;
            case "refs": CmdRefs(a[2]); break;
            case "sig2loc": CmdSig2Loc(a[2], a[3]); break;
        }
    }
    // sig2loc <hex> <out.loc> — JIT localsSig(LocalVarSig blob) → bodyswap 兼容 .loc(index|isPinned|TypeFullName)
    static void CmdSig2Loc(string hex, string outPath) {
        hex = hex.Replace("|", "").Trim();
        var b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        if (b.Length < 2 || b[0] != 0x07) { Console.WriteLine("[sig2loc] not a LocalVarSig (first byte 0x" + (b.Length > 0 ? b[0].ToString("X2") : "?") + ")"); return; }
        int p = 1, count;
        // 压缩整数
        if ((b[p] & 0x80) == 0) { count = b[p]; p += 1; }
        else if ((b[p] & 0xC0) == 0x80) { count = ((b[p] & 0x3F) << 8) | b[p + 1]; p += 2; }
        else { count = ((b[p] & 0x1F) << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]; p += 4; }
        var sb = new StringBuilder();
        for (int idx = 0; idx < count && p < b.Length; idx++) {
            bool pinned = false;
            // pinned 是自定义修饰符(cmod_opt 0x20 + token)，实际编码: ELEMENT_TYPE_PINNED(0x45) 出现在类型后? CLR 里 pinned 在 sig 里是前缀 custom mod
            // 实测 forcedump/.loc 由运行时产生, 这里按标准 LocalVarSig: [pinned]? type; pinned 以 0x45 前缀出现
            while (p < b.Length && b[p] == 0x45) { pinned = true; p++; }
            var sig = ParseSigType(b, ref p, "");
            if (sig == null) { Console.WriteLine("[sig2loc] parse fail at local " + idx + " offset " + p); return; }
            sb.Append(idx).Append('|').Append(pinned ? 1 : 0).Append('|').Append(sig).Append('\n');
        }
        File.WriteAllText(outPath, sb.ToString());
        Console.WriteLine("[sig2loc] wrote " + outPath + " locals=" + count);
    }
    static string Compressed(uint v) { return v.ToString(); }
    static string ParseSigType(byte[] b, ref int p, string ctx) {
        if (p >= b.Length) return null;
        byte t = b[p++];
        switch (t) {
            case 0x02: return "System.Boolean"; case 0x03: return "System.Char";
            case 0x04: return "System.SByte"; case 0x05: return "System.Byte";
            case 0x06: return "System.Int16"; case 0x07: return "System.UInt16";
            case 0x08: return "System.Int32"; case 0x09: return "System.UInt32";
            case 0x0A: return "System.Int64"; case 0x0B: return "System.UInt64";
            case 0x0C: return "System.Single"; case 0x0D: return "System.Double";
            case 0x0E: return "System.String"; case 0x1C: return "System.Object";
            case 0x18: return "System.IntPtr"; case 0x19: return "System.UIntPtr";
            case 0x1D: { var e = ParseSigType(b, ref p, ctx); return e == null ? null : e + "[]"; }
            case 0x10: { var e = ParseSigType(b, ref p, ctx); return e == null ? null : e + "&"; }
            case 0x0F: { var e = ParseSigType(b, ref p, ctx); return e == null ? null : e + "*"; }
            case 0x45: return ParseSigType(b, ref p, ctx); // pinned 修饰符, 当作前缀跳过
            case 0x11: case 0x12: {
                // TypeDefOrRefEncoded = 压缩整数 v; 低2位: 0=TypeDef 1=TypeRef 2=TypeSpec; rid = v >> 2
                if (p >= b.Length) return null;
                uint v;
                byte c = b[p++];
                if ((c & 0x80) == 0) v = c;
                else if ((c & 0xC0) == 0x80) { v = (uint)(((c & 0x3F) << 8) | b[p++]); }
                else { v = (uint)(((c & 0x1F) << 24) | (b[p] << 16) | (b[p + 1] << 8) | b[p + 2]); p += 3; }
                uint table = (v & 0x3) == 0 ? 0x02u : (v & 0x3) == 1 ? 0x01u : 0x1Bu;
                uint mdTok = (table << 24) | (v >> 2);
                var tr = mod.ResolveToken((int)mdTok) as ITypeDefOrRef;
                return tr != null ? tr.FullName : "?0x" + mdTok.ToString("X8");
            }
            case 0x15: { // GENERICINST
                bool isVal = b[p] == 0x11; p++;
                var baseT = ParseSigType(b, ref p, ctx); // CLASS/VALUETYPE
                if (baseT == null) return null;
                if (p >= b.Length) return null;
                int argc; { byte c = b[p++]; argc = (c & 0x80) == 0 ? c : ((c & 0x3F) << 8) | b[p++]; }
                var args = new List<string>();
                for (int i2 = 0; i2 < argc; i2++) { var a = ParseSigType(b, ref p, ctx); if (a == null) return null; args.Add(a); }
                // 还原 List`1[[T]] 运行时格式
                int bt = baseT.IndexOf('`');
                if (bt > 0) {
                    var arity = baseT.Substring(bt + 1);
                    int n; int.TryParse(arity.TrimEnd(new[] { '\0' }), out n);
                    var inner = string.Join(",", args.Select(x => "[[" + x + "]]"));
                    return baseT + "[[" + inner + "]]";
                }
                return baseT + "<" + string.Join(",", args) + ">";
            }
            case 0x13: return "!!" + b[p++];  // VAR
            case 0x1E: return "!" + b[p++];   // MVAR
            default: return null;
        }
    }
    // refs <kw> — 扫全模块指令里引用了名字含 kw 的字段/方法(newobj)的位置
    static void CmdRefs(string kw) {
        foreach (var t in mod.GetTypes()) foreach (var m in t.Methods) {
            if (!m.HasBody) continue;
            foreach (var ins in m.Body.Instructions) {
                string who = null;
                if (ins.Operand is IField f && (f.Name.String.Contains(kw) || f.DeclaringType.Name.String.Contains(kw)))
                    who = "fld " + f.FullName;
                else if (ins.Operand is IMethod im && (im.Name.String.Contains(kw) || (im.DeclaringType != null && im.DeclaringType.Name.String.Contains(kw))))
                    who = "m " + im.FullName;
                if (who != null)
                    Console.WriteLine("  0x" + m.MDToken.Raw.ToString("X8") + " " + m.DeclaringType.Name.String + "::" + m.Name.String + " @IL_" + ins.Offset.ToString("X4") + " " + ins.OpCode.Name + " " + who);
            }
        }
    }
    static string Md5(string p) {
        using (var md5 = System.Security.Cryptography.MD5.Create())
        using (var s = File.OpenRead(p))
            return BitConverter.ToString(md5.ComputeHash(s)).Replace("-", "");
    }
    static void CmdTypes(string kw) {
        foreach (var t in mod.GetTypes()) {
            if (t.FullName.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0)
                Console.WriteLine("  0x" + (0x02000000u | t.Rid).ToString("X8") + "  " + t.FullName + "  methods=" + t.Methods.Count + " staticFields=" + t.Fields.Count(f => f.IsStatic));
        }
    }
    static void CmdAg() {
        foreach (var kw in new[] { "ArgumentGateway", "RequestWorker" }) {
            Console.WriteLine("=== kw=" + kw + " ===");
            foreach (var t in mod.GetTypes()) {
                if (!t.Name.String.Contains(kw)) continue;
                Console.WriteLine("TYPE 0x" + (0x02000000u | t.Rid).ToString("X8") + "  " + t.FullName);
                foreach (var f in t.Fields)
                    Console.WriteLine("  FIELD 0x" + (0x04000000u | f.Rid).ToString("X8") + " " + (f.IsStatic ? "static " : "") + f.FieldType.FullName + " " + f.Name.String);
                foreach (var m in t.Methods) {
                    int il = 0, nop = 0;
                    if (m.HasBody && m.Body.Instructions != null) {
                        il = m.Body.Instructions.Count;
                        nop = m.Body.Instructions.Count(i => i.OpCode.Code == Code.Nop);
                    }
                    Console.WriteLine("  METH 0x" + m.MDToken.Raw.ToString("X8") + " " + m.FullName.Substring(m.FullName.IndexOf(' ') + 1) + " il=" + il + (m.HasBody && il == 4 && nop >= 3 ? "  [STUB]" : ""));
                }
            }
        }
    }
    static MethodDef Resolve(string tokHex) {
        uint tok = Convert.ToUInt32(tokHex, 16);
        var m = mod.ResolveToken(tok) as MethodDef;
        if (m == null) Console.WriteLine("token 0x" + tok.ToString("X8") + " not a MethodDef (got " + (mod.ResolveToken(tok) != null ? mod.ResolveToken(tok).GetType().Name : "null") + ")");
        return m;
    }
    static void CmdM(string tokHex) {
        var m = Resolve(tokHex);
        if (m == null) return;
        Console.WriteLine("METHOD 0x" + m.MDToken.Raw.ToString("X8") + "  " + m.FullName);
        Console.WriteLine("  impl=" + m.ImplAttributes + " attr=" + m.Attributes);
        if (!m.HasBody) { Console.WriteLine("  no body"); return; }
        var b = m.Body;
        Console.WriteLine("  instructions=" + b.Instructions.Count + " locals=" + b.Variables.Count + " eh=" + b.ExceptionHandlers.Count + " maxStack=" + b.MaxStack + " initLocals=" + b.InitLocals);
        for (int i = 0; i < b.Variables.Count; i++)
            Console.WriteLine("    V_" + i + "  " + b.Variables[i].Type.FullName);
        foreach (var eh in b.ExceptionHandlers)
            Console.WriteLine("    EH " + eh.HandlerType + " try=[" + (eh.TryStart != null ? eh.TryStart.Offset.ToString("X4") : "?") + ".." + (eh.TryEnd != null ? eh.TryEnd.Offset.ToString("X4") : "?") + ") handler=" + (eh.HandlerStart != null ? eh.HandlerStart.Offset.ToString("X4") : "?") + " catchType=" + (eh.CatchType != null ? eh.CatchType.FullName : "null"));
    }
    static void CmdIl(string tokHex, string outPath) {
        var m = Resolve(tokHex);
        if (m == null || !m.HasBody) return;
        var sb = new StringBuilder();
        sb.AppendLine("// " + m.FullName + "  token=0x" + m.MDToken.Raw.ToString("X8"));
        sb.AppendLine("// locals=" + m.Body.Variables.Count + " eh=" + m.Body.ExceptionHandlers.Count);
        foreach (var v in m.Body.Variables) sb.AppendLine("//   V_" + v.Index + "  " + v.Type.FullName);
        foreach (var ins in m.Body.Instructions) {
            var line = "IL_" + ins.Offset.ToString("X4") + ":  " + ins.OpCode.Name;
            if (ins.Operand != null) {
                if (ins.Operand is Instruction t) line += " -> IL_" + t.Offset.ToString("X4");
                else if (ins.Operand is Instruction[] sw) line += " (" + sw.Length + " targets: " + string.Join(",", sw.Select(x => "IL_" + x.Offset.ToString("X4"))) + ")";
                else if (ins.Operand is Local l) line += " V_" + l.Index;
                else if (ins.Operand is IField f) line += " 0x" + f.MDToken.Raw.ToString("X8") + " " + f.FullName;
                else if (ins.Operand is IMethod im) line += " 0x" + im.MDToken.Raw.ToString("X8") + " " + im.FullName;
                else if (ins.Operand is ITypeDefOrRef tdr) line += " 0x" + tdr.MDToken.Raw.ToString("X8") + " " + tdr.FullName;
                else line += " " + ins.Operand;
            }
            sb.AppendLine(line);
        }
        File.WriteAllText(outPath, sb.ToString());
        Console.WriteLine("[agscan] wrote " + outPath + " (" + m.Body.Instructions.Count + " instrs)");
    }
    static void CmdType(string full) {
        var t = mod.Find(full, false);
        if (t == null) { Console.WriteLine("type not found: " + full); return; }
        Console.WriteLine("TYPE 0x" + (0x02000000u | t.Rid).ToString("X8") + " " + t.FullName + " base=" + (t.BaseType != null ? t.BaseType.FullName : "null"));
        foreach (var f in t.Fields) Console.WriteLine("  FIELD " + (f.IsStatic ? "static " : "inst   ") + f.FieldType.FullName + " " + f.Name.String);
        foreach (var m in t.Methods) Console.WriteLine("  METH 0x" + m.MDToken.Raw.ToString("X8") + " " + m.FullName + (m.HasBody ? " il=" + m.Body.Instructions.Count : " no-body"));
    }
    static void CmdStubs() {
        int stubs = 0, total = 0;
        foreach (var t in mod.GetTypes()) foreach (var m in t.Methods) {
            total++;
            if (m.HasBody && m.Body.Instructions.Count == 4
                && m.Body.Instructions[0].OpCode.Code == Code.Nop && m.Body.Instructions[1].OpCode.Code == Code.Nop
                && m.Body.Instructions[2].OpCode.Code == Code.Nop && m.Body.Instructions[3].OpCode.Code == Code.Ret) stubs++;
        }
        Console.WriteLine("[agscan] stub(nop;nop;nop;ret)=" + stubs + " / total=" + total);
    }
}
