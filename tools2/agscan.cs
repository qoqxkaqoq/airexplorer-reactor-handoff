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
