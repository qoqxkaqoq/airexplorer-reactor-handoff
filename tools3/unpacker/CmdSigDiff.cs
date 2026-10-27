using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>
/// sigdiff — 对比官方 exe 与产物中同 token 对象的"身份"(Name/Class/Sig blob)。
/// Necrobit 只加密方法体, 元数据表(含签名 blob)未加密 -> 官方磁盘元数据即运行时身份。
/// 用法: sigdiff &lt;official.exe&gt; &lt;prod.exe&gt; &lt;methodTok&gt; [moreToks...]
/// </summary>
public static class CmdSigDiff
{
    public static int Run(string[] args)
    {
        if (args.Length < 4) { Console.WriteLine("usage: sigdiff <official.exe> <prod.exe> <methodTok> [...]"); return 2; }
        var off = ModuleDefMD.Load(args[1]);
        var prod = ModuleDefMD.Load(args[2]);

        var tokens = new HashSet<uint>();
        foreach (var a in args.Skip(3))
        {
            uint t = Convert.ToUInt32(a.Trim().Replace("0x", ""), 16);
            tokens.Add(t);
            // 展开方法体引用的全部 operand token + locals
            if (off.ResolveToken(t) is MethodDef mm && mm.HasBody)
            {
                foreach (var ins in mm.Body.Instructions)
                    if (ins.Operand is ITokenOperand op && op.MDToken.Raw != 0)
                        tokens.Add(op.MDToken.Raw);
                if (mm.Body.Variables != null)
                    foreach (var v in mm.Body.Variables)
                        Collect(v.Type, tokens);
                Collect(mm.MethodSig?.RetType, tokens);
                if (mm.MethodSig != null) foreach (var p in mm.MethodSig.Params) Collect(p, tokens);
            }
        }

        int checkedN = 0, diffN = 0;
        foreach (var tok in tokens.OrderBy(x => x))
        {
            try
            {
                string o = Describe(off.ResolveToken(tok));
                string p = Describe(prod.ResolveToken(tok));
                checkedN++;
                if (o != p)
                {
                    diffN++;
                    Console.WriteLine($"DIFF 0x{tok:X8}:\n  OFFICIAL: {o}\n  PROD    : {p}");
                    foreach (var a3 in args.Skip(3))
                    {
                        uint mt3 = Convert.ToUInt32(a3.Trim().Replace("0x", ""), 16);
                        if (off.ResolveToken(mt3) is MethodDef mm3 && mm3.HasBody)
                            Console.WriteLine("  context: " + FindContext(mm3, tok));
                    }
                }
            }
            catch (Exception e) { Console.WriteLine($"ERR  0x{tok:X8}: {e.Message}"); }
        }
        Console.WriteLine($"[sigdiff] checked={checkedN} diff={diffN}");
        return 0;
    }

    static void Collect(TypeSig? s, HashSet<uint> acc)
    {
        while (s != null)
        {
            if (s is TypeDefOrRefSig t && t.TypeDefOrRef != null) acc.Add(t.TypeDefOrRef.MDToken.Raw);
            if (s is GenericInstSig g)
            {
                Collect(g.GenericType, acc);
                foreach (var a in g.GenericArguments) Collect(a, acc);
            }
            s = s.Next;
        }
    }

    public static int RunDiag(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: diagsig <exe> <methodTok>"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        uint tok = Convert.ToUInt32(args[2].Replace("0x", ""), 16);
        if (mod.ResolveToken(tok) is not MethodDef m) { Console.WriteLine("not a method: " + tok); return 1; }
        Console.WriteLine($"[diagsig] {m.DeclaringType?.FullName}::{m.Name} tok=0x{tok:X8}");
        Console.WriteLine($"  ret: {Dump(m.MethodSig?.RetType, 0)}");
        if (m.MethodSig?.Params != null)
            for (int i = 0; i < m.MethodSig.Params.Count; i++)
                Console.WriteLine($"  p{i}: {Dump(m.MethodSig.Params[i], 0)}");
        if (m.Body?.Variables != null)
            for (int i = 0; i < Math.Min(m.Body.Variables.Count, 12); i++)
                Console.WriteLine($"  l{i}: {Dump(m.Body.Variables[i].Type, 0)}");
        return 0;
    }

    static string Dump(TypeSig? s, int d)
    {
        if (s == null) return "<null>";
        string pad = new string(' ', d * 2);
        string tok = "";
        if (s is TypeDefOrRefSig t && t.TypeDefOrRef != null)
            tok = $" tok=0x{t.TypeDefOrRef.MDToken.Raw:X8} [{t.TypeDefOrRef.GetType().Name}]";
        string extra = s is GenericInstSig g ?
            "\n" + pad + "  gen: " + Dump(g.GenericType, d + 1) + string.Join("", g.GenericArguments.Select(a => "\n" + pad + "  arg: " + Dump(a, d + 1))) : "";
        return $"{pad}{s.GetType().Name} {s.FullName}{tok}{extra}" + (s.Next != null ? "\n" + pad + " next: " + Dump(s.Next, d) : "");
    }

    static string Describe(object? o)
    {
        switch (o)
        {
            case null: return "<null>";
            case MethodDef m:
                return $"MethodDef {m.DeclaringType?.FullName}::{m.Name} sig={BlobHex(m.Signature)}";
            case FieldDef f:
                return $"FieldDef {f.DeclaringType?.FullName}::{f.Name} sig={BlobHex(f.Signature)}";
            case MemberRef mr:
                return $"MemberRef {mr.Class?.FullName}::{mr.Name} sig={BlobHex(mr.Signature)}";
            case TypeSpec ts:
                return $"TypeSpec sig={BlobHex(ts.TypeSig)}";
            case TypeDef td:
                return $"TypeDef {td.FullName}";
            case TypeRef tr:
                return $"TypeRef {tr.FullName}";
            case StandAloneSig sa:
                return $"StandAloneSig sig={BlobHex(sa.Signature)}";
            case MethodSpec ms:
                return $"MethodSpec {ms.Method?.FullName} inst={BlobHex(ms.Instantiation)}";
            default:
                return o.GetType().Name + " " + o.ToString();
        }
    }

    static string BlobHex(object? sigObj)
    {
        if (sigObj == null) return "<null>";
        try
        {
            return sigObj switch
            {
                MethodSig msig => "ret=" + msig.RetType.FullName + "|params=" + string.Join(",", msig.Params.Select(p => p.FullName)) + "",
                FieldSig fsig => fsig.Type.FullName,
                TypeSig tsig => tsig.FullName + $"|(et={tsig.ElementType})",
                GenericInstMethodSig g => string.Join(";", g.GenericArguments.Select(a => a.FullName)),
                _ => "<unhandled:" + sigObj.GetType().Name + ">"
            };
        }
        catch (Exception e) { return "<sigerr:" + e.Message + ">"; }
    }
static string FindContext(MethodDef m, uint tok)
{
    var sb = new System.Text.StringBuilder();
    if (m.MethodSig != null)
    {
        if (m.MethodSig.RetType != null && TokenIn(m.MethodSig.RetType, tok)) sb.Append("retType ");
        if (m.MethodSig.Params != null)
            for (int i = 0; i < m.MethodSig.Params.Count; i++)
                if (TokenIn(m.MethodSig.Params[i], tok)) sb.Append($"param{i} ");
    }
    if (m.Body?.Variables != null)
        for (int i = 0; i < m.Body.Variables.Count; i++)
            if (TokenIn(m.Body.Variables[i].Type, tok)) sb.Append($"local{i} ");
    foreach (var ins in m.Body?.Instructions ?? Enumerable.Empty<Instruction>())
        if (ins.Operand is ITokenOperand op && op.MDToken.Raw == tok) sb.Append($"IL_{ins.Offset:X4}({ins.OpCode}) ");
    return sb.Length == 0 ? "(not referenced in this method)" : sb.ToString();
}

static bool TokenIn(TypeSig? s, uint tok)
{
    while (s != null)
    {
        if (s is TypeDefOrRefSig t && t.TypeDefOrRef != null && t.TypeDefOrRef.MDToken.Raw == tok) return true;
        if (s is GenericInstSig g)
        {
            if (TokenIn(g.GenericType, tok)) return true;
            foreach (var a in g.GenericArguments) if (TokenIn(a, tok)) return true;
        }
        s = s.Next;
    }
    return false;
}
}
