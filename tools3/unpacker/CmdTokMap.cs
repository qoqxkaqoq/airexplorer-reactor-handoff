using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>
/// tokmap — 从 mt 快照提取方法的原始 IL，把每个 operand token 分别在
/// 官方 exe 与产物里 resolve，对比身份 —— 找出"官方序 token 在产物表里错位"的全部点。
/// 用法: tokmap &lt;official.exe&gt; &lt;prod.exe&gt; &lt;module_text.bin&gt; &lt;manifest.tsv&gt; &lt;methodTok&gt; [--max N]
/// </summary>
public static class CmdTokMap
{
    const int MT_SHIFT = 0x2000;

    public static int Run(string[] args)
    {
        if (args.Length < 6) { Console.WriteLine("usage: tokmap <official.exe> <prod.exe> <module_text.bin> <manifest.tsv> <tok> [--max N]"); return 2; }
        for (int i = 0; i < args.Length; i++) Console.WriteLine($"arg[{i}]={args[i]}");
        var off = ModuleDefMD.Load(args[1]);
        var prod = ModuleDefMD.Load(args[2]);
        byte[] mt;
        try { mt = File.ReadAllBytes(args[3]); } catch (Exception e) { Console.WriteLine("FAIL@mt: " + e.StackTrace); return 1; }
        int max = 40;
        for (int i = 6; i < args.Length; i++) if (args[i] == "--max") max = int.Parse(args[++i]);

        string tokStr = args[5].Replace("0x", "").ToUpperInvariant();
        Console.WriteLine($"step: tokStr={tokStr}");
        // manifest: tok -> rva(hex)
        uint mtRva = 0;
        foreach (var line in File.ReadLines(args[4]))
        {
            var f = line.Split('\t');
            if (f.Length >= 2 && f[1].Trim().Replace("0x","").ToUpperInvariant().Equals(tokStr, StringComparison.OrdinalIgnoreCase))
            { mtRva = Convert.ToUInt32(f[0].Trim(), 16); break; }
        }
        if (mtRva == 0) { Console.WriteLine("token not in manifest"); return 1; }
        Console.WriteLine($"step: mtRva=0x{mtRva:X}");
        int mOff = (int)(mtRva - MT_SHIFT);
        Console.WriteLine($"step: mOff={mOff} mtLen={mt.Length}");
        byte b0 = mt[mOff];
        if ((b0 & 3) != 3) { Console.WriteLine($"mt head not fat: 0x{b0:X2}"); return 1; }
        int hsz = ((mt[mOff + 1] >> 4) & 0xF) * 4;
        int codeSize = BitConverter.ToInt32(mt, mOff + 4);
        uint localsTok = BitConverter.ToUInt32(mt, mOff + 8);
        var il = new byte[codeSize];
        Array.Copy(mt, mOff + hsz, il, 0, codeSize);
        Console.WriteLine($"[tokmap] tok=0x{tokStr} mtRva=0x{mtRva:X} codeSize={codeSize} localsTok=0x{localsTok:X8}");

        // 官方 local sig
        string offLocals = "(none)";
        if (localsTok != 0 && off.ResolveToken(localsTok) is StandAloneSig osas && osas.Signature is LocalSig ol)
            offLocals = string.Join(",", ol.Locals.Select(v => v.FullName));
        string prodLocals = "(none)";
        if (localsTok != 0 && prod.ResolveToken(localsTok) is StandAloneSig psas && psas.Signature is LocalSig pl)
            prodLocals = string.Join(",", pl.Locals.Select(v => v.FullName));
        Console.WriteLine($"locals(0x{localsTok:X8}) official: {offLocals}");
        Console.WriteLine($"locals(0x{localsTok:X8}) prod    : {prodLocals}");
        if (offLocals != prodLocals) Console.WriteLine("  >>> LOCALS MISMATCH <<<");

        // IL operand: 用官方模块作为 resolver 解析指令
        CilBody body;
        try
        {
            body = MethodBodyReader.CreateCilBody(off, il, null, null, (ushort)3,
                8, (uint)codeSize, localsTok, new GenericParamContext());
        }
        catch (Exception e) { Console.WriteLine("IL 解析失败: " + e.GetType().Name + " " + e.Message + "\n" + e.StackTrace); return 1; }
        Console.WriteLine($"step: body parsed, instrs={body.Instructions.Count}");

        int n = 0, diff = 0;
        foreach (var ins in body.Instructions)
        {
            if (ins.Operand is not ITokenOperand op) continue;
            uint t = op.MDToken.Raw;
            if (t == 0) continue;
            n++;
            string o = SafeDesc(off, t), p = SafeDesc(prod, t);
            if (o != p)
            {
                diff++;
                if (diff <= max)
                    Console.WriteLine($"MISMATCH IL_{ins.Offset:X4} {ins.OpCode,-12} tok=0x{t:X8}\n  official: {o}\n  prod    : {p}");
            }
        }
        Console.WriteLine($"[tokmap] operands={n} mismatch={diff}");
        return 0;
    }

    static string SafeDesc(ModuleDef mod, uint tok)
    {
        try
        {
            object? r = mod.ResolveToken(tok);
            if (r == null) return "<unresolved>";
            return r switch
            {
                MemberRef mr => $"MemberRef {mr.Class?.FullName}::{mr.Name}",
                FieldDef fd => $"FieldDef {fd.DeclaringType?.FullName}::{fd.Name}",
                MethodDef md => $"MethodDef {md.DeclaringType?.FullName}::{md.Name}",
                MethodSpec ms => $"MethodSpec {ms.Method?.FullName}",
                TypeSpec ts => $"TypeSpec {ts.TypeSig.FullName}",
                TypeDef td => $"TypeDef {td.FullName}",
                TypeRef tr => $"TypeRef {tr.FullName}",
                StandAloneSig sa => $"StandAloneSig n={(sa.Signature is LocalSig ls2 ? ls2.Locals.Count.ToString() : "?")}",
                _ => r.GetType().Name
            };
        }
        catch (Exception e) { return "<err:" + e.Message + ">"; }
    }
}
