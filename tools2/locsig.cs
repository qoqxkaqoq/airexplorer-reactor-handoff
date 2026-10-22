using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// locsig: 用官方 JIT dump 的 m_<rid>.loc (index|isPinned|TypeFullName) 替换
// 目标 exe 里 nbrestore 的 System.Object 占位 locals —— 官方真签名, 不再猜。
// 用法: locsig <dumpDir> <in.exe> <out.exe> [--dump]
class LocSig {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: locsig <dumpDir> <in> <out> [--dump]"); return; }
        string dumpDir = a[0];
        var mod = ModuleDefMD.Load(a[1]);
        bool dump = a.Any(x => x == "--dump");
        var importer = new Importer(mod, ImporterOptions.TryToUseDefs);

        int fixedM = 0, fixedV = 0, missLoc = 0, missType = 0, already = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody || m.Body.Variables.Count == 0) continue;
                string lp = Path.Combine(dumpDir, "m_" + m.MDToken.Raw.ToString("X8") + ".loc");
                if (!File.Exists(lp)) { missLoc++; continue; }
                var lines = File.ReadAllLines(lp).Where(x => x.Trim().Length > 0).ToList();
                if (lines.Count != m.Body.Variables.Count) { missLoc++; continue; }
                bool anyObj = m.Body.Variables.Any(v => v.Type.FullName == "System.Object");
                if (!anyObj) { already++; continue; }
                bool ok = true;
                var sigs = new List<TypeSig>();
                foreach (var ln in lines) {
                    var p = ln.Split('|');
                    if (p.Length < 3) { ok = false; break; }
                    var sig = ParseType(p[2], mod);
                    if (sig == null) { ok = false; missType++; if (dump) Console.WriteLine("[missType] " + p[2]); break; }
                    sigs.Add(sig);
                }
                if (!ok) continue;
                for (int i = 0; i < sigs.Count; i++)
                    m.Body.Variables[i].Type = importer.Import(sigs[i]);
                fixedM++; fixedV += sigs.Count;
                if (dump && fixedM <= 5) Console.WriteLine("[fix] " + t.FullName + "::" + m.Name + " " + sigs.Count + " locals");
            }
        }
        Console.WriteLine("[locsig] fixed=" + fixedM + " locals=" + fixedV + " noDump=" + missLoc + " missType=" + missType + " alreadyReal=" + already);
        var wopt = new ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[2], wopt);
        Console.WriteLine("[out] " + a[2]);
    }

    // TypeFullName -> TypeSig (处理嵌套+/泛型`1[[..]]/[]/&/*)
    static TypeSig ParseType(string s, ModuleDef mod) {
        s = s.Trim();
        if (s.EndsWith("[]")) { var e = ParseType(s.Substring(0, s.Length - 2), mod); return e == null ? null : new SZArraySig(e); }
        if (s.EndsWith("&")) { var e = ParseType(s.Substring(0, s.Length - 1), mod); return e == null ? null : new ByRefSig(e); }
        if (s.EndsWith("*")) { var e = ParseType(s.Substring(0, s.Length - 1), mod); return e == null ? null : new PtrSig(e); }
        int bt = s.IndexOf('`');
        if (bt > 0 && s.Contains("[[")) {
            // 泛型: Name`N[[Arg1, asm]][[Arg2, asm]]
            int bracket = s.IndexOf("[[");
            string head = s.Substring(0, bracket);
            var args = new List<TypeSig>();
            int i = bracket;
            while (i < s.Length - 1) {
                if (s.Substring(i).StartsWith("[[")) {
                    int depth = 1, j = i + 2;
                    while (j < s.Length && depth > 0) {
                        if (s[j] == '[' && s[j + 1] == '[') { depth += 2; j += 2; }
                        else if (s[j] == ']' && j + 1 < s.Length && s[j + 1] == ']') { depth -= 2; j += 2; }
                        else if (s[j] == '[') depth++; else if (s[j] == ']') depth--;
                        else j++;
                    }
                    string inner = s.Substring(i + 2, j - i - 4);
                    int comma = inner.IndexOf(',');
                    args.Add(ParseType(comma > 0 ? inner.Substring(0, comma).Trim() : inner, mod));
                    i = j;
                } else i++;
            }
            if (args.Any(x => x == null)) return null;
            var gt = FindType(head, mod);
            if (gt == null) return null;
            var gsig = gt.ToTypeSig(gt.IsValueType) as ClassOrValueTypeSig;
            return new GenericInstSig(gsig, args);
        }
        var td = FindType(s, mod);
        return td == null ? null : td.ToTypeSig(td.IsValueType);
    }

    static Dictionary<string, TypeDef> _byFull, _byNested;
    static TypeDef FindType(string full, ModuleDef mod) {
        if (_byFull == null) {
            _byFull = new Dictionary<string, TypeDef>();
            _byNested = new Dictionary<string, TypeDef>();
            foreach (var t in mod.GetTypes()) {
                if (!_byFull.ContainsKey(t.FullName)) _byFull[t.FullName] = t;
                _byNested[t.FullName] = t;
            }
        }
        if (_byFull.TryGetValue(full, out var td)) return td;
        // 嵌套: Ns.Outer+Inner —— FullName 表里已是 "Ns.Outer+Inner" 形式, 直接命中
        // CorLib 常见类型兜底
        var cor = mod.CorLibTypes;
        int dot = full.LastIndexOf('.');
        if (dot > 0) {
            var ns = full.Substring(0, dot);
            var nm = full.Substring(dot + 1);
            if (ns == "System") {
                switch (nm) {
                    case "Int32": return cor.Int32.TypeDefOrRef.ResolveTypeDef();
                    case "UInt32": return cor.UInt32.TypeDefOrRef.ResolveTypeDef();
                    case "Int64": return cor.Int64.TypeDefOrRef.ResolveTypeDef();
                    case "UInt64": return cor.UInt64.TypeDefOrRef.ResolveTypeDef();
                    case "Int16": return cor.Int16.TypeDefOrRef.ResolveTypeDef();
                    case "Byte": return cor.Byte.TypeDefOrRef.ResolveTypeDef();
                    case "SByte": return cor.SByte.TypeDefOrRef.ResolveTypeDef();
                    case "Boolean": return cor.Boolean.TypeDefOrRef.ResolveTypeDef();
                    case "Char": return cor.Char.TypeDefOrRef.ResolveTypeDef();
                    case "Single": return cor.Single.TypeDefOrRef.ResolveTypeDef();
                    case "Double": return cor.Double.TypeDefOrRef.ResolveTypeDef();
                    case "String": return cor.String.TypeDefOrRef.ResolveTypeDef();
                    case "Object": return cor.Object.TypeDefOrRef.ResolveTypeDef();
                }
            }
        }
        return null;
    }
}
