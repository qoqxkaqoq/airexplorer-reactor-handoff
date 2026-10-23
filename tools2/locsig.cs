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

        int fixedM = 0, fixedV = 0, missLoc = 0, missType = 0, already = 0, bodyMismatch = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody || m.Body.Variables.Count == 0) continue;
                string tok = m.MDToken.Raw.ToString("X8");
                string lp = Path.Combine(dumpDir, "m_" + tok + ".loc");
                if (!File.Exists(lp)) { missLoc++; continue; }
                var lines = File.ReadAllLines(lp).Where(x => x.Trim().Length > 0).ToList();
                if (lines.Count != m.Body.Variables.Count) { missLoc++; continue; }

                // ★ 体一致性指纹: 官方 .bin 头的 ilSize/ehCount 必须与当前 body 一致。
                // 不一致说明该方法的 IL 不是这份 dump 对应的体(cilantro 移植体等),
                // 官方 locals 序号语义对不上, 换了必炸(v68 教训: Dictionary`2 args 错)。
                string bp = Path.Combine(dumpDir, "m_" + tok + ".bin");
                if (!File.Exists(bp)) { bodyMismatch++; continue; }
                var braw = File.ReadAllBytes(bp);
                if (braw.Length < 24) { bodyMismatch++; continue; }
                uint offIlSize = BitConverter.ToUInt32(braw, 4);
                uint offEhCnt = BitConverter.ToUInt32(braw, 12);
                int curIlSize = m.Body.Instructions.Sum(i => i.GetSize());
                int curEhCnt = m.Body.ExceptionHandlers.Count;
                if (offIlSize != (uint)curIlSize || offEhCnt != (uint)curEhCnt) {
                    bodyMismatch++;
                    if (dump) Console.WriteLine("[bodyMismatch] " + tok + " il " + offIlSize + "/" + curIlSize + " eh " + offEhCnt + "/" + curEhCnt);
                    continue;
                }

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
        Console.WriteLine("[locsig] fixed=" + fixedM + " locals=" + fixedV + " noDump=" + missLoc + " missType=" + missType + " alreadyReal=" + already + " bodyMismatch=" + bodyMismatch);
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
            // v2: depth 按单字符 '[' ']' 计数(等价于 [[ ]] 配对), 对任意嵌套正确;
            //     每个参数块内只在 depth==0 处切第一个逗号(asm 部分丢弃)。
            //     旧实现在嵌套参数(List`1[[...]] 作 arg)上会切出残缺文本 → 参数数错
            //     → TypeLoadException: Dictionary`2 wrong number of generic arguments。
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
                    if (depth != 0) return null;   // 括号不配对
                    string block = s.Substring(i + 2, j - i - 4);   // 去掉外层 [[ ]]
                    int kdepth = 0, comma = -1;
                    for (int k = 0; k < block.Length; k++) {
                        if (block[k] == '[') kdepth++;
                        else if (block[k] == ']') kdepth--;
                        else if (block[k] == ',' && kdepth == 0) { comma = k; break; }
                    }
                    string typeName = comma > 0 ? block.Substring(0, comma).Trim() : block.Trim();
                    args.Add(ParseType(typeName, mod));
                    i = j;
                } else i++;
            }
            if (args.Any(x => x == null)) return null;
            // ★ arity 安全网: 参数个数必须等于 head 的 `N, 不等则放弃(宁可保 Object 不猜)
            if (arity > 0 && args.Count != arity) {
                Console.WriteLine("[arityMismatch] " + head + " want " + arity + " got " + args.Count + "  src=" + s);
                return null;
            }
            var gsig = ResolveRefSig(head, mod) as ClassOrValueTypeSig;
            if (gsig == null) return null;
            return new GenericInstSig(gsig, args);
        }
        var sig = ResolveRefSig(s, mod);
        return sig;
    }

    // 统一解析: 本模块 TypeDef -> TypeRef 表 -> corlib 基元。
    // 返回 ClassSig/ValueTypeSig/CorLibTypeSig, 全是可直接入签名的 TypeSig。
    static TypeSig ResolveRefSig(string full, ModuleDef mod) {
        var td = FindType(full, mod);
        if (td != null) return td.ToTypeSig(td.IsValueType);
        var tdr = FindRef(full, mod);
        if (tdr != null) {
            bool st = IsKnownValueType(full);
            if (!st) {
                // 真身可解析时用真实 kind(避免把 struct 当 class)
                var res = tdr.ResolveTypeDef();
                if (res != null) return res.ToTypeSig(res.IsValueType);
            }
            return st ? (TypeSig)new ValueTypeSig(tdr) : new ClassSig(tdr);
        }
        return CorLibSig(full, mod);
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

    static Dictionary<string, ITypeDefOrRef> _byRefFull;
    // TypeRef 表按 FullName 查找; 找不到就建新 TypeRefUser(追加到表尾, 不动已有行)
    static ITypeDefOrRef FindRef(string full, ModuleDef mod) {
        if (_byRefFull == null) {
            _byRefFull = new Dictionary<string, ITypeDefOrRef>();
            foreach (var tr in mod.GetTypeRefs())
                if (!_byRefFull.ContainsKey(tr.FullName)) _byRefFull[tr.FullName] = tr;
        }
        if (_byRefFull.TryGetValue(full, out var r)) return r;
        int dot = full.LastIndexOf('.');
        if (dot <= 0) return null;
        var ns = full.Substring(0, dot);
        var nm = full.Substring(dot + 1);
        // 按 ns 选 AssemblyRef: WinForms 类型挂 System.Windows.Forms, 其余默认 mscorlib
        var asmRef = ns.StartsWith("System.Windows.Forms")
            ? mod.GetAssemblyRefs().FirstOrDefault(x => x.Name == "System.Windows.Forms")
            : null;
        if (asmRef == null) asmRef = mod.CorLibTypes.AssemblyRef;
        var trNew = new TypeRefUser(mod, ns, nm, asmRef);
        _byRefFull[full] = trNew;
        return trNew;
    }

    // CorLib 兜底 —— 直接返回 CorLibTypeSig(本身就是 TypeSig)。
    // ResolveTypeDef() 在被 Reactor 重写过元数据的模块上解析失败返回 null,
    // 之前 115 个 missType 连 System.Int32 都命中就是这个原因。
    static TypeSig CorLibSig(string full, ModuleDef mod) {
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
        // 运行时反射 FullName 嵌套用 '+', dnlib 用 '/' —— 归一化后再查
        string alt = full.Replace('+', '/');
        if (_byFull.TryGetValue(alt, out var td2)) return td2;
        return null;
    }
}
