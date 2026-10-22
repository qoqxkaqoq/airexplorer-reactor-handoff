// tokmap.cs — 官方 exe 全量 token → 签名指纹 映射表（对账基准）
// 用法: tokmap8 <官方exe> <输出tsv>
// 输出: kind \t token \t fingerprint
//   kind: TypeDef | TypeRef | TypeSpec | MethodDef | MemberRef | FieldDef | MethodSpec | StandAloneSig
//   指纹: 归一化 FullName + 签名（含声明类型链、方法签名、泛型实例化），重载之间可区分
// 另扫描: ldc.i4 X ; call aux(int→RuntimeTypeHandle/RuntimeFieldHandle) 的辅助解密调用点 → 辅助输出
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class TokMap {
    static StringBuilder Sb = new StringBuilder();
    static int AuxTypeCalls = 0, AuxFieldCalls = 0;

    static void Emit(string kind, uint token, string fp) {
        Sb.Append(kind).Append('\t').Append(token.ToString("X8")).Append('\t').Append(fp).Append('\n');
    }

    // 归一化类型指纹：FullName 本身已含命名空间/嵌套/程序集，重载无关
    static string TypeFp(ITypeDefOrRef t) {
        if (t == null) return "<null>";
        if (t is TypeSpec ts) {
            try { return "TSPEC:" + ts.TypeSig.FullName; } catch { return "TSPEC:<unreadable>"; }
        }
        return t.FullName;
    }

    // 方法指纹：声明类型 + 名字 + 返回类型 + 参数类型序列（区分重载）
    static string MethodFp(IMethod im) {
        if (im == null) return "<nullmethod>";
        if (im is MethodSpec ms) {
            var m = ms.Method;
            return "MSPEC[" + MethodFp(m) + " inst=" + MethodSpecInst(ms) + "]";
        }
        if (im is MemberRef mr && mr.Class != null)
            return mr.Class.FullName + "::" + mr.Name + SigOf(mr.MethodSig);
        if (im is MethodDef md)
            return (md.DeclaringType != null ? md.DeclaringType.FullName : "<module>") + "::" + md.Name + SigOf(md.MethodSig);
        return im.FullName;
    }

    static string MethodSpecInst(MethodSpec ms) {
        try {
            if (ms.Instantiation == null) return "<none>";
            var gi = ms.Instantiation as GenericInstMethodSig;
            if (gi == null || gi.GenericArguments == null) return "<none>";
            return string.Join(",", gi.GenericArguments.Select(x => x.FullName));
        } catch { return "<err>"; }
    }

    static string SigOf(MethodSig sig) {
        if (sig == null) return "(<nosig>)";
        try {
            var ps = sig.Params != null ? string.Join(",", sig.Params.Select(p => p.FullName)) : "";
            if (sig.Params.Count == 0)
                return "(" + sig.RetType.FullName + "())";
            return "(" + sig.RetType.FullName + "(" + ps + "))";
        } catch { return "(<sigerr>)"; }
    }

    static string FieldFp(IField f) {
        if (f == null) return "<nullfield>";
        if (f is MemberRef mr)
            return (mr.Class != null ? mr.Class.FullName : "?") + "::" + mr.Name + " :" + (mr.FieldSig != null ? mr.FieldSig.Type.FullName : "?");
        if (f is FieldDef fd)
            return (fd.DeclaringType != null ? fd.DeclaringType.FullName : "<module>") + "::" + fd.Name + " :" + (fd.FieldSig != null ? fd.FieldSig.Type.FullName : "?");
        return f.FullName;
    }

    static int Main(string[] args) {
        if (args.Length < 2) { Console.Error.WriteLine("usage: tokmap8 <exe> <out.tsv> [aux.tsv]"); return 2; }
        var mod = ModuleDefMD.Load(args[0]);
        var seen = new HashSet<uint>();

        foreach (var t in mod.GetTypes()) {
            Emit("TypeDef", t.MDToken.Raw, TypeFp(t));
            foreach (var f in t.Fields) Emit("FieldDef", f.MDToken.Raw, FieldFp(f));
            foreach (var m in t.Methods) {
                Emit("MethodDef", m.MDToken.Raw, MethodFp(m));
                if (m.HasBody) {
                    var il = m.Body.Instructions;
                    for (int i = 0; i < il.Count - 1; i++) {
                        if (il[i].OpCode.Code != Code.Ldc_I4) continue;
                        if (il[i + 1].OpCode.Code != Code.Call) continue;
                        var callee = il[i + 1].Operand as IMethod;
                        if (callee == null) continue;
                        // 辅助解密器: 返回 RuntimeTypeHandle/RuntimeFieldHandle 且参数是 int32
                        var sig = (callee.ResolveMethodDef() != null ? callee.ResolveMethodDef().MethodSig : (callee as MemberRef)?.MethodSig);
                        if (sig == null || sig.Params == null || sig.Params.Count != 1) continue;
                        if (sig.Params[0].FullName != "System.Int32") continue;
                        var rt = sig.RetType != null ? sig.RetType.FullName : "";
                        if (rt == "System.RuntimeTypeHandle" || rt == "System.RuntimeFieldHandle") {
                            int ival;
                            try { ival = il[i].GetLdcI4Value(); } catch { continue; }
                            Sb.Append("AuxCall").Append('\t').Append(((MethodDef)m).MDToken.Raw.ToString("X8"))
                              .Append('\t').Append(rt == "System.RuntimeTypeHandle" ? "T" : "F")
                              .Append('\t').Append(ival.ToString())
                              .Append('\t').Append(MethodFp(callee))
                              .Append('\t').Append("IL_" + il[i].Offset.ToString("X4"))
                              .Append('\n');
                            if (rt == "System.RuntimeTypeHandle") AuxTypeCalls++; else AuxFieldCalls++;
                        }
                    }
                }
            }
        }
        // TypeRef / TypeSpec / MemberRef / MethodSpec 元数据表自身（按表 rid 遍历）
        Action<uint, uint, Action<IMDTokenProvider>> walk = (tag, rows, act) => {
            for (uint rid = 1; rid <= rows; rid++) {
                var t2 = mod.ResolveToken(tag | rid);
                if (t2 != null) act(t2);
            }
        };
        var tsr = mod.TablesStream;
        walk(0x01000000, tsr.TypeRefTable.Rows, x => { if (seen.Add(x.MDToken.Raw)) Emit("TypeRef", x.MDToken.Raw, TypeFp((TypeRef)x)); });
        walk(0x1B000000, tsr.TypeSpecTable.Rows, x => { if (seen.Add(x.MDToken.Raw)) Emit("TypeSpec", x.MDToken.Raw, TypeFp((TypeSpec)x)); });
        walk(0x0A000000, tsr.MemberRefTable.Rows, x => { if (seen.Add(x.MDToken.Raw)) { var mr = (MemberRef)x; Emit("MemberRef", x.MDToken.Raw, mr.IsMethodRef ? MethodFp(mr) : FieldFp(mr)); } });
        walk(0x2B000000, tsr.MethodSpecTable.Rows, x => { if (seen.Add(x.MDToken.Raw)) Emit("MethodSpec", x.MDToken.Raw, MethodFp((MethodSpec)x)); });

        File.WriteAllText(args[1], Sb.ToString());
        Console.WriteLine("[tokmap] 官方=" + Path.GetFileName(args[0])
            + " 行数=" + (Sb.Length > 0 ? Sb.ToString().Count(c => c == '\n') : 0)
            + " auxTypeCalls=" + AuxTypeCalls + " auxFieldCalls=" + AuxFieldCalls);
        return 0;
    }
}
