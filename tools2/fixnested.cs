using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// fixnested: 修 MemberRef 的 DeclaringType —— dnlib/Importer 在重写时会把
// **嵌套类型**写成**顶层 TypeRef**(丢了 ResolutionScope), 运行时就是
//   TypeLoadException: Could not load type 'X`1'
// 这里按"简单名唯一匹配"把 TypeRef 换回模块里真正的 TypeDef(含嵌套关系),
// 并重建 TypeSpec(GenericInstSig) 的 GenericType。
//
// 用法: fixnested <in> <out> [--dump]
class FixNested {
    static void Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: fixnested <in> <out> [--dump]"); return; }
        var mod = ModuleDefMD.Load(a[0]);
        bool dump = a.Any(x => x == "--dump");
        var byName = new Dictionary<string, List<TypeDef>>();
        foreach (var t in mod.GetTypes()) {
            var n = t.Name.String;
            if (!byName.ContainsKey(n)) byName[n] = new List<TypeDef>();
            byName[n].Add(t);
        }

        ITypeDefOrRef FixTdor(ITypeDefOrRef t, string where) {
            if (t is TypeRef tr) {
                if (byName.TryGetValue(tr.Name.String, out var cands) && cands.Count == 1) {
                    if (dump) Console.WriteLine("[fix] " + where + "  " + tr.FullName + " -> " + cands[0].FullName);
                    return cands[0];
                }
                if (dump) Console.WriteLine("[keep] " + where + "  " + tr.FullName + "  (cands=" + (cands == null ? 0 : cands.Count) + ")");
            }
            return t;
        }

        int nMr = 0, nTs = 0, nFieldSig = 0;
        foreach (var mr in mod.GetMemberRefs().ToList()) {
            var cls = mr.Class;
            if (cls is TypeSpec ts && ts.TypeSig is GenericInstSig gi) {
                var gt = gi.GenericType;
                if (gt != null && gt.TypeDefOrRef is TypeRef tr2) {
                    var fixedT = FixTdor(tr2, "MR-spec " + mr.Name);
                    if (!ReferenceEquals(fixedT, tr2)) {
                        var newGt = new ClassSig((ITypeDefOrRef)fixedT);
                        ts.TypeSig = new GenericInstSig(newGt, gi.GenericArguments);
                        nTs++;
                    }
                }
            } else if (cls is TypeRef tr) {
                var fixedT = FixTdor(tr, "MR " + mr.Name);
                if (!ReferenceEquals(fixedT, tr)) { mr.Class = fixedT; nMr++; }
            }
        }
        // 字段/方法签名里的 TypeRef 也要修（locals 走固定 sig 时）
        foreach (var t in mod.GetTypes()) {
            foreach (var f in t.Fields) {
                var ft = f.FieldType;
                if (ft is ClassSig cs && cs.TypeDefOrRef is TypeRef tr) {
                    var fixedT = FixTdor(tr, "F " + t.Name + "::" + f.Name);
                    if (!ReferenceEquals(fixedT, tr)) { f.FieldSig.Type = new ClassSig((ITypeDefOrRef)fixedT); nFieldSig++; }
                }
            }
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var v in m.Body.Variables) {
                    if (v.Type is ClassSig cs2 && cs2.TypeDefOrRef is TypeRef tr3) {
                        var fixedT = FixTdor(tr3, "L " + t.Name + "::" + m.Name);
                        if (!ReferenceEquals(fixedT, tr3)) { v.Type = new ClassSig((ITypeDefOrRef)fixedT); nFieldSig++; }
                    }
                }
            }
        }
        Console.WriteLine("[fixnested] memberref=" + nMr + " typespec=" + nTs + " sigs=" + nFieldSig);
        var wopt = new ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], wopt);
        Console.WriteLine("[out] " + a[1]);
    }
}
