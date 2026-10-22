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

        // 递归修任意 TypeSig 里的"顶层 TypeRef"（数组/byref/泛型实例/泛型实参）
        TypeSig FixSig2(TypeSig sig) {
            if (sig == null) return null;
            if (sig is TypeDefOrRefSig tds) {
                if (tds.TypeDefOrRef is TypeRef trx) {
                    var ft = FixTdor(trx, "sig");
                    if (!ReferenceEquals(ft, trx)) return ((ITypeDefOrRef)ft).ToTypeSig(tds is ValueTypeSig);
                }
                return sig;
            }
            if (sig is GenericInstSig gi) {
                bool ch = false;
                var gt = gi.GenericType;
                ClassOrValueTypeSig ngt = gt;
                if (gt != null && gt.TypeDefOrRef is TypeRef gtr) {
                    var ft = FixTdor(gtr, "gasig");
                    if (!ReferenceEquals(ft, gtr)) { ngt = new ClassSig((ITypeDefOrRef)ft); ch = true; }
                }
                var args = new List<TypeSig>();
                foreach (var g in gi.GenericArguments) { var x = FixSig2(g); if (!ReferenceEquals(x, g)) ch = true; args.Add(x); }
                return ch ? new GenericInstSig(ngt, args) : sig;
            }
            if (sig is SZArraySig sa) { var e = FixSig2(sa.Next); return ReferenceEquals(e, sa.Next) ? sig : new SZArraySig(e); }
            if (sig is ByRefSig br) { var e = FixSig2(br.Next); return ReferenceEquals(e, br.Next) ? sig : new ByRefSig(e); }
            if (sig is PtrSig pp) { var e = FixSig2(pp.Next); return ReferenceEquals(e, pp.Next) ? sig : new PtrSig(e); }
            return sig;
        }

        int nMr = 0, nTs = 0, nFieldSig = 0, nThis = 0, nIns = 0;
        foreach (var mr in mod.GetMemberRefs().ToList()) {
            var cls = mr.Class;
            if (cls is TypeSpec ts0 && ts0.TypeSig is ClassSig cs0 && cs0.TypeDefOrRef is TypeRef tr0) {
                // TypeSpec 里只有一个裸 ClassSig(泛型实例被简化成 TypeSpec+ClassSig)
                var ft0 = FixTdor(tr0, "MR-tsig " + mr.Name);
                if (!ReferenceEquals(ft0, tr0)) { ts0.TypeSig = new ClassSig((ITypeDefOrRef)ft0); nTs++; }
            } else if (cls is TypeSpec ts && ts.TypeSig is GenericInstSig gi) {
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
                var nf = FixSig2(f.FieldType);
                if (nf != null && !ReferenceEquals(nf, f.FieldType)) { f.FieldSig.Type = nf; nFieldSig++; }
            }
            // 泛型类型的实例方法: this 参数类型若是"顶层 TypeRef", 运行时解析会 TypeLoad
            if (t.GenericParameters.Count > 0) {
                foreach (var m in t.Methods) {
                    if (!m.HasThis || m.Parameters.Count == 0) continue;
                    var p0 = m.Parameters[0];
                    if (p0.Type is ClassSig pcs && pcs.TypeDefOrRef is TypeRef ptr
                        && byName.TryGetValue(ptr.Name.String, out var pcands) && pcands.Count == 1
                        && pcands[0] == t) {
                        var gargs = new List<TypeSig>();
                        for (int gi = 0; gi < t.GenericParameters.Count; gi++) gargs.Add(new GenericVar(gi, t));
                        p0.Type = new GenericInstSig(new ClassSig(t), gargs);
                        nThis++;
                    }
                }
            }
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var v in m.Body.Variables) {
                    var nv = FixSig2(v.Type);
                    if (nv != null && !ReferenceEquals(nv, v.Type)) { v.Type = nv; nFieldSig++; }
                }
                // 指令操作数里的 TypeRef: castclass/isinst/newobj/box/ldtoken 的 token
                // 若是 TypeRef 且本模块有同名唯一 TypeDef, 必须换成 TypeDef ——
                // 否则运行时可能解析成另一个 Type 实例, castclass 直接 InvalidCast
                // (v55 的 VirtualInitializer::AddEfficientHandler 就是
                //  castclass ProgramFinder [tok 0x0100090F], 而正确 token 是 0x0200065C)
                foreach (var ins in m.Body.Instructions) {
                    var tdr = ins.Operand as ITypeDefOrRef;
                    if (!(tdr is TypeRef trIns)) continue;
                    var fti = FixTdor(trIns, "INS " + t.Name + "::" + m.Name);
                    if (!ReferenceEquals(fti, trIns)) { ins.Operand = fti; nIns++; }
                }
                if (m.MethodSig != null) {
                    for (int pi = 0; pi < m.MethodSig.Params.Count; pi++) {
                        var np = FixSig2(m.MethodSig.Params[pi]);
                        if (np != null && !ReferenceEquals(np, m.MethodSig.Params[pi])) { m.MethodSig.Params[pi] = np; nFieldSig++; }
                    }
                    var nr = FixSig2(m.MethodSig.RetType);
                    if (nr != null && !ReferenceEquals(nr, m.MethodSig.RetType)) { m.MethodSig.RetType = nr; nFieldSig++; }
                }
            }
        }
        Console.WriteLine("[fixnested] memberref=" + nMr + " typespec=" + nTs + " sigs=" + nFieldSig + " this=" + nThis + " insOperand=" + nIns);
        var wopt = new ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], wopt);
        Console.WriteLine("[out] " + a[1]);
    }
}
