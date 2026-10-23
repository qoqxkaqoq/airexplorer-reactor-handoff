using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// sigclose <in.exe> <out.exe>
// 全局签名封闭: 官方体内 MemberRef 的方法/字段签名含类级泛型Var(!0) 且 Class=TypeSpec(封闭泛型)
// → 克隆 MemberRef, Var 替换为 TypeSpec 实参。CLR JIT 对 "!0 + TypeSpec" 绑定失败(MissingMethodException)
//   的官方代码(Reactor 解释器从不 JIT 它们)由此修复。
class SigClose {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var cache = new Dictionary<MemberRef, MemberRef>();
        int n = 0, sites = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var il = m.Body.Instructions;
                for (int i = 0; i < il.Count; i++) {
                    if (!(il[i].Operand is MemberRef mr)) continue;
                    if (mr.MethodSig == null && mr.FieldSig == null) continue;
                    bool need = false;
                    if (mr.MethodSig != null) need = SigHasVar(mr.MethodSig);
                    else if (mr.FieldSig != null) need = TypeHasVar(mr.FieldSig.Type);
                    if (!need) continue;
                    // Class 必须是封闭泛型 TypeSpec 才能映射 Var
                    var ts = mr.Class as TypeSpec;
                    if (ts == null || !(ts.TypeSig is GenericInstSig)) continue;
                    var gis = (GenericInstSig)ts.TypeSig;
                    MemberRef rep;
                    if (!cache.TryGetValue(mr, out rep)) {
                        if (mr.MethodSig != null) {
                            var ns = CloseMethodSig(mr.MethodSig, gis);
                            rep = new MemberRefUser(mod, mr.Name, ns, mr.Class);
                        } else {
                            var nf = new FieldSig(CloseType(mr.FieldSig.Type, gis));
                            rep = new MemberRefUser(mod, mr.Name, nf, mr.Class);
                        }
                        cache[mr] = rep;
                        n++;
                    }
                    il[i].Operand = rep;
                    sites++;
                }
            }
        }
        Console.WriteLine("[sigclose] newRefs=" + n + " sites=" + sites);
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll;
        mod.Write(a[1], opts);
        Console.WriteLine("[sigclose] wrote " + a[1]);
    }

    static bool SigHasVar(MethodSig s) {
        if (TypeHasVar(s.RetType)) return true;
        if (s.Params != null) foreach (var p in s.Params) if (TypeHasVar(p)) return true;
        return false;
    }
    static bool TypeHasVar(TypeSig t) {
        while (t != null) {
            if (t is GenericVar) return true;
            var gis = t as GenericInstSig;
            if (gis != null) {
                if (TypeHasVar(gis.GenericType)) return true;
                foreach (var ga in gis.GenericArguments) if (TypeHasVar(ga)) return true;
                return false;
            }
            var sz = t as SZArraySig;
            if (sz != null) { t = sz.Next; continue; }
            var byref = t as ByRefSig;
            if (byref != null) { t = byref.Next; continue; }
            var ptr = t as PtrSig;
            if (ptr != null) { t = ptr.Next; continue; }
            break;
        }
        return false;
    }
    static TypeSig CloseType(TypeSig t, GenericInstSig gis) {
        if (t is GenericVar) {
            int idx = (int)((GenericVar)t).Number;
            if (idx < gis.GenericArguments.Count) return gis.GenericArguments[idx];
            return t;
        }
        var g2 = t as GenericInstSig;
        if (g2 != null) {
            var gt = (ClassOrValueTypeSig)CloseType(g2.GenericType, gis);
            var ng = new GenericInstSig(gt);
            foreach (var ga in g2.GenericArguments) ng.GenericArguments.Add(CloseType(ga, gis));
            return ng;
        }
        var sz = t as SZArraySig;
        if (sz != null) return new SZArraySig(CloseType(sz.Next, gis));
        var byref = t as ByRefSig;
        if (byref != null) return new ByRefSig(CloseType(byref.Next, gis));
        var ptr = t as PtrSig;
        if (ptr != null) return new PtrSig(CloseType(ptr.Next, gis));
        return t;
    }
    static MethodSig CloseMethodSig(MethodSig s, GenericInstSig gis) {
        var ns = new MethodSig(s.CallingConvention, s.GenParamCount, CloseType(s.RetType, gis));
        foreach (var p in s.Params) ns.Params.Add(CloseType(p, gis));
        return ns;
    }
}
