using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// sigclose <in.exe> <out.exe>  (v2)
// 官方体内 MemberRef 的方法/字段签名用 MVAR(0x13 方法级泛型变量)编码类级参数 — 畸形编码:
//   解释器(Reactor)不校验; CLR JIT 按开放签名匹配 → Add(MVAR) 无法字面匹配开放定义 Add(VAR) → MissingMethodException
// 修法: MVar → Var(类级, 0x1E) 同编号转换 — MemberRef 签名与 TypeDef 开放方法签名字面匹配, JIT 时再经 TypeSpec 实例化。
class SigClose {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var cache = new Dictionary<MemberRef, MemberRef>();
        int n = 0, sites = 0, scanned = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var il = m.Body.Instructions;
                for (int i = 0; i < il.Count; i++) {
                    if (!(il[i].Operand is MemberRef mr)) continue;
                    scanned++;
                    if (mr.MethodSig == null && mr.FieldSig == null) continue;
                    bool need = false;
                    if (mr.MethodSig != null) need = SigHasVarLike(mr.MethodSig);
                    else if (mr.FieldSig != null) need = TypeHasVarLike(mr.FieldSig.Type);
                    if (!need) continue;
                    MemberRef rep;
                    if (!cache.TryGetValue(mr, out rep)) {
                        // 克隆对象树, GenericVar 原样保留(类级) — 新 MemberRef 触发 dnlib 重编码 sig blob (1E 00)
                        if (mr.MethodSig != null)
                            rep = new MemberRefUser(mod, mr.Name, CloneMethodSig(mr.MethodSig), mr.Class);
                        else
                            rep = new MemberRefUser(mod, mr.Name, new FieldSig(CloneType(mr.FieldSig.Type)), mr.Class);
                        cache[mr] = rep;
                        n++;
                    }
                    il[i].Operand = rep;
                    sites++;
                    if (mr.MDToken.Raw == 0x0A000181) Console.WriteLine("[dbg] hit 0x0A000181 in " + m.FullName + " -> rep=" + (rep == null ? "null" : "ok") + " same=" + (rep == mr));
                }
            }
        }
        Console.WriteLine("[sigclose] scanned=" + scanned + " newRefs=" + n + " sites=" + sites);
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], opts);
        Console.WriteLine("[sigclose] wrote " + a[1]);
    }

    static bool SigHasVarLike(MethodSig s) {
        if (TypeHasVarLike(s.RetType)) return true;
        if (s.Params != null) foreach (var p in s.Params) if (TypeHasVarLike(p)) return true;
        return false;
    }
    static bool TypeHasVarLike(TypeSig t) {
        while (t != null) {
            if (t is GenericVar || t is GenericMVar) return true;
            var gis = t as GenericInstSig;
            if (gis != null) {
                if (TypeHasVarLike(gis.GenericType)) return true;
                foreach (var ga in gis.GenericArguments) if (TypeHasVarLike(ga)) return true;
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
    static TypeSig CloneType(TypeSig t) {
        if (t is GenericVar) return new GenericVar((int)((GenericVar)t).Number);
        if (t is GenericMVar) return new GenericVar((int)((GenericMVar)t).Number);
        var g2 = t as GenericInstSig;
        if (g2 != null) {
            var gt = (ClassOrValueTypeSig)CloneType(g2.GenericType);
            var ng = new GenericInstSig(gt);
            foreach (var ga in g2.GenericArguments) ng.GenericArguments.Add(CloneType(ga));
            return ng;
        }
        var sz = t as SZArraySig;
        if (sz != null) return new SZArraySig(CloneType(sz.Next));
        var byref = t as ByRefSig;
        if (byref != null) return new ByRefSig(CloneType(byref.Next));
        var ptr = t as PtrSig;
        if (ptr != null) return new PtrSig(CloneType(ptr.Next));
        return t;
    }
    static MethodSig CloneMethodSig(MethodSig s) {
        var ns = new MethodSig(s.CallingConvention, s.GenParamCount, CloneType(s.RetType));
        foreach (var p in s.Params) ns.Params.Add(CloneType(p));
        return ns;
    }
}
