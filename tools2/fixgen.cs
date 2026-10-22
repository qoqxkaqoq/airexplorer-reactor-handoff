using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// fixgen: 把 nb_slayer 产物里的假名类型 (GeneratedType_NNNN / GeneratedEnum_NNNN) 引用,
// 按"字段结构指纹"映射回目标模块的真实类型(典型: GeneratedType_0440 -> <Module>{a8c2e9b2...})。
//
// bodytrans 的 RebindRefs 只管字段/方法的"名字", 管不了"类型本身被改名"的情况,
// 于是移植体里留下 TypeRef GeneratedType_0440 -> TypeLoadException。
//
// 用法: fixgen <src(cilantro)> <dst> <out> [--only GeneratedType_0440] [--dump]
class FixGen {
    static int Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: fixgen <src> <dst> <out> [--only Name] [--dump]"); return 1; }
        var src = ModuleDefMD.Load(a[0]);
        var dst = ModuleDefMD.Load(a[1]);
        string only = null;
        var manual = new Dictionary<string, string>();
        for (int i = 3; i < a.Length; i++) {
            if (a[i] == "--only" && i + 1 < a.Length) only = a[++i];
            else if (a[i] == "--map" && i + 1 < a.Length) {
                var kv = a[++i].Split('=');
                if (kv.Length == 2) manual[kv[0]] = kv[1];
            }
        }
        bool dump = a.Any(x => x == "--dump");

        // 1) 源侧假名类型 + 指纹
        var aliases = new Dictionary<string, TypeDef>();
        foreach (var t in src.GetTypes()) {
            var n = t.Name.String;
            if (!n.StartsWith("GeneratedType_") && !n.StartsWith("GeneratedEnum_") && !n.StartsWith("GeneratedStruct_")) continue;
            if (only != null && n != only) continue;
            aliases[t.FullName] = t;
        }
        Console.WriteLine("[src] 假名类型 " + aliases.Count + (only != null ? " (only=" + only + ")" : ""));

        // 2) 目标侧类型池
        var dstTypes = dst.GetTypes().ToList();
        var map = new Dictionary<string, TypeDef>();
        foreach (var kv in aliases) {
            var fp = Fingerprint(kv.Value);
            // 先试"同父类型下按嵌套序号"——文档实证: 同一父类型下 cilantro 与官方的
            // NestedTypes 顺序一致, 这比全局指纹唯一匹配可靠得多。
            var srcT = kv.Value;
            if (srcT.DeclaringType != null) {
                var parentName = srcT.DeclaringType.FullName;
                var dstParent = dstTypes.FirstOrDefault(x => x.FullName == parentName);
                if (dstParent != null) {
                    int idx = -1;
                    for (int i = 0; i < srcT.DeclaringType.NestedTypes.Count; i++)
                        if (srcT.DeclaringType.NestedTypes[i] == srcT) { idx = i; break; }
                    if (idx >= 0 && idx < dstParent.NestedTypes.Count) {
                        var cand = dstParent.NestedTypes[idx];
                        if (Fingerprint(cand) == fp) {
                            map[kv.Key] = cand;
                            Console.WriteLine("[mapN] " + kv.Key + "  ->  " + cand.FullName + "  (idx " + idx + ")");
                            continue;
                        }
                        // 序号不对就退回到"同父下唯一指纹"
                        var sib = dstParent.NestedTypes.Where(x => Fingerprint(x) == fp).ToList();
                        if (sib.Count == 1) {
                            map[kv.Key] = sib[0];
                            Console.WriteLine("[mapP] " + kv.Key + "  ->  " + sib[0].FullName);
                            continue;
                        }
                    }
                }
            }
            var cands = dstTypes.Where(x => Fingerprint(x) == fp).ToList();
            if (cands.Count == 1) {
                map[kv.Key] = cands[0];
                Console.WriteLine("[map] " + kv.Key + "  ->  " + cands[0].FullName + "   (" + kv.Value.Fields.Count + " fields)");
            } else {
                Console.WriteLine("[skip] " + kv.Key + "  candidates=" + cands.Count + "  fp=" + fp.Substring(0, Math.Min(60, fp.Length)));
            }
        }
        foreach (var kv in manual) {
            var dstT = dstTypes.FirstOrDefault(x => x.FullName == kv.Value || x.Name == kv.Value);
            if (dstT != null) { map[kv.Key] = dstT; Console.WriteLine("[mapM] " + kv.Key + "  ->  " + dstT.FullName); }
            else Console.WriteLine("[mapM-miss] " + kv.Key + " -> " + kv.Value);
        }
        if (map.Count == 0) { Console.WriteLine("[err] 无可映射类型"); return 2; }

        // 3) 扫描 dst 的 IL, 替换操作数
        int nField = 0, nType = 0, nMethod = 0, nLocal = 0;
        foreach (var t in dst.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var v in m.Body.Variables) {
                    var nt = FixSig(v.Type, map);
                    if (nt != null && !ReferenceEquals(nt, v.Type)) { v.Type = nt; nLocal++; }
                }
                foreach (var ins in m.Body.Instructions) {
                    if (ins.Operand is IMethod im0 && im0.DeclaringType != null && map.ContainsKey(Norm(im0.DeclaringType.FullName))) {
                        // MemberRef 同时实现 IField/IMethod, 必须先按"方法引用"处理,
                        // 否则 ldftn 会被当成字段去查字段表 -> [missf] 漏掉
                        var imn0 = Norm(im0.DeclaringType.FullName);
                        var srcT0 = aliases[imn0];
                        var dstT0 = map[imn0];
                        MethodDef cand0 = dstT0.Methods.FirstOrDefault(x => x.Name == im0.Name);
                        if (cand0 == null) {
                            int mi0 = -1;
                            for (int k = 0; k < srcT0.Methods.Count; k++) if (srcT0.Methods[k].Name == im0.Name) { mi0 = k; break; }
                            if (mi0 >= 0 && mi0 < dstT0.Methods.Count) cand0 = dstT0.Methods[mi0];
                        }
                        if (cand0 != null) { ins.Operand = cand0; nMethod++; continue; }
                        if (dump) Console.WriteLine("[missm2] " + im0.DeclaringType.FullName + "::" + im0.Name);
                    }
                    if (ins.Operand is IField f) {
                        var dt = f.DeclaringType;
                        if (dt == null) continue;
                        var dtn = Norm(dt.FullName);
                        if (dtn == null || !map.ContainsKey(dtn)) continue;
                        var srcT = aliases[dtn];
                        int idx = IndexOfField(srcT, f.Name);
                        if (idx < 0) { if (dump) Console.WriteLine("[missf] " + dt.FullName + "::" + f.Name); continue; }
                        var dstT = map[dtn];
                        if (idx >= dstT.Fields.Count) { if (dump) Console.WriteLine("[oob] " + dstT.FullName + " idx=" + idx); continue; }
                        ins.Operand = dstT.Fields[idx];
                        nField++;
                    } else if (ins.Operand is IMethod im && im.DeclaringType != null && map.ContainsKey(Norm(im.DeclaringType.FullName))) {
                        var imn = Norm(im.DeclaringType.FullName);
                        var srcT = aliases[imn];
                        var dstT = map[imn];
                        var cand = dstT.Methods.FirstOrDefault(x => x.Name == im.Name);
                        if (cand == null) {
                            // 名字被 nb_slayer 改过 -> 按"类型内方法序号"回退
                            int mi = -1;
                            for (int k = 0; k < srcT.Methods.Count; k++) if (srcT.Methods[k] == im.ResolveMethodDef()) { mi = k; break; }
                            if (mi < 0) {
                                // MemberRef 解析不到 MethodDef 时按名字在同名方法里找序号
                                for (int k = 0; k < srcT.Methods.Count; k++) if (srcT.Methods[k].Name == im.Name) { mi = k; break; }
                            }
                            if (mi >= 0 && mi < dstT.Methods.Count) cand = dstT.Methods[mi];
                        }
                        if (cand != null) { ins.Operand = cand; nMethod++; }
                        else if (dump) Console.WriteLine("[missm] " + im.DeclaringType.FullName + "::" + im.Name);
                    } else if (ins.Operand is IType ty && map.ContainsKey(Norm(ty.FullName))) {
                        ins.Operand = map[Norm(ty.FullName)];
                        nType++;
                    }
                }
            }
        }
        Console.WriteLine("[patch] fields=" + nField + " methods=" + nMethod + " types=" + nType + " locals=" + nLocal);

        var wopt = new ModuleWriterOptions(dst);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        dst.Write(a[2], wopt);
        Console.WriteLine("[out] " + a[2] + " size=" + new FileInfo(a[2]).Length);
        return 0;
    }

    // 递归替换 TypeSig 里的假名类型（局部变量签名 / 数组元素 / byref / 泛型实参）
    static TypeSig FixSig(TypeSig sig, Dictionary<string, TypeDef> map) {
        if (sig == null) return null;
        if (sig is TypeDefOrRefSig tds) {
            var td = tds.TypeDefOrRef;
            if (td != null && map.ContainsKey(td.FullName)) {
                var target = map[td.FullName];
                bool isValue = target.IsValueType;
                return target.ToTypeSig(isValue);
            }
            return sig;
        }
        if (sig is SZArraySig sa) {
            var e = FixSig(sa.Next, map);
            return ReferenceEquals(e, sa.Next) ? sig : new SZArraySig(e);
        }
        if (sig is ByRefSig br) {
            var e = FixSig(br.Next, map);
            return ReferenceEquals(e, br.Next) ? sig : new ByRefSig(e);
        }
        if (sig is PtrSig p) {
            var e = FixSig(p.Next, map);
            return ReferenceEquals(e, p.Next) ? sig : new PtrSig(e);
        }
        if (sig is CModReqdSig cr) {
            var e = FixSig(cr.Next, map);
            return ReferenceEquals(e, cr.Next) ? sig : new CModReqdSig(cr.Modifier, e);
        }
        if (sig is CModOptSig co) {
            var e = FixSig(co.Next, map);
            return ReferenceEquals(e, co.Next) ? sig : new CModOptSig(co.Modifier, e);
        }
        if (sig is GenericInstSig gi) {
            bool changed = false;
            var args = new List<TypeSig>();
            foreach (var g in gi.GenericArguments) {
                var x = FixSig(g, map);
                if (!ReferenceEquals(x, g)) changed = true;
                args.Add(x);
            }
            if (!changed) return sig;
            return new GenericInstSig(gi.GenericType, args);
        }
        return sig;
    }

    // TypeSpec 的 FullName 带泛型实参 (X`1<Y>), map 的 key 是 X`1 -> 去掉 <...>
    static string Norm(string full) {
        if (full == null) return null;
        int i = full.IndexOf('<');
        return i > 0 ? full.Substring(0, i) : full;
    }

    static int IndexOfField(TypeDef t, UTF8String name) {
        for (int i = 0; i < t.Fields.Count; i++) if (t.Fields[i].Name == name) return i;
        return -1;
    }

    // 指纹: 字段数 + 每个字段的 (static?, 类型名, 是否自引用)
    static string Fingerprint(TypeDef t) {
        var parts = new List<string>();
        foreach (var f in t.Fields) {
            string ft;
            bool self = false;
            var ftv = f.FieldType;
            if (ftv != null && ftv.FullName == t.FullName) self = true;
            else if (ftv is ClassSig cs && cs.TypeDefOrRef != null && cs.TypeDefOrRef.FullName == t.FullName) self = true;
            else if (ftv is ValueTypeSig vs && vs.TypeDefOrRef != null && vs.TypeDefOrRef.FullName == t.FullName) self = true;
            else if (ftv is GenericInstSig gis && gis.GenericType != null && gis.GenericType.TypeDefOrRef != null && gis.GenericType.TypeDefOrRef.FullName == t.FullName) self = true;
            ft = self ? "SELF" : (ftv == null ? "?" : ftv.TypeName);
            parts.Add((f.IsStatic ? "s:" : "i:") + ft);
        }
        return t.Fields.Count + "|" + string.Join(",", parts);
    }
}
