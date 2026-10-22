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
        for (int i = 3; i < a.Length; i++) if (a[i] == "--only" && i + 1 < a.Length) only = a[++i];
        bool dump = a.Any(x => x == "--dump");

        // 1) 源侧假名类型 + 指纹
        var aliases = new Dictionary<string, TypeDef>();
        foreach (var t in src.GetTypes()) {
            var n = t.Name.String;
            if (!n.StartsWith("GeneratedType_") && !n.StartsWith("GeneratedEnum_")) continue;
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
        if (map.Count == 0) { Console.WriteLine("[err] 无可映射类型"); return 2; }

        // 3) 扫描 dst 的 IL, 替换操作数
        int nField = 0, nType = 0, nMethod = 0;
        foreach (var t in dst.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    if (ins.Operand is IField f) {
                        var dt = f.DeclaringType;
                        if (dt == null || !map.ContainsKey(dt.FullName)) continue;
                        var srcT = aliases[dt.FullName];
                        int idx = IndexOfField(srcT, f.Name);
                        if (idx < 0) { if (dump) Console.WriteLine("[missf] " + dt.FullName + "::" + f.Name); continue; }
                        var dstT = map[dt.FullName];
                        if (idx >= dstT.Fields.Count) { if (dump) Console.WriteLine("[oob] " + dstT.FullName + " idx=" + idx); continue; }
                        ins.Operand = dstT.Fields[idx];
                        nField++;
                    } else if (ins.Operand is IMethod im && im.DeclaringType != null && map.ContainsKey(im.DeclaringType.FullName)) {
                        var srcT = aliases[im.DeclaringType.FullName];
                        var dstT = map[im.DeclaringType.FullName];
                        var cand = dstT.Methods.FirstOrDefault(x => x.Name == im.Name);
                        if (cand != null) { ins.Operand = cand; nMethod++; }
                        else if (dump) Console.WriteLine("[missm] " + im.DeclaringType.FullName + "::" + im.Name);
                    } else if (ins.Operand is IType ty && map.ContainsKey(ty.FullName)) {
                        ins.Operand = map[ty.FullName];
                        nType++;
                    }
                }
            }
        }
        Console.WriteLine("[patch] fields=" + nField + " methods=" + nMethod + " types=" + nType);

        var wopt = new ModuleWriterOptions(dst);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        dst.Write(a[2], wopt);
        Console.WriteLine("[out] " + a[2] + " size=" + new FileInfo(a[2]).Length);
        return 0;
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
            ft = self ? "SELF" : (ftv == null ? "?" : ftv.TypeName);
            parts.Add((f.IsStatic ? "s:" : "i:") + ft);
        }
        return t.Fields.Count + "|" + string.Join(",", parts);
    }
}
