using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// fixmap: 用"嵌套类型序号"把 cilantro 的假名批量映射回官方名。
//
// 依据(已实测): 同一父类型下, cilantro 与官方的 NestedTypes **顺序完全一致**
// (例: TemplateArgument 两边都是 40 个; 第 7 位 official=m4iNrp3uTHM9viOH5bc 对应 cilantro=GeneratedEnum_0425)。
// nb_slayer 只是把匿名/编译器生成的类型改了名, 没有重排。
//
// 于是: 对每个未解析的 Generated* TypeRef, 找到它在 **源** 里的序号, 取目标同序号类型改名。
// 成员(方法/字段)同理按在类型内的序号对齐。
//
// 用法: fixmap <src.exe(cilantro)> <dst.exe> <out.exe>
class FixMap {
    static void Main(string[] a) {
        var src = ModuleDefMD.Load(a[0]);
        var dst = ModuleDefMD.Load(a[1]);

        // 源索引: 父类型全名 -> (嵌套序号 -> TypeDef)
        var srcNested = new Dictionary<string, List<TypeDef>>();
        foreach (var t in src.GetTypes()) {
            var p = t.DeclaringType;
            if (p == null) continue;
            if (!srcNested.TryGetValue(p.FullName, out var l)) { l = new List<TypeDef>(); srcNested[p.FullName] = l; }
            l.Add(t);
        }

        int typeFixed = 0, memFixed = 0, unresolved = 0;

        foreach (var tr in dst.GetTypeRefs()) {
            if (!IsFake(tr.Name.String)) continue;
            if (tr.Resolve() != null) continue;                       // 已能解析, 不动
            var parentRef = tr.DeclaringType;
            if (parentRef == null) { unresolved++; continue; }

            if (!srcNested.TryGetValue(parentRef.FullName, out var sibs)) { unresolved++; continue; }
            int idx = sibs.FindIndex(x => x.Name.String == tr.Name.String);
            if (idx < 0) { unresolved++; continue; }

            var dstParent = dst.Find(parentRef.FullName, false);
            if (dstParent == null || dstParent.NestedTypes.Count <= idx) { unresolved++; continue; }
            var target = dstParent.NestedTypes[idx];
            Console.WriteLine("[map] " + parentRef.Name + "/" + tr.Name + "  ->  " + target.Name);
            tr.Name = target.Name;
            typeFixed++;

            // 该类型上的成员: 按在类型内的顺序对齐
            foreach (var mr in dst.GetMemberRefs()) {
                if (mr.Class != tr) continue;
                if (!IsFake(mr.Name.String)) continue;
                var st = sibs[idx];
                int mi = -1;
                if (mr.IsMethodRef) {
                    var lst = st.Methods.ToList();
                    mi = lst.FindIndex(x => x.Name.String == mr.Name.String);
                    if (mi >= 0 && mi < target.Methods.Count) { mr.Name = target.Methods[mi].Name.String; memFixed++; }
                } else if (mr.IsFieldRef) {
                    var lst = st.Fields.ToList();
                    mi = lst.FindIndex(x => x.Name.String == mr.Name.String);
                    if (mi >= 0 && mi < target.Fields.Count) { mr.Name = target.Fields[mi].Name.String; memFixed++; }
                }
            }
        }

        // 再扫一遍指令里的 MethodSpec / 成员引用兜底
        foreach (var t in dst.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    if (ins.Operand is IMethod im && im is MemberRef mr && IsFake(mr.Name.String)) {
                        var cls = mr.Class as TypeRef;
                        if (cls == null || cls.DeclaringType == null) continue;
                        if (!srcNested.TryGetValue(cls.DeclaringType.FullName, out var sibs)) continue;
                        int idx = sibs.FindIndex(x => x.Name.String == cls.Name.String);
                        if (idx < 0) continue;
                        var dstParent = dst.Find(cls.DeclaringType.FullName, false);
                        if (dstParent == null || dstParent.NestedTypes.Count <= idx) continue;
                        var target = dstParent.NestedTypes[idx];
                        var st = sibs[idx];
                        var lst = st.Methods.ToList();
                        int mi = lst.FindIndex(x => x.Name.String == mr.Name.String);
                        if (mi >= 0 && mi < target.Methods.Count) { mr.Name = target.Methods[mi].Name.String; memFixed++; }
                    }
                }
            }

        Console.WriteLine("[fixmap] 类型改名 = " + typeFixed + "  成员改名 = " + memFixed + "  未映射 = " + unresolved);
        var wopt = new ModuleWriterOptions(dst);
        wopt.MetadataOptions.Flags = MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        dst.Write(a[2], wopt);
        Console.WriteLine("[fixmap] wrote " + a[2]);
    }

    static bool IsFake(string n) {
        return n.StartsWith("GeneratedType_") || n.StartsWith("GeneratedEnum_") ||
               n.StartsWith("GeneratedMethod_") || n.StartsWith("generatedField_") || n.StartsWith("generatedMethod_");
    }
}
