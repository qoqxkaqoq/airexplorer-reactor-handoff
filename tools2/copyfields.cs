// copyfields.cs — 补齐 C# 编译器生成的静态数据容器字段
//
// 现象: krypton_merge 启动报
//   MissingFieldException: Field not found: '<PrivateImplementationDetails>{A53A4920-...}.D5B7247C...'
// 原因: <PrivateImplementationDetails>(及带 GUID 的那个)是编译器放 byte[]/大常量数据的地方,
//       Krypton 重写程序集时丢了一部分字段, 而回填回来的方法仍引用它们。
// 坑: 字段类型 __StaticArrayInitTypeSize=N 必须带上 ClassLayout.Size=N,
//     否则 dnlib 写盘时报 initial value size != size of field type。
//
// 用法: copyfields <src> <dst> <out>
using System;
using System.Linq;
using dnlib.DotNet;

class CopyFields {
    static ModuleDef dst;

    static void Main(string[] a) {
        var src = ModuleDefMD.Load(a[0]);
        dst = ModuleDefMD.Load(a[1]);

        int addedFields = 0, addedTypes = 0;
        foreach (var st in src.GetTypes()) {
            if (!st.FullName.Contains("PrivateImplementationDetails")) continue;

            var dt = dst.Find(st.FullName, false);
            if (dt == null) {
                var nt = new TypeDefUser(st.Namespace, st.Name);
                nt.Attributes = st.Attributes;
                dst.Types.Add(nt);
                dt = nt;
                addedTypes++;
                Console.WriteLine("[copy] 补类型 " + st.FullName);
            }

            foreach (var sf in st.Fields) {
                if (dt.Fields.Any(x => x.Name.String == sf.Name.String)) continue;
                var ftype = ResolveArrayType(sf.FieldType == null ? null : sf.FieldType.FullName);
                var nf = new FieldDefUser(sf.Name, new FieldSig(ftype), sf.Attributes);
                try {
                    nf.HasFieldRVA = true;
                    nf.InitialValue = sf.InitialValue == null ? null : (byte[])sf.InitialValue.Clone();
                } catch (Exception ex) {
                    Console.WriteLine("[copy] 字段数据复制失败 " + sf.Name + ": " + ex.Message);
                }
                dt.Fields.Add(nf);
                addedFields++;
                Console.WriteLine("[copy] 补字段 " + st.FullName + "::" + sf.Name +
                                  (sf.InitialValue == null ? "" : (" (" + sf.InitialValue.Length + "B 数据)")));
            }
        }

        Console.WriteLine("[copyfields] 补字段 " + addedFields + " / 补类型 " + addedTypes);
        if (addedFields + addedTypes == 0) return;

        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(dst);
        // PreserveAll 很关键: dnlib 默认写入会重排元数据行号(RID), 而 Reactor 的
            // VM/解密 blob 里存的是**原始** token, 运行时靠 ResolveMethod/ResolveField 解析。
            // 一旦重排, 就会解析到错误成员并触发 anti-tamper 异常(AutoReaktor v3 记的头号坑)。
            wopt.MetadataOptions.Flags = dnlib.DotNet.Writer.MetadataFlags.PreserveAll
                                       | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        dst.Write(a[2], wopt);
        Console.WriteLine("[copyfields] 写出: " + a[2]);
    }

    // 按 __StaticArrayInitTypeSize=N 的语义在 dst 里找/建类型, 并写上 ClassLayout.Size=N
    static TypeSig ResolveArrayType(string fullName) {
        if (string.IsNullOrEmpty(fullName)) return null;
        var existing = dst.Find(fullName, false);
        if (existing != null) return existing.ToTypeSig();

        const string tag = "__StaticArrayInitTypeSize=";
        uint size = 0;
        int eq = fullName.LastIndexOf(tag, StringComparison.Ordinal);
        if (eq >= 0) uint.TryParse(fullName.Substring(eq + tag.Length), out size);

        string parentName = null, shortName = fullName;
        int slash = fullName.LastIndexOf('/');
        if (slash >= 0) { parentName = fullName.Substring(0, slash); shortName = fullName.Substring(slash + 1); }

        TypeDef parent = parentName == null ? null : dst.Find(parentName, false);
        var nt = new TypeDefUser("", shortName);
        nt.Attributes = dnlib.DotNet.TypeAttributes.NestedPublic |
                        dnlib.DotNet.TypeAttributes.ExplicitLayout |
                        dnlib.DotNet.TypeAttributes.Sealed;
        if (size > 0) nt.ClassLayout = new ClassLayoutUser(1, size);
        if (parent != null) parent.NestedTypes.Add(nt);
        else dst.Types.Add(nt);
        Console.WriteLine("[copy] 建类型 " + fullName + (size > 0 ? (" (size=" + size + ")") : ""));
        return nt.ToTypeSig();
    }
}
