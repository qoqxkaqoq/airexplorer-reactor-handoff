using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// fixrefs: 修掉"从 cilantro 移植真体"时带过来的假名。
//
// 背景: cilantro 是 nb_slayer 的产物, 它把编译器生成的闭包类/哑枚举重命名成了
//   GeneratedType_0431 / GeneratedEnum_0425, 这些名字在原版里根本不存在,
//   于是移植过来的方法一 JIT 就 TypeLoadException。
//
// 对应关系(已逐个核对成员名与签名):
//   GeneratedType_0431<T>              -> TemplateArgument/URqFYq3xtmntT2OcLub`1
//   GeneratedType_0431::generatedMethod_0290
//                                      -> URqFYq3xtmntT2OcLub`1::r3vw2AFBgZ   (Comparison<DistributorProfile> 的 lambda)
//   GeneratedEnum_0425                 -> System.Int32
//       (真实调用点是 InstantiateStatelessUser<System.Int32>, 且实参是 ref int 局部)
//
// 用法: fixrefs <in.exe> <out.exe>
class FixRefs {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);

        // 1) 收集假 TypeRef
        TypeRef gt = null, ge = null;
        foreach (var tr in mod.GetTypeRefs()) {
            if (tr.Name == "GeneratedType_0431") gt = tr;
            if (tr.Name == "GeneratedEnum_0425") ge = tr;
        }
        Console.WriteLine("[fixrefs] GeneratedType_0431 = " + (gt == null ? "none" : gt.FullName));
        Console.WriteLine("[fixrefs] GeneratedEnum_0425 = " + (ge == null ? "none" : ge.FullName));

        // 2) 构造替换目标
        var corlib = mod.CorLibTypes.AssemblyRef;
        var int32 = new TypeRefUser(mod, "System", "Int32", corlib);

        TypeRef gtReal = null;
        if (gt != null) {
            var decl = gt.DeclaringType;   // TemplateArgument
            gtReal = decl != null
                ? new TypeRefUser(mod, "CloudClient.Templating.TemplateArgument", "URqFYq3xtmntT2OcLub`1", decl) { ResolutionScope = decl }
                : new TypeRefUser(mod, "CloudClient.Templating.TemplateArgument", "URqFYq3xtmntT2OcLub`1", mod.Assembly != null ? (IResolutionScope)mod.Assembly : mod);
            if (decl != null) { gtReal.ResolutionScope = decl; }
        }

        // 就地改名: TypeRef / MemberRef 是共享对象, 改一次即可覆盖全部引用
        int nMember = 0;
        if (gtReal != null && gt != null) gt.Name = "URqFYq3xtmntT2OcLub`1";
        if (ge != null) {
            // GeneratedEnum_0425 在真实代码里就是 System.Int32
            ge.Name = "Int32";
            ge.Namespace = "System";
            ge.ResolutionScope = corlib;
        }
        foreach (var mr in mod.GetMemberRefs()) {
            if (mr.Name == "generatedMethod_0290") { mr.Name = "r3vw2AFBgZ"; nMember++; }
        }
        int nType = (gt != null ? 1 : 0) + (ge != null ? 1 : 0);
        Console.WriteLine("[fixrefs] TypeRef 改名 = " + nType + "   成员名替换 = " + nMember);
        var wopt = new ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags = MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], wopt);
        Console.WriteLine("[fixrefs] wrote " + a[1]);
    }

}
