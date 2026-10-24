using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
// bcscan <exe> — 列出引用 BouncyCastle 类型/成员的所有方法（RSA 验证点=激活校验）
class BcScan {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var bcRefs = new List<IMemberRef>();
        foreach (var mr in mod.GetMemberRefs()) {
            string cn = mr.Class is ITypeDefOrRef t ? t.FullName : "";
            if (cn.IndexOf("BouncyCastle", StringComparison.OrdinalIgnoreCase) >= 0) bcRefs.Add(mr);
        }
        Console.WriteLine("[bc] BouncyCastle MemberRefs=" + bcRefs.Count);
        var bcSet = bcRefs.Select(x => x.MDToken.Raw).ToHashSet();
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (m.Body == null) continue;
                var hits = m.Body.Instructions
                    .Where(i => (i.OpCode.Code == dnlib.DotNet.Emit.Code.Call || i.OpCode.Code == dnlib.DotNet.Emit.Code.Callvirt || i.OpCode.Code == dnlib.DotNet.Emit.Code.Newobj)
                            && i.Operand is IMemberRef mr && bcSet.Contains(mr.MDToken.Raw))
                    .Select(i => ((IMemberRef)i.Operand).FullName).Distinct().ToList();
                if (hits.Count > 0) {
                    Console.WriteLine("0x" + m.MDToken.Raw.ToString("X8") + " " + t.FullName + "::" + m.Name + "  [" + hits.Count + "]");
                    foreach (var h in hits.Take(8)) Console.WriteLine("     " + h);
                }
            }
        }
    }
}
