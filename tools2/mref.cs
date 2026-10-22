using System;
using System.Linq;
using dnlib.DotNet;

// mref: 列出 MemberRef / TypeRef 里名字含关键字的行 (给字节补丁找现成 token 用)
// 用法: mref <file> <keyword>
class MRef {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string kw = a[1];
        int n = 0;
        foreach (var mr in mod.GetMemberRefs()) {
            string full = mr.FullName;
            if (full.IndexOf(kw, StringComparison.OrdinalIgnoreCase) < 0) continue;
            Console.WriteLine("MR 0x" + mr.MDToken.Raw.ToString("X8") + "  " + full);
            n++;
        }
        foreach (var tr in mod.GetTypeRefs()) {
            if (tr.FullName.IndexOf(kw, StringComparison.OrdinalIgnoreCase) < 0) continue;
            Console.WriteLine("TR 0x" + tr.MDToken.Raw.ToString("X8") + "  " + tr.FullName);
            n++;
        }
        Console.WriteLine("total " + n);
    }
}
