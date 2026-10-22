using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// xref: 列出所有引用指定类型/成员的方法与指令 (定位"谁创建了这个委托/谁给这个字段赋值")
// 用法: xref <file> <typeOrMemberSubstr> [--ctor] [--limit N]
class XRef {
    static void Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: xref <file> <substr> [--ctor] [--limit N]"); return; }
        var mod = ModuleDefMD.Load(a[0]);
        string kw = a[1];
        bool onlyCtor = a.Any(x => x == "--ctor");
        int limit = 200;
        for (int i = 2; i < a.Length; i++) if (a[i] == "--limit" && i + 1 < a.Length) limit = int.Parse(a[++i]);
        int n = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    string s = null;
                    if (ins.Operand is IMethod im) s = "M " + im.FullName + " [0x" + im.MDToken.Raw.ToString("X8") + "]";
                    else if (ins.Operand is IField f) s = "F " + f.FullName + " [0x" + f.MDToken.Raw.ToString("X8") + "]";
                    else if (ins.Operand is IType ty) s = "T " + ty.FullName + " [0x" + ty.MDToken.Raw.ToString("X8") + "]";
                    if (s == null) continue;
                    if (s.IndexOf(kw, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    if (onlyCtor && ins.OpCode.Code != Code.Newobj && ins.OpCode.Code != Code.Ldftn) continue;
                    Console.WriteLine(t.FullName + "::" + m.Name + "  @" + ins.Offset.ToString("X4") + "  " + ins.OpCode.Name + "  " + s);
                    if (++n >= limit) { Console.WriteLine("... limit"); return; }
                }
            }
        }
        Console.WriteLine("total " + n);
    }
}
