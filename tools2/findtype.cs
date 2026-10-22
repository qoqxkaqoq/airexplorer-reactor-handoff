// findtype.cs — 按关键字找类型, 并列出它的字段/大小
// 用法: findtype <file.exe> <keyword>
using System;
using System.Linq;
using dnlib.DotNet;

class FindType {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string kw = a.Length > 1 ? a[1] : "PrivateImplementationDetails";
        foreach (var t in mod.GetTypes()) {
            if (!t.FullName.Contains(kw)) continue;
            Console.WriteLine("[type] " + t.FullName + "  字段=" + t.Fields.Count + " 方法=" + t.Methods.Count);
            foreach (var f in t.Fields) {
                string rv = "";
                try { if (f.RVA != 0) rv = " rva=0x" + ((uint)f.RVA).ToString("X"); } catch { }
                Console.WriteLine("    fld " + f.Name + " : " + f.FieldType + rv);
            }
        }
    }
}
