// probe.cs — 用反射列出 dnlib 关键类型的成员，确定 API 名字
using System;
using System.Linq;
using System.Reflection;

class Probe {
    static void Main(string[] a) {
        string want = a.Length > 0 ? a[0] : "ModuleDefMD";
        var types = typeof(dnlib.DotNet.ModuleDefMD).Assembly.GetTypes();
        foreach (var t in types) {
            if (!t.Name.Contains(want)) continue;
            Console.WriteLine("### TYPE " + t.FullName);
            foreach (var p in t.GetProperties(BindingFlags.Public | BindingFlags.Instance))
                Console.WriteLine("   prop " + p.PropertyType.Name + " " + p.Name);
            foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
                              .Where(m => !m.IsSpecialName))
                Console.WriteLine("   meth " + m.ReturnType.Name + " " + m.Name + "(" + string.Join(",", m.GetParameters().Select(x => x.ParameterType.Name)) + ")");
            foreach (var f in t.GetFields(BindingFlags.Public | BindingFlags.Instance))
                Console.WriteLine("   fld  " + f.FieldType.Name + " " + f.Name);
        }
    }
}
