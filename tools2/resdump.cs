using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;

// resdump: 列出/导出模块的嵌入资源
// 用法: resdump <file> [nameSubstr] [outFile]
class ResDump {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string kw = a.Length > 1 ? a[1] : null;
        string outFile = a.Length > 2 ? a[2] : null;
        foreach (var r in mod.Resources) {
            var er = r as EmbeddedResource;
            long len = er != null ? (long)er.CreateReader().Length : -1;
            Console.WriteLine("RES  " + r.Name + "  len=" + len);
            if (kw != null && r.Name.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0 && er != null && outFile != null) {
                var data = er.CreateReader().ToArray();
                File.WriteAllBytes(outFile, data);
                Console.WriteLine("  -> " + outFile + " (" + data.Length + " bytes)");
            }
        }
    }
}
