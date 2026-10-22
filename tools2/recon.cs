// recon.cs — 样本静态画像: PE节/资源/方法体RVA分布/模块cctor链/Reactor痕迹
// 用法: recon <file.exe> [typeFullName]
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;

class Recon {
    // dnlib 3.3.4 里 IPEImage 是内部成员，用反射拿，避免 API 名猜测
    static object GetPEImage(ModuleDefMD mod) {
        foreach (var name in new[] { "MetaData", "Metadata" }) {
            var pi = typeof(ModuleDefMD).GetProperty(name,
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            if (pi != null) {
                var v = pi.GetValue(mod);
                if (v != null) {
                    var p2 = v.GetType().GetProperty("PEImage");
                    if (p2 != null) return p2.GetValue(v);
                }
            }
            var fi = typeof(ModuleDefMD).GetField(name.Substring(0, 1).ToLowerInvariant() + name.Substring(1),
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            if (fi != null) {
                var v = fi.GetValue(mod);
                if (v != null) {
                    var p2 = v.GetType().GetProperty("PEImage");
                    if (p2 != null) return p2.GetValue(v);
                }
            }
        }
        return null;
    }
    static void Main(string[] a) {
        string file = a[0];
        var mod = ModuleDefMD.Load(file);
        dynamic pe = GetPEImage(mod);
        if (pe == null) Console.WriteLine("(warn) 拿不到 IPEImage，跳过 PE 节信息");
        Console.WriteLine("===== FILE: " + Path.GetFileName(file) + " (" + new FileInfo(file).Length + " B) =====");

        // --- PE 节 ---
        Console.WriteLine("--- PE sections ---");
        foreach (var s in pe.ImageSectionHeaders) {
            object rawName = s.Name;
            string name = rawName is byte[] b ? System.Text.Encoding.ASCII.GetString(b).TrimEnd('\0') : Convert.ToString(rawName);
            Console.WriteLine(string.Format("  {0,-12} RVA=0x{1:X8} VS=0x{2:X8} Raw=0x{3:X6} Phys=0x{4:X6} flags=0x{5:X8}",
                name, Convert.ToUInt32(s.VirtualAddress), Convert.ToUInt32(s.VirtualSize),
                Convert.ToUInt32(s.SizeOfRawData), Convert.ToUInt32(s.PointerToRawData), Convert.ToUInt32(s.Characteristics)));
        }

        // --- COR20 / 附加数据区 ---
        Console.WriteLine("--- COR20 dir ---");
        try {
            var dd = pe.ImageNTHeaders.OptionalHeader.DataDirectories[14];
            Console.WriteLine(string.Format("  RVA=0x{0:X8} size=0x{1:X}", (uint)dd.VirtualAddress, (uint)dd.Size));
        } catch (Exception e) { Console.WriteLine("  (unavailable: " + e.Message + ")"); }
        // 各节末尾的"尾部数据"（Reactor 常把加密数据放在最后一节之后的附加节）
        Console.WriteLine("--- tail beyond last section ---");
        try {
            uint maxEnd = 0;
            foreach (var s in pe.ImageSectionHeaders)
                maxEnd = Math.Max(maxEnd, (uint)s.PointerToRawData + (uint)s.SizeOfRawData);
            var fi2 = new FileInfo(file);
            long extra = fi2.Length - maxEnd;
            Console.WriteLine("  fileSize=" + fi2.Length + " lastSectionEnd=" + maxEnd + " extraTail=" + extra + "B");
        } catch (Exception e) { Console.WriteLine("  (unavailable: " + e.Message + ")"); }

        // --- 资源 ---
        Console.WriteLine("--- resources (" + mod.Resources.Count + ") ---");
        foreach (var r in mod.Resources) {
            long len = 0;
            if (r is EmbeddedResource erc) len = erc.CreateReader().Length;
            Console.WriteLine("  [" + r.ResourceType + "] " + r.Name + " " + len + "B");
        }

        // --- 类型/方法体统计 ---
        int withBody = 0, noBody = 0, rvaZero = 0, native = 0;
        var noBodySamples = new List<string>();
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (m.MethodBody == null) continue;
                if (m.HasBody) withBody++;
                else {
                    noBody++;
                    if (m.IsNative) native++;
                    if (m.RVA == 0) rvaZero++;
                    if (noBodySamples.Count < 15) noBodySamples.Add(t.FullName + "::" + m.Name);
                }
            }
        }
        Console.WriteLine("--- methods: body=" + withBody + " nobody=" + noBody + " (rva=0:" + rvaZero + " native:" + native + ") ---");
        foreach (var s in noBodySamples) Console.WriteLine("    nobody> " + s);

        // --- 全局类型 ---
        var g = mod.GlobalType;
        if (g != null) {
            Console.WriteLine("--- <Module>: methods=" + g.Methods.Count + " fields=" + g.Fields.Count + " ---");
            foreach (var m in g.Methods)
                Console.WriteLine("    " + m.Name + " sig=" + m.MethodSig + " body=" + m.HasBody + " rva=0x" + m.RVA.ToString("X"));
            foreach (var f in g.Fields)
                Console.WriteLine("    fld " + f.Name + " " + f.FieldType + " rva=0x" + (f.RVA).ToString("X"));
        }

        // --- 入口 ---
        Console.WriteLine("--- entrypoint: " + (mod.EntryPoint == null ? "none" : mod.EntryPoint.FullName) + " ---");

        // --- 指定类型的全部方法 ---
        if (a.Length > 1) {
            string want = a[1];
            foreach (var t in mod.GetTypes()) {
                if (t.FullName != want) continue;
                Console.WriteLine("--- type " + t.FullName + " ---");
                foreach (var m in t.Methods)
                    Console.WriteLine(string.Format("    {0,-40} body={1,-5} il={2,-6} rva=0x{3:X6} implflags=0x{4:X4} attrs={5}",
                        m.Name, m.HasBody, m.HasBody ? m.Body.Instructions.Count : 0, (uint)m.RVA, (uint)m.ImplAttributes, m.Attributes));
                foreach (var f in t.Fields)
                    Console.WriteLine("    fld " + f.Name + " : " + f.FieldType);
            }
        }
    }
}
