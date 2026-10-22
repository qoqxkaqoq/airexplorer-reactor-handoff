using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;

// ilpatch: 在**原文件**里按 IL 偏移打字节补丁。长度不变, 所以不影响任何偏移/表。
// 用途: 中和反篡改分支(例如把 "br -> throw" 整条填成 nop, 让控制流落到正常路径)。
//
// 用法: ilpatch <in.exe> <out.exe> <Type::Method> <IL偏移(hex)> <字节(hex, 空格分隔)>
//   例: ilpatch in.exe out.exe "NS.Type::Method" 0x00F6 "00 00 00 00 00"
class IlPatch {
    static void Main(string[] a) {
        if (a.Length < 5) { Console.WriteLine("usage: ilpatch <in> <out> <Type::Method> <ilOffset> <hexbytes>"); return; }
        string inPath = a[0], outPath = a[1];
        var spec = a[2].Split(new[] { "::" }, StringSplitOptions.None);
        int ilOff = Convert.ToInt32(a[3].Replace("0x", ""), 16);
        var patch = a[4].Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(x => Convert.ToByte(x, 16)).ToArray();

        var mod = ModuleDefMD.Load(inPath);
        var t = mod.Find(spec[0], false);
        if (t == null) { Console.WriteLine("[err] 类型不存在: " + spec[0]); return; }
        var m = t.Methods.FirstOrDefault(x => x.Name == spec[1] && x.HasBody);
        if (m == null) { Console.WriteLine("[err] 方法不存在: " + spec[1]); return; }

        var data = File.ReadAllBytes(inPath);
        var secs = Sections(data);
        int bodyOff = RvaToOff(secs, (uint)m.RVA);
        if (bodyOff < 0) { Console.WriteLine("[err] RVA 映射失败"); return; }

        int b0 = data[bodyOff];
        int codeOff, codeSize;
        if ((b0 & 3) == 2) {                       // tiny
            codeSize = b0 >> 2; codeOff = bodyOff + 1;
        } else if ((b0 & 3) == 3) {                // fat
            ushort flags = BitConverter.ToUInt16(data, bodyOff);
            codeSize = BitConverter.ToInt32(data, bodyOff + 4);
            codeOff = bodyOff + 12;
            Console.WriteLine("[il] fat header, flags=0x" + flags.ToString("X") + " codeSize=" + codeSize);
        } else { Console.WriteLine("[err] 非法方法头 0x" + b0.ToString("X2")); return; }

        Console.WriteLine("[il] " + spec[0] + "::" + spec[1] + "  bodyOff=0x" + bodyOff.ToString("X")
                          + " codeOff=0x" + codeOff.ToString("X") + " codeSize=" + codeSize);
        Console.WriteLine("[il] 原字节 @0x" + (codeOff + ilOff).ToString("X") + " : "
                          + BitConverter.ToString(data, codeOff + ilOff, patch.Length));

        if (ilOff + patch.Length > codeSize) { Console.WriteLine("[err] 补丁越界"); return; }
        Array.Copy(patch, 0, data, codeOff + ilOff, patch.Length);
        File.WriteAllBytes(outPath, data);
        Console.WriteLine("[il] 已写入 " + outPath + "  (" + patch.Length + " 字节)");
    }

    static System.Collections.Generic.List<(uint va, uint vs, uint pr, uint rs)> Sections(byte[] d) {
        int pe = BitConverter.ToInt32(d, 0x3C);
        int n = BitConverter.ToUInt16(d, pe + 6);
        int optSize = BitConverter.ToUInt16(d, pe + 20);
        var list = new System.Collections.Generic.List<(uint, uint, uint, uint)>();
        for (int i = 0; i < n; i++) {
            int o = pe + 24 + optSize + i * 40;
            list.Add((BitConverter.ToUInt32(d, o + 12), BitConverter.ToUInt32(d, o + 8),
                      BitConverter.ToUInt32(d, o + 20), BitConverter.ToUInt32(d, o + 16)));
        }
        return list;
    }

    static int RvaToOff(System.Collections.Generic.List<(uint va, uint vs, uint pr, uint rs)> secs, uint rva) {
        foreach (var s in secs)
            if (rva >= s.va && rva < s.va + Math.Max(s.vs, s.rs))
                return (int)(s.pr + (rva - s.va));
        return -1;
    }
}
