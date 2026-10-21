using System;
using dnlib.DotNet;

class PeekRes {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var r in mod.Resources) {
            if (r is dnlib.DotNet.EmbeddedResource er) {
                var rd = er.CreateReader();
                var head = new byte[16];
                for (int i = 0; i < 16; i++) head[i] = rd.ReadByte();
                var hex = BitConverter.ToString(head).Replace("-", " ");
                bool isStd = head[0] == 0xCE && head[1] == 0xCA && head[2] == 0xEF && head[3] == 0xBE;
                Console.WriteLine("[res] " + r.Name + " | 头16B: " + hex + " | " + (isStd ? "标准.resources(已解密)" : "非标准(可能加密)"));
            }
        }
        // 也检查是否有 AssemblyResource(链接型)
        return 0;
    }
}
