using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// ilscan <exe> <id1,...>              — 扫描模块内所有明文方法 IL 找 ldc.i4 <id>
// ilscan dump <dumpDir> <id1,...>     — 扫描官方真体 dump（m_*.bin, 24B头+IL）找 ldc.i4 <id>
// 用途: 通过解密字符串 id 反查引用方法（激活链定位）
class IlScan {
    static ModuleDefMD mod;
    static void Main(string[] a) {
        if (a.Length >= 3 && a[0] == "dump") { ScanDump(a[1], a[2]); return; }
        mod = ModuleDefMD.Load(a[0]);
        var targets = a[1].Split(',').Select(x => int.Parse(x.Trim())).ToHashSet();
        var tn = a.Length > 2 ? a[2] : "";
        var dict = new Dictionary<int, List<string>>();
        foreach (var t in mod.GetTypes()) {
            if (tn.Length > 0 && !t.FullName.Contains(tn)) continue;
            foreach (var m in t.Methods) {
                if (m.Body == null) continue;
                foreach (var ins in m.Body.Instructions) {
                    if (ins.OpCode.Code != Code.Ldc_I4) continue;
                    if (ins.Operand is int v && targets.Contains(v)) {
                        if (!dict.TryGetValue(v, out var l)) dict[v] = l = new List<string>();
                        l.Add("0x" + m.MDToken.Raw.ToString("X8") + " " + t.FullName + "::" + m.Name);
                    }
                }
            }
        }
        Report(dict, targets);
    }

    static void ScanDump(string dir, string idsArg) {
        // 支持 US 偏移（正数或 32 位补码负数）
        var targets = new HashSet<int>();
        foreach (var s in idsArg.Split(',')) {
            var v = int.Parse(s.Trim());
            targets.Add(v);
            if (v < 0) targets.Add(v + unchecked((int)0x100000000) > int.MaxValue ? v : v); // placeholder
        }
        // 统一转 uint 比对
        var tus = targets.Select(x => (uint)x).ToHashSet();
        var dict = new Dictionary<uint, List<string>>();
        foreach (var bp in Directory.GetFiles(dir, "m_*.bin")) {
            var tokName = Path.GetFileNameWithoutExtension(bp).Substring(2);
            byte[] d;
            try { d = File.ReadAllBytes(bp); } catch { continue; }
            if (d.Length < 28) continue;
            int ilSize = (int)BitConverter.ToUInt32(d, 4);
            if (ilSize <= 0 || 24 + ilSize > d.Length) continue;
            var il = new byte[ilSize];
            Array.Copy(d, 24, il, 0, ilSize);
            for (int i = 0; i + 4 < il.Length; i++) {
                if (il[i] != 0x72) continue; // ldstr: operand = US token (0x70xxxxxx)
                uint tok = BitConverter.ToUInt32(il, i + 1);
                if ((tok & 0x70000000) == 0) continue;
                uint us = tok & 0x00FFFFFF;
                if (tus.Contains(us)) {
                    if (!dict.TryGetValue(us, out var l)) dict[us] = l = new List<string>();
                    l.Add("0x" + tokName + " (ldstr)");
                }
                i += 4;
            }
            // ldc.i4 模式（Reactor 字符串解密：ldc.i4 <usOff>; call decrypt）
            for (int i = 0; i + 4 < il.Length; i++) {
                if (il[i] != 0x20) continue;
                uint v = BitConverter.ToUInt32(il, i + 1);
                if (tus.Contains(v)) {
                    if (!dict.TryGetValue(v, out var l)) dict[v] = l = new List<string>();
                    l.Add("0x" + tokName + " (ldc.i4)");
                }
                i += 4;
            }
        }
        foreach (var kv in dict.OrderBy(x => x.Key)) {
            Console.WriteLine("== us " + kv.Key + " : " + kv.Value.Count + " refs");
            foreach (var s in kv.Value.Take(40)) Console.WriteLine("   " + s);
            if (kv.Value.Count > 40) Console.WriteLine("   ... +" + (kv.Value.Count - 40));
        }
        foreach (var id in tus.Where(x => !dict.ContainsKey(x)))
            Console.WriteLine("== us " + id + " : (0 refs)");
    }

    static void Report(Dictionary<int, List<string>> dict, HashSet<int> targets) {
        foreach (var kv in dict.OrderBy(x => x.Key)) {
            Console.WriteLine("== id " + kv.Key + " : " + kv.Value.Count + " refs");
            foreach (var s in kv.Value.Take(40)) Console.WriteLine("   " + s);
            if (kv.Value.Count > 40) Console.WriteLine("   ... +" + (kv.Value.Count - 40));
        }
        foreach (var id in targets.Where(x => !dict.ContainsKey(x)))
            Console.WriteLine("== id " + id + " : (0 refs)");
    }
}
