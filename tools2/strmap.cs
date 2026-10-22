using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// strmap: 修 "JIT 写回体里的字符串还是密文" 的问题。
//
// 现象: 从 JIT 入口收割的 IL, ldstr 的 token 指向 #US 堆; 但 Reactor 加密的正是 #US 堆,
//       运行时才在内存里就地解密。于是写回文件后, ldstr 取到的是密文(例:
//       "ing>>-GetEnumerator>d__52" 其实是 "ValidatorArgument.EmitterReporter")。
// 依据: nb_slayer 的产物(nb_original)是在进程内跑的, #US 已是明文 —— 同一个方法同一位置的
//       ldstr 就是正确值。
//
// 做法: 逐方法按指令序号对齐(两边都是同一份代码), 把 (密文 -> 明文) 收集成全局表, 再整体替换。
//
// 用法:
//   strmap build <src(nb_original)> <dst> <map.tsv>     # 只统计
//   strmap apply <dst> <map.tsv> <out>                  # 按表替换并写盘
class StrMap {
    static void Main(string[] a) {
        if (a[0] == "build") Build(a[1], a[2], a[3]);
        else Apply(a[1], a[2], a[3]);
    }

    static void Build(string srcPath, string dstPath, string outTsv) {
        var src = ModuleDefMD.Load(srcPath);
        var dst = ModuleDefMD.Load(dstPath);
        var map = new Dictionary<string, string>();
        int same = 0, diff = 0, unaligned = 0;

        foreach (var t in dst.GetTypes()) {
            var st = src.Find(t.FullName, false);
            if (st == null) continue;
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var sm = st.Methods.FirstOrDefault(x => x.Name == m.Name && x.HasBody && x.MethodSig != null
                                                        && m.MethodSig != null
                                                        && x.MethodSig.Params.Count == m.MethodSig.Params.Count);
                if (sm == null) continue;
                var di = m.Body.Instructions;
                var si = sm.Body.Instructions;
                if (di.Count != si.Count) { unaligned++; continue; }
                for (int i = 0; i < di.Count; i++) {
                    if (di[i].OpCode.Code != Code.Ldstr || si[i].OpCode.Code != Code.Ldstr) continue;
                    var d = di[i].Operand as string;
                    var s = si[i].Operand as string;
                    if (d == null || s == null) continue;
                    if (d == s) { same++; continue; }
                    // 只收"同位置不同值"的配对; 一个密文对应多个明文时保留第一个
                    if (!map.ContainsKey(d)) { map[d] = s; diff++; }
                }
            }
        }

        Console.WriteLine("[strmap] 相同 = " + same + "  不同(待修) = " + diff + "  指令数不齐的方法 = " + unaligned);
        foreach (var kv in map.Take(12))
            Console.WriteLine("   [" + kv.Key + "]  ->  [" + kv.Value + "]");
        File.WriteAllLines(outTsv, map.Select(kv => kv.Key.Replace("\t", "\\t") + "\t" + kv.Value.Replace("\t", "\\t")));
        Console.WriteLine("[strmap] 写出 " + outTsv);
    }

    static void Apply(string dstPath, string tsv, string outPath) {
        var map = new Dictionary<string, string>();
        foreach (var line in File.ReadAllLines(tsv)) {
            var p = line.Split('\t');
            if (p.Length < 2) continue;
            map[p[0].Replace("\\t", "\t")] = p[1].Replace("\\t", "\t");
        }
        Console.WriteLine("[strmap] 表项 = " + map.Count);

        var mod = ModuleDefMD.Load(dstPath);
        int hit = 0, miss = 0;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    if (ins.OpCode.Code != Code.Ldstr) continue;
                    var s = ins.Operand as string;
                    if (s == null) continue;
                    if (map.TryGetValue(s, out var good)) { ins.Operand = good; hit++; }
                    else miss++;
                }
            }
        Console.WriteLine("[strmap] 替换 = " + hit + "  未命中 = " + miss);
        var wopt = new ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags = MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, wopt);
        Console.WriteLine("[strmap] wrote " + outPath);
    }
}
