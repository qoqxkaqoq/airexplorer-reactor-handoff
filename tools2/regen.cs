// regen.cs — 重新写盘, 让 dnlib 按 IL 重新计算每个方法的 MaxStack
//
// 背景: 本样本回植真体后启动即崩(0xE0434352), 堆栈是
//   InvalidProgramException at VerifyCombinedStateRequest()
// InvalidProgramException 最常见的成因之一就是方法头 MaxStack 小于实际需要的栈深。
//
// 前任这条工具链上所有写盘处都加了 MetadataFlags.KeepOldMaxStack,
// 也就是沿用了被 nb_slayer dump 时写死的旧 MaxStack 值。
// 本工具不加这个 flag, 让 dnlib 依 IL/CFG 自己算一遍 MaxStack。
//
// 用法: regen <in.exe> <out.exe> [--max N]    (--max: 强制所有方法 MaxStack 不小于 N)
using System;
using System.Linq;
using dnlib.DotNet;

class Regen {
    static void Main(string[] a) {
        string inPath = a[0], outPath = a[1];
        int floor = 0;
        for (int i = 2; i < a.Length; i++)
            if (a[i] == "--max" && i + 1 < a.Length) int.TryParse(a[i + 1], out floor);

        var mod = ModuleDefMD.Load(inPath);
        int bodies = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                bodies++;
                if (floor > 0) {
                    // dnlib 对这类体算不出 maxstack(CFG 汇合处栈深不一致),
                    // 改用保守大值兜底: MaxStack 偏大只是多占点栈空间, 偏小才会 InvalidProgramException
                    if (m.Body.MaxStack < floor) m.Body.MaxStack = (ushort)floor;
                    m.Body.KeepOldMaxStack = true;
                } else {
                    m.Body.KeepOldMaxStack = false;      // 交给 dnlib 重算
                }
            }
        }
        Console.WriteLine("[regen] 有体方法 = " + bodies + (floor > 0 ? ("  MaxStack 下限 = " + floor) : ""));

        var opt = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        if (floor > 0) opt.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, opt);
        Console.WriteLine("[regen] 写出: " + outPath);
    }
}
