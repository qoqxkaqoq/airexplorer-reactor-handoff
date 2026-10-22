using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// stripinit: 在真实的 .cctor 里**只删掉 Reactor 的引导调用**, 保留应用自身的初始化。
//
// 为什么需要: Reactor 把初始化链注入进成百上千个类型的 .cctor。
//   - 直接清成 ret  -> 应用自己的单例/静态字段永不初始化 -> 下游 NRE (depfix6 的 m_RequestClient 就是)
//   - 原样保留      -> 引导会去装 JIT hook / 建 BinaryReader(resource) -> ArgumentNullException / InvalidProgram
// 所以只摘掉引导, 保留剩下的语句。
//
// 用法: stripinit <in.exe> <out.exe> [--dry]
class StripInit {
    static readonly string[] ReactorTypes = {
        "CloudClient.Templating.DispatcherInitializer",
        "AirExplorer.Wrapping.WrapperProvider",
        "AirExplorer.Search.FinderMap",
    };

    static void Main(string[] a) {
        string inPath = a[0], outPath = a[1];
        bool dry = a.Length > 2 && a[2] == "--dry";
        var mod = ModuleDefMD.Load(inPath);

        int touched = 0, removed = 0, retargeted = 0;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (m.Name.String != ".cctor" || !m.HasBody) continue;
                var body = m.Body;
                var ins = body.Instructions;
                var kill = new HashSet<Instruction>();
                foreach (var x in ins) {
                    if (x.OpCode.Code != Code.Call && x.OpCode.Code != Code.Callvirt) continue;
                    if (!(x.Operand is IMethod im)) continue;
                    var dt = im.DeclaringType;
                    if (dt == null) continue;
                    if (ReactorTypes.Contains(dt.FullName)) kill.Add(x);
                }
                if (kill.Count == 0) continue;

                // 分支目标若落在被删指令上, 重定向到其后第一条存活指令
                var order = ins.ToList();
                foreach (var x in order) {
                    if (x.Operand is Instruction tgt && kill.Contains(tgt)) {
                        int i = order.IndexOf(tgt);
                        Instruction next = null;
                        for (int j = i + 1; j < order.Count; j++) if (!kill.Contains(order[j])) { next = order[j]; break; }
                        if (next != null) { x.Operand = next; retargeted++; }
                    } else if (x.Operand is Instruction[] arr) {
                        for (int k = 0; k < arr.Length; k++)
                            if (kill.Contains(arr[k])) {
                                int i = order.IndexOf(arr[k]);
                                for (int j = i + 1; j < order.Count; j++) if (!kill.Contains(order[j])) { arr[k] = order[j]; retargeted++; break; }
                            }
                    }
                }
                foreach (var x in kill) ins.Remove(x);
                if (ins.Count == 0) ins.Add(OpCodes.Ret.ToInstruction());   // 全被删空时必须留一条 ret
                removed += kill.Count;
                touched++;
                body.UpdateInstructionOffsets();
            }

        Console.WriteLine("[stripinit] cctor touched = " + touched + "  calls removed = " + removed + "  targets retargeted = " + retargeted);
        if (dry) return;

        var wopt = new ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags = MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, wopt);
        Console.WriteLine("[stripinit] wrote " + outPath + "  size=" + new FileInfo(outPath).Length);
    }
}
