// neutralize.cs — 中和残留的 Reactor 保护运行时
//
// 推理链:
//   depfix2 里方法体已经是明文(不需要运行时解密了),
//   但 <Module>::.cctor 仍会走 DefineEfficientProfiler 等初始化链去装 JIT hook,
//   hook 再按"加密体"的方式去处理这些明文体 -> 喂给 JIT 的东西不对 -> InvalidProgramException。
//   (Krypton 的 README 里对应的能力叫 "neutralize leftover protection runtime")
// 因此: 方法体已明文的前提下, 初始化链不仅没用而且有害, 应该中和掉。
//
// 三档:
//   --mode cctors   只清空 <Module>::.cctor (最彻底)
//   --mode hook     只把 JIT hook 方法(6 参 uint 返回) 直接返回 0
//   --mode both     两者都做
// 用法: neutralize <in.exe> <out.exe> [--mode both]
using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class Neutralize {
    static void Main(string[] a) {
        string inPath = a[0], outPath = a[1];
        string mode = "both";
        for (int i = 2; i < a.Length; i++)
            if (a[i] == "--mode" && i + 1 < a.Length) mode = a[i + 1];

        var mod = ModuleDefMD.Load(inPath);
        int n = 0;

        if (mode == "cctors" || mode == "both") {
            var gt = mod.GlobalType;
            if (gt != null) {
                foreach (var m in gt.Methods) {
                    if (m.Name.String != ".cctor") continue;
                    var body = new CilBody();
                    body.MaxStack = 0;
                    body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                    m.Body = body;
                    n++;
                    Console.WriteLine("[neutralize] 清空 <Module>::.cctor");
                }
            }
        }

        if (mode == "hook" || mode == "both") {
            foreach (var t in mod.GetTypes()) {
                foreach (var m in t.Methods) {
                    if (!m.IsStatic || !m.HasBody) continue;
                    var sig = m.MethodSig;
                    if (sig == null || sig.Params.Count != 6) continue;
                    if (sig.RetType.FullName != "System.UInt32") continue;
                    // DNR 的 CompileMethod: 什么都不做, 直接返回 0 (让 JIT 走正常路径)
                    var body = new CilBody();
                    body.MaxStack = 1;
                    body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
                    body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                    m.Body = body;
                    n++;
                    Console.WriteLine("[neutralize] JIT hook 置空: " + t.FullName + "::" + m.Name);
                }
            }
        }

        if (n == 0) { Console.WriteLine("[neutralize] 没找到可中和的目标"); return; }
        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        // PreserveAll 很关键: dnlib 默认写入会重排元数据行号(RID), 而 Reactor 的
            // VM/解密 blob 里存的是**原始** token, 运行时靠 ResolveMethod/ResolveField 解析。
            // 一旦重排, 就会解析到错误成员并触发 anti-tamper 异常(AutoReaktor v3 记的头号坑)。
            wopt.MetadataOptions.Flags = dnlib.DotNet.Writer.MetadataFlags.PreserveAll
                                       | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, wopt);
        Console.WriteLine("[neutralize] 写出: " + outPath + " (改动 " + n + " 处)");
    }
}
