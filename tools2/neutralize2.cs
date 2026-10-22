// neutralize2.cs — 中和所有"被注入 Reactor 初始化链"的类型 cctor
//
// 关键发现: Reactor 把初始化代码注入进**多个**类型的 .cctor, 不只是 <Module>::.cctor。
// Krypton 只清了 <Module>::.cctor, 于是 StatelessModel::.cctor 仍在跑:
//     call WrapperProvider::ValidateAccessibleResponderManager()
//     call DispatcherInitializer::DefineEfficientProfiler()
//     call DispatcherInitializer::InstantiateGlobalCalculator()   (还重复了一次)
//     call DispatcherInitializer::DefineActiveEvent()
// 方法体已经明文了, 这些初始化不仅没用而且有害 —— 它们会去装 JIT hook,
// hook 再按"加密体"去处理明文体, 于是 InvalidProgram / Bad IL range / 访问违规。
//
// 判据: 某个 .cctor 里调用了 DispatcherInitializer / WrapperProvider 的静态方法 -> 清空为 ret
// 用法: neutralize2 <in.exe> <out.exe> [--dry]
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class Neutralize2 {
    static readonly string[] ReactorTypes = {
        "CloudClient.Templating.DispatcherInitializer",
        "AirExplorer.Wrapping.WrapperProvider",
    };

    static void Main(string[] a) {
        string inPath = a[0], outPath = a[1];
        bool dry = a.Length > 2 && a[2] == "--dry";
        var mod = ModuleDefMD.Load(inPath);

        int n = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (m.Name.String != ".cctor" || !m.HasBody) continue;
                bool hit = false;
                foreach (var ins in m.Body.Instructions) {
                    var im = ins.Operand as IMethod;
                    if (im == null) continue;
                    var dt = im.DeclaringType;
                    if (dt == null) continue;
                    string tn = dt.FullName;
                    if (ReactorTypes.Any(x => tn.StartsWith(x, StringComparison.Ordinal))) { hit = true; break; }
                }
                if (!hit) continue;

                n++;
                Console.WriteLine("[neutral] " + t.FullName + "::.cctor  (il=" + m.Body.Instructions.Count + ")");
                if (dry) continue;
                var body = new CilBody();
                body.MaxStack = 0;
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                m.Body = body;
            }
        }

        Console.WriteLine("[neutralize2] 命中 " + n + " 个 cctor");
        if (dry || n == 0) return;
        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        // PreserveAll 很关键: dnlib 默认写入会重排元数据行号(RID), 而 Reactor 的
            // VM/解密 blob 里存的是**原始** token, 运行时靠 ResolveMethod/ResolveField 解析。
            // 一旦重排, 就会解析到错误成员并触发 anti-tamper 异常(AutoReaktor v3 记的头号坑)。
            wopt.MetadataOptions.Flags = dnlib.DotNet.Writer.MetadataFlags.PreserveAll
                                       | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, wopt);
        Console.WriteLine("[neutralize2] 写出: " + outPath);
    }
}
