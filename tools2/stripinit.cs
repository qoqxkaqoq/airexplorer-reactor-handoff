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
    // 这些**不能**摘: TrackCompiler(rt) 是"按类型句柄初始化该类型静态字段"的例程,
    // 摘掉它, cctor 里本该被赋值的静态对象(如 ValidatorDefinition::MatchRunner)就永远是 null,
    // 下游会以 NullReferenceException 的形式炸在莫名其妙的地方。
    static readonly string[] KeepMethods = { "TrackCompiler" };

    static readonly string[] ReactorTypes = {
        "CloudClient.Templating.DispatcherInitializer",
        "AirExplorer.Wrapping.WrapperProvider",
        "AirExplorer.Search.FinderMap",
    };

    static void Main(string[] a) {
        string inPath = a[0], outPath = a[1];
        bool dry = a.Contains("--dry");
        bool all = a.Contains("--all");   // 连非 cctor 方法里的引导调用一起摘(只摘无参 void)
        var mod = ModuleDefMD.Load(inPath);

        int touched = 0, removed = 0, retargeted = 0;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                if (m.Name.String != ".cctor" && !all) continue;
                var body = m.Body;
                var ins = body.Instructions;
                var kill = new HashSet<Instruction>();
                foreach (var x in ins) {
                    if (x.OpCode.Code != Code.Call && x.OpCode.Code != Code.Callvirt) continue;
                    if (!(x.Operand is IMethod im)) continue;
                    var dt = im.DeclaringType;
                    if (dt == null) continue;
                    if (!ReactorTypes.Contains(dt.FullName)) continue;
                    // 只摘"返回 void"的调用。
                    // 注意 FinderMap::DirectDefinition 有重载: 无参 void 的是装 hook,
                    // (int)->string 的那个才是**字符串解密器** —— 摘掉它会让 stsfld 从空栈取值,
                    // 直接变成 InvalidProgramException。所以必须按返回类型判断。
                    if (KeepMethods.Contains(im.Name.String)) continue;
                    bool isVoid = im.MethodSig != null && im.MethodSig.RetType != null
                                  && im.MethodSig.RetType.ElementType == ElementType.Void;
                    if (isVoid) kill.Add(x);
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
                // 不能直接删: 被摘的 call 可能带参数(例如 TrackCompiler(ldtoken ...)),
                // 直接删会让栈上残留值 -> InvalidProgramException。
                // 用 N 个 pop 顶掉它的参数, 保持栈平衡。
                foreach (var x in kill) {
                    var im2 = (IMethod)x.Operand;
                    int argc = im2.MethodSig == null ? 0 : im2.MethodSig.Params.Count;
                    x.OpCode = OpCodes.Pop;
                    x.Operand = null;
                    if (argc == 0) { x.OpCode = OpCodes.Nop; }
                    else {
                        int at = ins.IndexOf(x);
                        for (int n = 1; n < argc; n++) ins.Insert(at, OpCodes.Pop.ToInstruction());
                    }
                }
                if (ins.Count == 0) ins.Add(OpCodes.Ret.ToInstruction());
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
