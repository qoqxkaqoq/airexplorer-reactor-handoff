using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// patchtamper <in.exe> <out.exe> — NOP 掉 IGC 真体的 tamper 校验段(ldtoken..throw)
class PatchTamper {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var m = mod.ResolveToken(0x06004192u) as MethodDef;
        if (m == null || !m.HasBody) { Console.WriteLine("IGC null"); return; }
        var il = m.Body.Instructions;
        int throwIdx = -1, ldstrIdx = -1;
        for (int i = 0; i < il.Count; i++) {
            if (il[i].OpCode.Code == Code.Ldstr && il[i].Operand is string s && s.Contains(" is tampered.")) {
                ldstrIdx = i;
                for (int k = i + 1; k < il.Count; k++) if (il[k].OpCode.Code == Code.Throw) { throwIdx = k; break; }
                break;
            }
        }
        if (throwIdx < 0) { Console.WriteLine("pattern not found"); return; }
        // 向前找段起点: 第一个 ldtoken(在此之前有 br 进入, 段由 ldtoken 开始算哈希)
        int startIdx = ldstrIdx;
        for (int k = ldstrIdx; k >= System.Math.Max(0, ldstrIdx - 12); k--) {
            if (il[k].OpCode.Code == Code.Ldtoken) { startIdx = k; break; }
        }
        Console.WriteLine("[patch] NOP range: #" + startIdx + " @" + il[startIdx].Offset.ToString("X4")
            + " .. #" + throwIdx + " @" + il[throwIdx].Offset.ToString("X4"));
        for (int k = startIdx; k <= throwIdx; k++) {
            il[k].OpCode = OpCodes.Nop;
            il[k].Operand = null;
        }
        Console.WriteLine("[patch] NOPed " + (throwIdx - startIdx + 1) + " instructions");
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], opts);
        Console.WriteLine("[patchtamper] wrote " + a[1]);
    }
}
