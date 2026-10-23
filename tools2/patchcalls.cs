using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// patchcalls <in.exe> <out.exe> — 把业务 cctor 里的 call InstantiateGlobalCalculator
// 等长替换为 5×nop(保留 06000002/0600459B 两处真实调用)。等长 → 所有偏移/EH 不变。
class PatchCalls {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var igcTok = 0x06004192u;
        var keep = new HashSet<uint> { 0x06000002u, 0x0600459Bu };
        int patched = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody || keep.Contains(m.MDToken.Raw)) continue;
                for (int i = 0; i < m.Body.Instructions.Count; i++) {
                    var ins = m.Body.Instructions[i];
                    if (ins.OpCode.Code != Code.Call || !(ins.Operand is IMethod im)) continue;
                    if (im.MDToken.Raw != igcTok) continue;
                    // 等长替换: 原 call(5B) → nop + 4×nop (共5条1字节nop)
                    ins.OpCode = OpCodes.Nop; ins.Operand = null;
                    for (int k = 0; k < 4; k++) m.Body.Instructions.Insert(i + 1 + k, Instruction.Create(OpCodes.Nop));
                    patched++;
                    i += 4;
                }
            }
        }
        Console.WriteLine("[patchcalls] nop-ified " + patched + " call IGC sites (kept 2)");
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], opts);
        Console.WriteLine("[patchcalls] wrote " + a[1]);
    }
}
