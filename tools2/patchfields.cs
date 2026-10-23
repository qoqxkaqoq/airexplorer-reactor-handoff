using System;
using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// patchfields <in.exe> <fv.txt> <out.exe> — r6cf451d0d 尾部插入字段值恢复代码
// (官方运行时的 <Module>{a8c2e9b2} 实例字段值 → v113 里直接写回, 修 IGC 哈希长度)
class PatchFields {
    static void Main(string[] a) {
        var fv = new Dictionary<string, long>();
        foreach (var ln in File.ReadAllLines(a[1])) {
            int eq = ln.IndexOf('=');
            if (eq <= 0) continue;
            var k = ln.Substring(0, eq); var v = ln.Substring(eq + 1);
            long n; if (k.StartsWith("m_") && long.TryParse(v, out n)) fv[k] = n;
        }
        Console.WriteLine("[patchfields] fields=" + fv.Count);

        var mod = ModuleDefMD.Load(a[0]);
        TypeDef gmt = null;
        foreach (var tt in mod.GetTypes()) if (tt.FullName.Contains("<Module>{a8c2e9b2")) { gmt = tt; break; }
        if (gmt == null) { Console.WriteLine("global type not found"); return; }
        var initM = mod.ResolveToken(0x0600459Cu) as MethodDef;   // r6cf451d0d
        if (initM == null || !initM.HasBody) { Console.WriteLine("init method null"); return; }

        // 字段引用表
        var fldMap = new Dictionary<string, FieldDef>();
        foreach (var f in gmt.Fields) fldMap[f.Name.String] = f;
        var contRef = gmt.Fields[0]; // m_0d0b145be2 静态字段(引用容器)
        foreach (var f in gmt.Fields) if (f.IsStatic) { contRef = f; break; }
        Console.WriteLine("[patchfields] container static field = " + contRef.Name);

        var il = initM.Body.Instructions;
        var ins = new List<Instruction>();
        int added = 0;
        foreach (var kv in fv) {
            if (!fldMap.TryGetValue(kv.Key, out var f)) continue;
            if (f.IsStatic) continue; // 只填实例字段
            ins.Add(new Instruction(OpCodes.Ldsfld, contRef));
            ins.Add(new Instruction(OpCodes.Ldc_I4, (int)kv.Value));
            ins.Add(new Instruction(OpCodes.Stfld, f));
            added++;
        }
        // 插到 ret 前(最后一条 ret)
        int retIdx = il.Count - 1;
        while (retIdx >= 0 && il[retIdx].OpCode.Code != Code.Ret) retIdx--;
        if (retIdx < 0) retIdx = il.Count;
        for (int k = 0; k < ins.Count; k++) il.Insert(retIdx + k, ins[k]);
        Console.WriteLine("[patchfields] inserted " + added + " field stores before ret @" + il[retIdx].Offset);

        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[2], opts);
        Console.WriteLine("[patchfields] wrote " + a[2]);
    }
}
