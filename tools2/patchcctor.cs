using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// 通用补丁器: 在带 AssemblyResolver 的情况下加载, 避免 "operand is null"
//   patchcctor <in.exe> <out.exe> cctor
//   patchcctor <in.exe> <out.exe> strings <mapping.tsv>
class Patch {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: patchcctor <in> <out> <cctor|strings> [mapping]"); return; }
        var dir = Path.GetDirectoryName(Path.GetFullPath(a[0]));
        var res = new AssemblyResolver { EnableTypeDefCache = true };
        res.PostSearchPaths.Insert(0, dir);
        res.PreSearchPaths.Insert(0, dir);
        var ctx = new ModuleContext(res);
        res.DefaultModuleContext = ctx;
        var mod = ModuleDefMD.Load(a[0], ctx);
        Console.WriteLine("[patch] loaded " + mod.Assembly.FullName + "  asmRefs=" + mod.GetAssemblyRefs().Count());

        int changed = 0;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions)
                    if (ins.Operand == null && ins.OpCode.OperandType != OperandType.InlineNone) {
                        if (changed < 5) Console.WriteLine("[null-operand] " + t.FullName + "::" + m.Name + "  " + ins);
                        changed++;
                    }
            }
        Console.WriteLine("[patch] null operands = " + changed);

        // Reactor 把 "call null" 当成占位符塞在方法体开头, 且总被前面的 br.s 跳过(死代码)。
        // dnlib 写盘时会因为操作数为 null 直接抛 ModuleWriterException, 所以要替换成 nop。
        int fixedNull = 0;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                for (int i = 0; i < ins.Count; i++)
                    if (ins[i].Operand == null && (ins[i].OpCode.Code == Code.Call || ins[i].OpCode.Code == Code.Callvirt)) {
                        ins[i].OpCode = OpCodes.Nop;
                        fixedNull++;
                    }
            }
        Console.WriteLine("[patch] call-null -> nop : " + fixedNull);

        string mode = a[2];
        if (mode == "cctor") {
            int n = 0;
            foreach (var t in mod.GetTypes())
                foreach (var m in t.Methods)
                    if (m.Name == ".cctor" && m.HasBody && t.Name.String.StartsWith("<Module")) {
                        m.Body = new CilBody();
                        m.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                        n++;
                        Console.WriteLine("[patch] cleared " + t.FullName + "::.cctor");
                    }
            Console.WriteLine("[patch] cctors cleared = " + n);
        }

        var wopt = new ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags = MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], wopt);
        Console.WriteLine("[patch] wrote " + a[1] + "  size=" + new FileInfo(a[1]).Length);
    }
}
