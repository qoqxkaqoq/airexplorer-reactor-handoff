using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// restub: 把指定方法体重置成 "ldnull; ret" (返回引用类型) 或 "ret"
// 用途: 批量移植时误把泛型方法 (InstantiateStatelessUser) 也搬过来, 跨模块签名不兼容 -> 回桩
// 用法: restub <in> <out> <Type> <Method> [--void]
class ReStub {
    static void Main(string[] a) {
        if (a.Length < 4) { Console.WriteLine("usage: restub <in> <out> <Type> <Method> [--void]"); return; }
        var mod = ModuleDefMD.Load(a[0]);
        var t = mod.Find(a[2], false);
        if (t == null) { Console.WriteLine("[err] type not found"); return; }
        var m = t.Methods.FirstOrDefault(x => x.Name == a[3]);
        if (m == null) { Console.WriteLine("[err] method not found"); return; }
        bool voidRet = a.Any(x => x == "--void");
        var body = new CilBody();
        body.MaxStack = 8;
        if (!voidRet) body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
        body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        m.Body = body;
        Console.WriteLine("[restub] " + a[2] + "::" + a[3] + "  -> " + (voidRet ? "ret" : "ldnull;ret"));
        var wopt = new ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], wopt);
        Console.WriteLine("[out] " + a[1]);
    }
}
