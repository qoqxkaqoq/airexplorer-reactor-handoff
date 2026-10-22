// stubm.cs — 把指定方法替换成最小桩(用于隔离 InvalidProgramException / Bad IL range 的源头)
// 用法: stubm <in.exe> <out.exe> <TypeFullName>::<MethodName> [...]
using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class StubM {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        int n = 0;
        for (int i = 2; i < a.Length; i++) {
            string spec = a[i];
            int sep = spec.LastIndexOf("::", StringComparison.Ordinal);
            if (sep < 0) { Console.WriteLine("[stub] 规格写法应为 Type::Method -> " + spec); continue; }
            string tn = spec.Substring(0, sep), mn = spec.Substring(sep + 2);
            var t = mod.Find(tn, false);
            if (t == null) { Console.WriteLine("[stub] 未找到类型 " + tn); continue; }
            foreach (var m in t.Methods.Where(x => x.Name.String == mn)) {
                var body = new CilBody();
                var rt = m.MethodSig == null ? null : m.MethodSig.RetType;
                if (rt == null || rt.FullName == "System.Void") {
                    body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                } else if (rt.IsPrimitive || (rt.IsValueType && rt.FullName != "System.Decimal")) {
                    body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
                    if (rt.FullName == "System.Int64" || rt.FullName == "System.UInt64")
                        body.Instructions.Add(Instruction.Create(OpCodes.Conv_I8));
                    if (rt.FullName == "System.Single") body.Instructions.Add(Instruction.Create(OpCodes.Conv_R4));
                    if (rt.FullName == "System.Double") body.Instructions.Add(Instruction.Create(OpCodes.Conv_R8));
                    body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                } else {
                    body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
                    body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                }
                body.MaxStack = 2;
                m.Body = body;
                n++;
                Console.WriteLine("[stub] " + tn + "::" + mn + " -> 桩(返回 " + (rt == null ? "void" : rt.FullName) + ")");
            }
        }
        if (n == 0) { Console.WriteLine("[stub] 没有可替换的目标"); return; }
        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        // PreserveAll 很关键: dnlib 默认写入会重排元数据行号(RID), 而 Reactor 的
            // VM/解密 blob 里存的是**原始** token, 运行时靠 ResolveMethod/ResolveField 解析。
            // 一旦重排, 就会解析到错误成员并触发 anti-tamper 异常(AutoReaktor v3 记的头号坑)。
            wopt.MetadataOptions.Flags = dnlib.DotNet.Writer.MetadataFlags.PreserveAll
                                       | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], wopt);
        Console.WriteLine("[stub] 写出: " + a[1] + " (" + n + " 个方法)");
    }
}
