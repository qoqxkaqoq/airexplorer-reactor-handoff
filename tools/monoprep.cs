// monoprep — 为 Mono/Linux 侧执行测试准备副本: 剥离自定义特性(避免缺失 WPF 程序集导致加载失败) + 可选方法桩替换
// 用法: monoprep <in> <out> [stub:TypeFull::Method ...]
using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class MonoPrep {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        int ca = 0;
        foreach (var t in mod.GetTypes()) {
            ca += t.CustomAttributes.Count; t.CustomAttributes.Clear();
            foreach (var f in t.Fields) { ca += f.CustomAttributes.Count; f.CustomAttributes.Clear(); }
            foreach (var m in t.Methods) {
                ca += m.CustomAttributes.Count; m.CustomAttributes.Clear();
                foreach (var p in m.ParamDefs) { ca += p.CustomAttributes.Count; p.CustomAttributes.Clear(); }
                foreach (var gp in m.GenericParameters) { ca += gp.CustomAttributes.Count; gp.CustomAttributes.Clear(); }
            }
            foreach (var p in t.Properties) { ca += p.CustomAttributes.Count; p.CustomAttributes.Clear(); }
            foreach (var e in t.Events) { ca += e.CustomAttributes.Count; e.CustomAttributes.Clear(); }
        }
        if (mod.Assembly != null) { ca += mod.Assembly.CustomAttributes.Count; mod.Assembly.CustomAttributes.Clear(); }
        ca += mod.CustomAttributes.Count; mod.CustomAttributes.Clear();
        Console.WriteLine("[monoprep] stripped CAs = " + ca);

        for (int i = 2; i < a.Length; i++) {
            var spec = a[i];
            if (!spec.StartsWith("stub:")) continue;
            var parts = spec.Substring(5).Split(new[] { "::" }, StringSplitOptions.None);
            var t = mod.Find(parts[0], false);
            if (t == null) { Console.WriteLine("[monoprep] type not found " + parts[0]); continue; }
            var m = t.FindMethod(parts[1]);
            if (m == null) { Console.WriteLine("[monoprep] method not found " + spec); continue; }
            var body = new CilBody();
            body.MaxStack = 1;
            var rt = m.ReturnType;
            string rtName = rt == null ? "System.Void" : rt.FullName;
            if (rtName == "System.Boolean") body.Instructions.Add(Instruction.CreateLdcI4(1));
            else if (rtName == "System.Int32" || rtName == "System.UInt32" || rtName == "System.Int64" ||
                     rtName == "System.UInt64" || rtName == "System.IntPtr" || rtName == "System.Byte" ||
                     rtName == "System.Int16" || rtName == "System.SByte" || rtName == "System.UInt16")
                body.Instructions.Add(Instruction.CreateLdcI4(0));
            else if (rtName != "System.Void") body.Instructions.Add(new Instruction(OpCodes.Ldnull));
            body.Instructions.Add(new Instruction(OpCodes.Ret));
            m.Body = body;
            Console.WriteLine("[monoprep] stubbed " + spec);
        }

        var opts = new ModuleWriterOptions(mod);
        opts.Logger = DummyLogger.NoThrowInstance;
        mod.Write(a[1], opts);
        Console.WriteLine("[monoprep] wrote " + a[1]);
        return 0;
    }
}
