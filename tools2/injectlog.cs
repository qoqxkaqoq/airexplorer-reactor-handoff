using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// injectlog <in.exe> <out.exe>
// 在 06002985(AdvancedClient.ctor)/06002BD6(MergeManager)/06002995(SplitSynchronizer)/
//    06002BD1(InitializerReg.ctor)/06002BCE(ValidateDynamicEncryptor) 方法开头注入日志:
//   File.AppendAllText("C:\\out\\ctor_log.txt", "TAG|" + Environment.StackTrace + "\n")
// 约束: 只复用模块既有 MemberRef / 新建 mscorlib 4.0 同版本引用(禁止跨运行时 Import)
class InjectLog {
    static ModuleDefMD mod;
    static void Main(string[] a) {
        mod = ModuleDefMD.Load(a[0]);
        var logFile = "C:\\out\\ctor_log.txt";

        // 需要 MemberRef: System.IO.File::AppendAllText(string,string) / System.Environment::get_StackTrace / String::Concat(string,string)
        var mscorlib = mod.GetAssemblyRefs().First(x => x.Name == "mscorlib");
        var fileRef = new TypeRefUser(mod, "System.IO", "File", mscorlib);
        var envRef  = new TypeRefUser(mod, "System", "Environment", mscorlib);
        var sigAppend = MethodSig.CreateStatic(mod.CorLibTypes.Void,
            mod.CorLibTypes.String, mod.CorLibTypes.String);
        var mAppend = new MemberRefUser(mod, "AppendAllText", sigAppend, fileRef);
        var sigGS = MethodSig.CreateStatic(mod.CorLibTypes.String);
        var mStack = new MemberRefUser(mod, "get_StackTrace", sigGS, envRef);
        // String::Concat(string,string) — 找既有
        IMethod mConcat = null;
        foreach (var mr in mod.GetMemberRefs())
            if (mr.IsMethodRef && mr.Name == "Concat" && mr.Class != null && mr.Class.FullName == "System.String") {
                var ms = mr.MethodSig;
                if (ms != null && ms.Params.Count == 2 && ms.Params[0].FullName == "System.String") { mConcat = mr; break; }
            }
        if (mConcat == null) throw new Exception("String::Concat(str,str) MemberRef not found");

        var targets = new[] {
            new[] { "06002985", "CTOR" },
            new[] { "06002BD6", "MERGE" },
            new[] { "06002995", "SPLIT" },
            new[] { "06002BD1", "INITREG" },
            new[] { "06002BCE", "VDYN" },
        };
        int swapped = 0;
        foreach (var t in targets) {
            var tok = uint.Parse(t[0], System.Globalization.NumberStyles.HexNumber);
            var m = mod.ResolveToken(0x06000000u | tok) as MethodDef;
            if (m == null || !m.HasBody) { Console.WriteLine("[injectlog] skip " + t[0]); continue; }
            var il = m.Body.Instructions;
            var first = il[0];
            var ins = new List<Instruction> {
                Instruction.Create(OpCodes.Ldstr, "TAG" + t[1] + "|"),
                Instruction.Create(OpCodes.Call, mStack),
                Instruction.Create(OpCodes.Call, mConcat),
                Instruction.Create(OpCodes.Ldstr, logFile),
                Instruction.Create(OpCodes.Call, mAppend),
            };
            // 日志调用插到最前, 原第一条跟在后面
            for (int i = ins.Count - 1; i >= 0; i--) il.Insert(0, ins[i]);
            // 修正: 插入后 ins[0]..ins[4] 在最前, 原first跟在 ins[4] 后 — 无需再处理
            swapped++;
            Console.WriteLine("[injectlog] " + t[0] + " " + m.FullName.Split(' ').Last() + " TAG=" + t[1]);
        }
        Console.WriteLine("[injectlog] swapped=" + swapped);
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
        opts.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], opts);
        Console.WriteLine("[out] " + a[1]);
    }
}
