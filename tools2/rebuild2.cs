using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// rebuild2: 用 dnlib 重写整个模块, 把 398KB 字符串表作为 FieldRVA 静态数组嵌入,
// 并把 SearchStrategy 换成 RuntimeHelpers.InitializeArray 一行赋值。
//
// 与 injectstr 的区别: 后者只改 MethodDef.RVA 列(字节级), 复用现成 MemberRef token,
// 结果 Windows CLR 报 "Bad class token" —— 说明那些 MemberRef 是孤儿行, 签名不可解析。
// 这里让 dnlib 重新生成全套 token / PE 布局, 代码自然落在 .text 里。
//
// 用法: rebuild2 <in.exe> <out.exe> <blob.bin> [typeName] [methodName] [--noop]
class Rebuild2 {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: rebuild2 <in.exe> <out.exe> <blob.bin> [type] [method] [--noop]"); return; }
        string inPath = a[0], outPath = a[1], blobPath = a[2];
        string typeName = a.Length > 3 && !a[3].StartsWith("--") ? a[3] : "CloudClient.Templating.DispatcherInitializer";
        string methName = a.Length > 4 && !a[4].StartsWith("--") ? a[4] : "SearchStrategy";
        bool noop = a.Any(x => x == "--noop");

        var blob = File.ReadAllBytes(blobPath);
        var mod = ModuleDefMD.Load(inPath);
        Console.WriteLine("[in] " + inPath + "  types=" + mod.GetTypes().Count() + "  blob=" + blob.Length);

        if (!noop) {
            var t = mod.Find(typeName, false);
            if (t == null) { Console.WriteLine("[err] type not found"); return; }
            var m = t.Methods.FirstOrDefault(x => x.Name == methName);
            var fExt = t.Fields.FirstOrDefault(x => x.Name == "_ExtractorVisitors");
            if (m == null || fExt == null) { Console.WriteLine("[err] method/field not found"); return; }

            // 1) 建 <PrivateImplementationDetails> + __StaticArrayInitTypeSize=N + 字段
            var pimpl = mod.Types.FirstOrDefault(x => x.Name == "<PrivateImplementationDetails>");
            if (pimpl == null) {
                pimpl = new TypeDefUser("<PrivateImplementationDetails>", mod.CorLibTypes.Object.TypeDefOrRef);
                pimpl.Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed | TypeAttributes.AnsiClass | TypeAttributes.ExplicitLayout;
                mod.Types.Add(pimpl);
                Console.WriteLine("[type] 新建 <PrivateImplementationDetails>");
            } else Console.WriteLine("[type] 复用 <PrivateImplementationDetails>  fields=" + pimpl.Fields.Count);

            var vt = new TypeDefUser("__StaticArrayInitTypeSize=" + blob.Length, mod.CorLibTypes.GetTypeRef("System", "ValueType"));
            vt.Attributes = TypeAttributes.NestedPublic | TypeAttributes.Sealed | TypeAttributes.AnsiClass | TypeAttributes.ExplicitLayout;
            vt.ClassLayout = new ClassLayoutUser(1, (uint)blob.Length);
            pimpl.NestedTypes.Add(vt);

            var fld = new FieldDefUser("__strtab", new FieldSig(vt.ToTypeSig()),
                FieldAttributes.Static | FieldAttributes.Assembly | FieldAttributes.HasFieldRVA);
            fld.InitialValue = blob;
            pimpl.Fields.Add(fld);
            Console.WriteLine("[field] " + pimpl.Name + "::__strtab  rva=" + fld.RVA.ToString("X"));

            // 2) 复用现成 token, 避免 Import 引入错误 scope
            ITypeDefOrRef byteType = null;
            try { byteType = mod.ResolveToken(0x0100005Bu) as ITypeDefOrRef; } catch { }
            if (byteType == null) byteType = mod.CorLibTypes.Byte.ToTypeDefOrRef();
            IMethod initArray = null;
            try { initArray = mod.ResolveToken(0x0A000998u) as IMethod; } catch { }
            Console.WriteLine("[tok] byte=" + (byteType == null ? "null" : byteType.FullName) + "  InitializeArray=" + (initArray == null ? "null" : initArray.FullName));
            if (initArray == null) { Console.WriteLine("[err] InitializeArray token 不可解析"); return; }

            // 3) 新 body
            var body = new CilBody();
            body.MaxStack = 3;
            body.InitLocals = false;
            body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, blob.Length));
            body.Instructions.Add(Instruction.Create(OpCodes.Newarr, byteType));
            body.Instructions.Add(Instruction.Create(OpCodes.Dup));
            body.Instructions.Add(Instruction.Create(OpCodes.Ldtoken, fld));
            body.Instructions.Add(Instruction.Create(OpCodes.Call, initArray));
            body.Instructions.Add(Instruction.Create(OpCodes.Stsfld, fExt));
            body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            m.Body = body;
            Console.WriteLine("[body] " + typeName + "::" + methName + "  -> 7 insn");
        }

        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        opts.Logger = DummyLogger.ThrowModuleWriterExceptionOnErrorInstance;
        mod.Write(outPath, opts);
        Console.WriteLine("[out] " + outPath + " size=" + new FileInfo(outPath).Length);
    }
}
