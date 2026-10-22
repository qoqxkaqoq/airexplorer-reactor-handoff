// merge.cs — 把 src 中的"真体"批量覆盖到 dst 上
//
// 背景: 本样本有两个互补产物
//   e8runnable : 99% 方法体是 nop/nop/nop/ret 空桩, 但"初始化链"方法(DefineEfficientProfiler 等)
//                保存着**未被反篡改污染**的真体 (stloc V_72 有几百处)
//   nb_original: 全部业务方法体都在, 但初始化链被反篡改改写成陷阱 (stloc V_72 -> stloc V_104)
// 本工具把 src 里所有"非桩且指令数达标"的方法体移植到 dst 的同名方法上。
// 桩(≤4 指令且全是 nop/ret)一律跳过, 防止用空桩覆盖掉 dst 已有的好体。
//
// 用法: merge <src> <dst> <out> [minIl=10]
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class Merge {
    static ModuleDef curDst;
    static Importer importer;

    static void Main(string[] a) {
        string srcPath = a[0], dstPath = a[1], outPath = a[2];
        int minIl = a.Length > 3 ? int.Parse(a[3]) : 10;
        var srcMod = ModuleDefMD.Load(srcPath);
        var dstMod = ModuleDefMD.Load(dstPath);
        curDst = dstMod;
        importer = new Importer(dstMod);

        int n = 0, skippedStub = 0, skippedSame = 0, notFound = 0, failed = 0;

        foreach (var st in srcMod.GetTypes()) {
            string tf = st.FullName;
            foreach (var sm in st.Methods) {
                if (!sm.HasBody) continue;
                int il = sm.Body.Instructions.Count;
                if (il < minIl) { skippedStub++; continue; }
                if (IsStub(sm)) { skippedStub++; continue; }

                var dt = FindType(dstMod, tf);
                if (dt == null) { notFound++; continue; }
                var dm = dt.Methods.FirstOrDefault(x => x.Name.String == sm.Name.String &&
                                                        x.MethodSig != null && sm.MethodSig != null &&
                                                        x.MethodSig.ToString() == sm.MethodSig.ToString());
                if (dm == null) { notFound++; continue; }
                if (dm.HasBody && SameBody(dm, sm)) { skippedSame++; continue; }

                try {
                    TransplantBody(dm, sm);
                    RebindRefs(dm, dstMod);
                    n++;
                    Console.WriteLine("[merge] " + tf + "::" + sm.Name + "  " +
                        (dm.HasBody ? il + " 指令" : "") + "  (原 " + (PrevIl) + " 指令)");
                } catch (Exception ex) {
                    failed++;
                    Console.WriteLine("[merge] 失败 " + sm.Name + ": " + ex.Message);
                }
            }
        }

        Console.WriteLine();
        Console.WriteLine("[merge] 移植 " + n + " / 跳过桩 " + skippedStub + " / 内容相同 " + skippedSame +
                          " / dst 无此成员 " + notFound + " / 失败 " + failed);
        if (n == 0) { Console.WriteLine("[merge] 无可写内容, 不产出文件"); return; }

        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(dstMod);
        wopt.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        dstMod.Write(outPath, wopt);
        Console.WriteLine("[merge] 写出: " + outPath);
    }

    static int PrevIl;

    static bool IsStub(MethodDef m) {
        var ops = m.Body.Instructions.Select(x => x.OpCode.Code).ToList();
        if (ops.Count <= 4 && ops.All(c => c == Code.Nop || c == Code.Ret)) return true;
        if (ops.SequenceEqual(new[] { Code.Ldnull, Code.Ret })) return true;
        if (ops.SequenceEqual(new[] { Code.Ldc_I4_0, Code.Ret })) return true;
        return false;
    }

    static bool SameBody(MethodDef d, MethodDef s) {
        if (d.Body.Instructions.Count != s.Body.Instructions.Count) return false;
        for (int i = 0; i < d.Body.Instructions.Count; i++) {
            var x = d.Body.Instructions[i]; var y = s.Body.Instructions[i];
            if (x.OpCode != y.OpCode) return false;
            var xo = x.Operand == null ? "" : x.Operand.ToString();
            var yo = y.Operand == null ? "" : y.Operand.ToString();
            if (xo != yo) return false;
        }
        return true;
    }

    static TypeDef FindType(ModuleDef mod, string full) {
        // 返回类型本身供链式调用; 实际签名兼容用名字查找
        foreach (var t in mod.GetTypes())
            if (t.FullName == full) return t;
        return null;
    }

    static void TransplantBody(MethodDef dst, MethodDef src) {
        PrevIl = dst.HasBody ? dst.Body.Instructions.Count : 0;
        var sb = src.Body;
        var body = new CilBody();
        body.InitLocals = sb.InitLocals;
        body.KeepOldMaxStack = true;
        body.MaxStack = sb.MaxStack;
        if (sb.Instructions.Count > 60 && sb.MaxStack < 128) body.MaxStack = 512;

        var localMap = new Dictionary<Local, Local>();
        foreach (var l in sb.Variables) {
            var nl = new Local(importer.Import(l.Type));
            body.Variables.Add(nl);
            localMap[l] = nl;
        }
        var instrMap = new Dictionary<Instruction, Instruction>();
        foreach (var i in sb.Instructions) {
            var ni = new Instruction(i.OpCode);
            instrMap[i] = ni;
            body.Instructions.Add(ni);
        }
        foreach (var i in sb.Instructions) {
            var ni = instrMap[i];
            var op = i.Operand;
            if (op == null) continue;
            if (op is Instruction t) ni.Operand = instrMap[t];
            else if (op is Instruction[] ts) {
                var arr = new Instruction[ts.Length];
                for (int k = 0; k < ts.Length; k++) arr[k] = instrMap[ts[k]];
                ni.Operand = arr;
            } else if (op is Local l2) ni.Operand = localMap[l2];
            else if (op is ITypeDefOrRef tdr) ni.Operand = importer.Import(tdr);
            else if (op is IMethod im) ni.Operand = ImportSmart(im);
            else if (op is IField fi) ni.Operand = ImportSmart(fi);
            else if (op is TypeSig sig) ni.Operand = importer.Import(sig);
            else ni.Operand = op;
        }
        foreach (var eh in sb.ExceptionHandlers) {
            var neh = new ExceptionHandler(eh.HandlerType);
            if (eh.TryStart != null) neh.TryStart = instrMap[eh.TryStart];
            if (eh.TryEnd != null) neh.TryEnd = instrMap[eh.TryEnd];
            if (eh.HandlerStart != null) neh.HandlerStart = instrMap[eh.HandlerStart];
            if (eh.HandlerEnd != null) neh.HandlerEnd = instrMap[eh.HandlerEnd];
            if (eh.FilterStart != null) neh.FilterStart = instrMap[eh.FilterStart];
            if (eh.CatchType != null) neh.CatchType = importer.Import(eh.CatchType);
            body.ExceptionHandlers.Add(neh);
        }
        dst.Body = body;
    }

    // 全局方法(<Module> 上的方法)在导入时容易丢,单独处理
    static object ImportSmart(object op) {
        var im = op as IMethod;
        if (im != null) {
            var md = im.ResolveMethodDef();
            bool isGlobal = md != null && md.DeclaringType != null && md.DeclaringType.IsGlobalModuleType;
            bool looksGlobal = im.DeclaringType != null && !UTF8String.IsNullOrEmpty(im.DeclaringType.Name) &&
                               im.DeclaringType.Name.String.StartsWith("<Module>");
            if (isGlobal || looksGlobal) {
                var gt = curDst.GlobalType;
                if (gt != null) {
                    var fm = gt.Methods.FirstOrDefault(x => x.Name.String == im.Name.String);
                    if (fm != null) return fm;
                }
            }
            return importer.Import(im);
        }
        var fi = op as IField;
        if (fi != null) return importer.Import(fi);
        return op;
    }

    // 把移植后仍指向无法解析的 TypeRef 的 MemberRef 改绑到 dst 里同名同签名的成员
    static void RebindRefs(MethodDef dstM, ModuleDef dstMod) {
        int nfix = 0;
        foreach (var ins in dstM.Body.Instructions) {
            if (ins.Operand is MemberRef mr && mr.MethodSig != null) {
                bool bad;
                try { bad = mr.ResolveMethodDef() == null && mr.Class is TypeRef; } catch { bad = mr.Class is TypeRef; }
                if (!bad) continue;
                var tr = (TypeRef)mr.Class;
                var dstT = dstMod.Find(tr.FullName.Replace('+', '/'), false);
                if (dstT == null) continue;
                string rsig = mr.MethodSig.ToString();
                var target = dstT.Methods.FirstOrDefault(x => x.Name.String == mr.Name.String &&
                                                              x.MethodSig != null && x.MethodSig.ToString() == rsig);
                if (target != null) { ins.Operand = target; nfix++; }
                else ins.Operand = new MemberRefUser(dstMod, mr.Name, mr.MethodSig, dstT);
                nfix++;
            } else if (ins.Operand is MemberRef fr && fr.FieldSig != null) {
                bool bad;
                try { bad = fr.ResolveFieldDef() == null && fr.Class is TypeRef; } catch { bad = fr.Class is TypeRef; }
                if (!bad) continue;
                var tr = (TypeRef)fr.Class;
                var dstT = dstMod.Find(tr.FullName.Replace('+', '/'), false);
                if (dstT == null) continue;
                var target = dstT.Fields.FirstOrDefault(x => x.Name.String == fr.Name.String);
                if (target != null) { ins.Operand = target; nfix++; }
            }
        }
        if (nfix > 0) Console.WriteLine("        (重绑定 " + nfix + " 处引用)");
    }
}
