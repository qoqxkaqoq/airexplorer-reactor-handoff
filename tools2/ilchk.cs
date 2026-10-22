// ilchk.cs — 找 "Bad IL range" 的出处: 跳转/switch 目标越界、EH 范围越界或空 handler
// 用法: ilchk <file.exe> [--fix <out.exe>]
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class IlChk {
    static void Main(string[] a) {
        string file = a[0];
        string outPath = null;
        for (int i = 1; i < a.Length - 1; i++)
            if (a[i] == "--fix") outPath = a[i + 1];
        var mod = ModuleDefMD.Load(file);

        var bad = new List<MethodDef>();
        int nEh = 0, nBr = 0, nSw = 0;

        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var body = m.Body;
                var instrs = body.Instructions;
                if (instrs.Count == 0) continue;
                var offs = new HashSet<uint>(instrs.Select(x => x.Offset));
                bool badHere = false;

                // 1) 跳转 / switch 目标必须落在本方法的某条指令上
                foreach (var ins in instrs) {
                    if (ins.Operand is Instruction tgt) {
                        if (!offs.Contains(tgt.Offset)) { badHere = true; nBr++; break; }
                    } else if (ins.Operand is Instruction[] tgts) {
                        foreach (var tg in tgts)
                            if (!offs.Contains(tg.Offset)) { badHere = true; nSw++; break; }
                        if (badHere) break;
                    }
                }

                // 2) EH 范围: 起止指令必须都在本方法里, 且 handler 不能为空
                if (!badHere) {
                    foreach (var eh in body.ExceptionHandlers) {
                        bool b = false;
                        if (eh.TryStart != null && !offs.Contains(eh.TryStart.Offset)) b = true;
                        if (eh.TryEnd != null && !offs.Contains(eh.TryEnd.Offset)) b = true;
                        if (eh.HandlerStart != null && !offs.Contains(eh.HandlerStart.Offset)) b = true;
                        if (eh.HandlerEnd != null && !offs.Contains(eh.HandlerEnd.Offset)) b = true;
                        if (eh.FilterStart != null && !offs.Contains(eh.FilterStart.Offset)) b = true;
                        if (eh.HandlerStart == null || eh.HandlerEnd == null) b = true;
                        if (b) { badHere = true; nEh++; break; }
                    }
                }

                if (badHere) {
                    bad.Add(m);
                    if (bad.Count <= 20)
                        Console.WriteLine("[bad] " + t.FullName + "::" + m.Name + "  il=" + instrs.Count +
                                          " EH=" + body.ExceptionHandlers.Count);
                }
            }
        }

        Console.WriteLine("[ilchk] 越界跳转 " + nBr + " / switch 目标越界 " + nSw + " / EH 范围问题 " + nEh +
                          "  -> 坏方法 " + bad.Count + " 个");

        if (outPath == null || bad.Count == 0) return;
        // 修不掉就退化成桩: 至少让它别再把整个进程拖成 BadImageFormatException
        foreach (var m in bad) {
            var body = new CilBody();
            var rt = m.MethodSig == null ? null : m.MethodSig.RetType;
            if (rt == null || rt.FullName == "System.Void") {
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            } else if (rt.IsValueType || rt.IsPrimitive) {
                body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            } else {
                body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            }
            body.MaxStack = 2;
            body.ExceptionHandlers.Clear();
            m.Body = body;
        }
        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, wopt);
        Console.WriteLine("[ilchk] 已桩化 " + bad.Count + " 个坏方法 -> " + outPath);
    }
}
