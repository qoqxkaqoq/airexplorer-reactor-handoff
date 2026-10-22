// cctorfix.cs — 委托三连（ldsfld 静态字段 + ldftn 实例方法 + newobj 委托ctor）诊断与修复
// 模式: cctorfix8 <exe> dump <类名子串>   — 输出该类字段/cctor/ctor 完整 IL
//       cctorfix8 <exe> scan             — 全局扫描三连, 报告 target 静态字段初始化缺口
//       cctorfix8 <exe> fix <输出.exe>   — 修复: 委托target字段无初始化时, 在其类cctor补 newobj+stsfld;
//                                          .ctor 桩替换为标准真体; 保留其他内容
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class CctorFix {
    static bool IsDelegateCtor(IMethod im) {
        var n = im.FullName;
        return n.Contains("Comparison") || n.Contains("Predicate") || n.Contains("Func`1")
            || n.Contains("Func`2") || n.Contains("Func`3") || n.Contains("Func`4")
            || n.Contains("Action`1") || n.Contains("Action`2") || n.Contains("EventHandler");
    }
    static bool IsCtorStub(MethodDef m) {
        if (m == null || !m.HasBody) return true;
        var il = m.Body.Instructions;
        // 桩特征: <=4 条且没有 call object::.ctor
        bool hasBase = il.Any(x => x.OpCode.Code == Code.Call && x.Operand is IMethod c
            && c.DeclaringType != null && c.DeclaringType.FullName == "System.Object" && c.Name == ".ctor");
        return il.Count <= 4 && !hasBase;
    }
    static bool IsCctorStub(MethodDef m) {
        if (m == null || !m.HasBody) return true;
        return m.Body.Instructions.Count <= 2;
    }

    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string mode = a.Length > 1 ? a[1] : "scan";

        if (mode == "dump") {
            string key = a[2];
            foreach (var t in mod.GetTypes()) {
                if (!t.FullName.Contains(key)) continue;
                Console.WriteLine("== 类 " + t.FullName + "  字段数=" + t.Fields.Count);
                foreach (var f in t.Fields)
                    Console.WriteLine("  字段 " + f.Name + " : " + f.FieldType.FullName + (f.IsStatic ? " [static]" : ""));
                foreach (var m in t.Methods) {
                    if (m.Name != ".ctor" && m.Name != ".cctor") continue;
                    Console.WriteLine("  -- " + m.Name + " (" + (m.HasBody ? m.Body.Instructions.Count.ToString() : "无体") + " 指令)");
                    if (m.HasBody)
                        foreach (var ins in m.Body.Instructions)
                            Console.WriteLine("     " + ins.OpCode + " " + OpStr(ins.Operand));
                }
            }
            return 0;
        }

        else if (mode == "fldref") {
            // fldref <字段名子串> [写|读]
            string needle = a[2]; bool writes = a.Length > 3;
            foreach (var t in mod.GetTypes()) {
                foreach (var m in t.Methods) {
                    if (!m.HasBody) continue;
                    foreach (var ins in m.Body.Instructions) {
                        if (ins.Operand is IField f && f.Name.String.Contains(needle)) {
                            bool isWrite = ins.OpCode.Code == Code.Stfld || ins.OpCode.Code == Code.Stsfld;
                            if (writes && !isWrite) continue;
                            var fr = f.ResolveFieldDef();
                            Console.WriteLine((isWrite ? "[写]" : "[读]") + " " + t.FullName + "::" + m.Name
                                + " IL_" + ins.Offset.ToString("X4") + " -> " + fr.DeclaringType.FullName + "::" + fr.Name
                                + "  本方法指令数=" + m.Body.Instructions.Count);
                        }
                    }
                }
            }
            return 0;
        }
        else if (mode == "meth") {
            foreach (var t in mod.GetTypes()) {
                if (!t.FullName.Contains(a[2])) continue;
                foreach (var m in t.Methods) {
                    if (m.Name.String != a[3]) continue;
                    Console.WriteLine("===== " + t.FullName + "::" + m.Name + " =====");
                    if (!m.HasBody) continue;
                    foreach (var ins in m.Body.Instructions)
                        Console.WriteLine("  IL_" + ins.Offset.ToString("X4") + ": " + ins.OpCode + " " + (ins.Operand == null ? "" : OpStr(ins.Operand)));
                }
            }
            return 0;
        }
        bool doFix = mode == "fix";
        int tri = 0, broken = 0, fixedCtor = 0, fixedCctor = 0;
        var patched = new HashSet<string>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var il = m.Body.Instructions;
                for (int i = 0; i + 2 < il.Count; i++) {
                    if (il[i].OpCode.Code != Code.Ldsfld) continue;
                    if (il[i + 1].OpCode.Code != Code.Ldftn) continue;
                    if (il[i + 2].OpCode.Code != Code.Newobj) continue;
                    var dc = il[i + 2].Operand as IMethod;
                    if (dc == null || !IsDelegateCtor(dc)) continue;
                    var fldTok = il[i].Operand as IField;
                    if (fldTok == null) continue;
                    var fld = fldTok.ResolveFieldDef();
                    if (fld == null || !fld.IsStatic) continue;
                    tri++;
                    var tgt = fld.DeclaringType.ResolveTypeDef();
                    if (tgt == null) continue;

                    // 该字段在 tgt 的任何方法里有没有 stsfld？
                    bool inited = tgt.Methods.Any(mm => mm.HasBody && mm.Body.Instructions
                        .Any(x => x.OpCode.Code == Code.Stsfld && (x.Operand as IField)?.ResolveFieldDef() == fld));
                    var cctor = tgt.FindStaticConstructor();
                    var ictor = tgt.FindDefaultConstructor();
                    bool ctorStub = IsCtorStub(ictor);
                    bool cctorMissingOrStub = cctor == null || IsCctorStub(cctor);
                    if (inited && !ctorStub) continue;
                    broken++;
                    Console.WriteLine("[缺初始化] " + t.FullName + "::" + m.Name + " IL_" + il[i].Offset.ToString("X4")
                        + "  字段=" + tgt.FullName + "::" + fld.Name
                        + "  stsfld=" + inited + " cctor=" + (cctor == null ? "无" : (IsCctorStub(cctor) ? "桩" : "有体")) + " ctor=" + (ctorStub ? "桩" : "真体"));
                    if (!doFix) continue;

                    // 修复1: .ctor 桩 -> 标准真体 ldarg.0; call object::.ctor(); ret
                    if (ctorStub && ictor != null) {
                        ictor.Body = new CilBody();
                        ictor.Body.Instructions.Add(new Instruction(OpCodes.Ldarg_0));
                        ictor.Body.Instructions.Add(OpCodes.Call.ToInstruction(mod.CorLibTypes.Object.TypeDef.FindMethod(".ctor") ?? FindObjectCtor(mod)));
                        ictor.Body.Instructions.Add(new Instruction(OpCodes.Ret));
                        ictor.Body.MaxStack = 1;
                        fixedCtor++;
                        patched.Add(tgt.FullName);
                    }
                    // 修复2: 字段无 stsfld -> cctor 补 newobj fld.DeclaringType + stsfld fld
                    if (!inited) {
                        if (cctor == null) {
                            cctor = new MethodDefUser(".cctor", MethodSig.CreateStatic(mod.CorLibTypes.Void),
                                MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);
                            cctor.Body = new CilBody();
                            tgt.Methods.Add(cctor);
                        }
                        if (IsCctorStub(cctor)) {
                            cctor.Body = new CilBody();
                            cctor.Body.Instructions.Add(OpCodes.Newobj.ToInstruction(ictor));
                        }
                        // 去掉已有的对同一字段的重复 stsfld（保险）
                        cctor.Body.Instructions.Add(OpCodes.Dup.ToInstruction());
                        cctor.Body.Instructions.Add(new Instruction(OpCodes.Stsfld, fld));
                        cctor.Body.Instructions.Add(new Instruction(OpCodes.Ret));
                        cctor.Body.MaxStack = 2;
                        fixedCctor++;
                        patched.Add(tgt.FullName);
                    }
                }
            }
        Console.WriteLine("[scan] 三连=" + tri + " 缺初始化=" + broken + " 修ctor=" + fixedCtor + " 补cctor=" + fixedCctor);
        if (doFix) {
            var opts = new ModuleWriterOptions(mod);
            opts.Logger = DummyLogger.NoThrowInstance;
            mod.Write(a[2], opts);
            Console.WriteLine("[fix] 已写出 " + a[2]);
        }
        return 0;
    }
    static IMethod FindObjectCtor(ModuleDef mod) {
        var obj = mod.CorLibTypes.Object.TypeDef;
        return obj?.FindDefaultConstructor();
    }
    static string OpStr(object op) {
        if (op is IField f) { var fr = f.ResolveFieldDef(); return f.DeclaringType.FullName + "::" + f.Name + " : " + (fr != null ? fr.FieldType.FullName : "?"); }
        if (op is IMethod mm) return mm.FullName;
        return op == null ? "" : op.ToString();
    }
}
