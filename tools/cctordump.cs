// cctordump.cs — 完整输出指定类型 .cctor/.ctor/全部方法的 IL（不截断操作数）+ 全局扫描
// "ldsfld displayClass + ldftn + newobj 委托ctor" 模式中委托 target 静态字段的初始化状态
// 用法: cctordump8 <exe> <TypeName可子串>   （无类型名=全局扫描模式）
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class CctorDump {
    static void FullIL(MethodDef m) {
        Console.WriteLine("===== " + m.FullName + " (" + (m.HasBody ? m.Body.Instructions.Count.ToString() : "无体") + " 指令) =====");
        if (!m.HasBody) return;
        foreach (var ins in m.Body.Instructions)
            Console.WriteLine("  IL_" + ins.Offset.ToString("X4") + ": " + ins.OpCode + " " + (ins.Operand == null ? "" : OpStr(ins.Operand)));
    }
    static string OpStr(object op) {
        if (op is IField f) { var fr = f.ResolveFieldDef(); return f.DeclaringType.FullName + "::" + f.Name + " : " + (fr != null ? fr.FieldType.FullName : "?"); }
        if (op is IMethod mm) return mm.FullName;
        return op.ToString();
    }
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        if (a.Length > 1) {
            foreach (var t in mod.GetTypes())
                if (t.FullName.Contains(a[1]))
                    foreach (var m in t.Methods)
                        if (m.Name == ".cctor" || m.Name == ".ctor" || (a.Length > 2 && m.Name == a[2]))
                            FullIL(m);
            return 0;
        }
        // 全局扫描: newobj 委托 .ctor(Object, IntPtr) 的 IL 三连 ldsfld F + ldftn + newobj
        // 检查 F 与 <targetClass>::<>9 的初始化（cctor 是否含 stsfld）
        int found = 0, broken = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var il = m.Body.Instructions;
                for (int i = 0; i + 2 < il.Count; i++) {
                    if (il[i].OpCode.Code != Code.Ldsfld) continue;
                    if (il[i+1].OpCode.Code != Code.Ldftn) continue;
                    if (il[i+2].OpCode.Code != Code.Newobj) continue;
                    var ctor = il[i+2].Operand as IMethod;
                    var dt = ctor?.MethodSig;
                    if (ctor == null || ctor.Name != ".ctor" || dt == null || dt.Params.Count != 2) continue;
                    if (!ctor.DeclaringType.FullName.Contains("Comparison") && !ctor.DeclaringType.FullName.Contains("Predicate")
                        && !ctor.DeclaringType.FullName.Contains("Func") && !ctor.DeclaringType.FullName.Contains("Action")
                        && !ctor.DeclaringType.FullName.Contains("Converter") && !ctor.DeclaringType.FullName.Contains("EventHandler")) continue;
                    var fld = il[i].Operand as IField;
                    if (fld == null) continue;
                    found++;
                    // target 字段声明类型
                    var tgtClass = fld.DeclaringType.ResolveTypeDef();
                    if (tgtClass == null) continue;
                    // 是否存在 stsfld 该类的静态字段（任意 cctor 内）？
                    bool initialized = false, hasCctor = false, cctorStub = false;
                    var cctor = tgtClass.FindStaticConstructor();
                    if (cctor != null) {
                        hasCctor = true;
                        cctorStub = !cctor.HasBody || cctor.Body.Instructions.Count <= 1
                            || (cctor.Body.Instructions.Count <= 4 && !cctor.Body.Instructions.Any(x => x.OpCode.Code == Code.Newobj));
                        foreach (var tm in tgtClass.Methods)
                            if (tm.HasBody)
                                foreach (var ins in tm.Body.Instructions)
                                    if (ins.OpCode.Code == Code.Stsfld && ins.Operand is IField sf
                                        && (sf.ResolveFieldDef()?.IsStatic ?? false))
                                        initialized = true;
