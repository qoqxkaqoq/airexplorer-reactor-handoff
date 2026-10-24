using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// agfix <in.exe> <snapshot.txt> <out.exe>
// ArgumentGateway 手术:
//  1) AG.cctor 开头插快照恢复: AG.* STR→ldstr+stsfld / INT→ldc+stsfld / B64→FromBase64String+stsfld
//  2) AG 全方法: call WriteRequest → 首个 stloc(含) 整段 NOP, stloc 前补 ldc.i4.0 (解密块拆除)
//  3) AG 全方法: ldsfld ArrangeAggregator → nop; call ExecuteExplorer → pop+ldc.i4.0 (校验段拆除)
class AgFix {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var ag = mod.Find("AirExplorer.Values.ArgumentGateway", false);
        if (ag == null) { Console.WriteLine("[agfix] AG type not found"); return; }

        // 1) 快照恢复插 cctor 开头
        var cctor = ag.FindMethod(".cctor");
        var flds = new Dictionary<string, FieldDef>();
        foreach (var f in ag.Fields) if (f.IsStatic) flds[f.Name.String] = f;
        var ins = new List<Instruction>();
        int nStr = 0, nInt = 0, nB64 = 0;
        foreach (var ln in File.ReadAllLines(a[1])) {
            var sp = ln.Split(' ');
            if (sp.Length < 2 || !sp[1].StartsWith("AG.")) continue;
            var fname = sp[1].Substring(3);
            if (!flds.TryGetValue(fname, out var f)) continue;
            f.Attributes = (f.Attributes & ~FieldAttributes.FieldAccessMask) | FieldAttributes.Public;
            if (sp[0] == "STR" && sp.Length >= 3) {
                ins.Add(new Instruction(OpCodes.Ldstr, Encoding.UTF8.GetString(Convert.FromBase64String(sp[2]))));
                ins.Add(new Instruction(OpCodes.Stsfld, f));
                nStr++;
            } else if (sp[0] == "B64" && sp.Length >= 3) {
                ins.Add(new Instruction(OpCodes.Ldstr, sp[2]));
                ins.Add(new Instruction(OpCodes.Call, new MemberRefUser(mod, "FromBase64String",
                    MethodSig.CreateStatic(new SZArraySig(mod.CorLibTypes.Byte), mod.CorLibTypes.String),
                    new TypeRefUser(mod, "System", "Convert", mod.CorLibTypes.AssemblyRef))));
                ins.Add(new Instruction(OpCodes.Stsfld, f));
                nB64++;
            } else if (sp[0] == "INT" && sp.Length >= 3) {
                if (sp[2] == "True") ins.Add(new Instruction(OpCodes.Ldc_I4_1));
                else if (sp[2] == "False") ins.Add(new Instruction(OpCodes.Ldc_I4_0));
                else if (!long.TryParse(sp[2], out var v)) continue;
                else ins.Add(new Instruction(OpCodes.Ldc_I4, (int)v));
                ins.Add(new Instruction(OpCodes.Stsfld, f));
                nInt++;
            }
        }
        if (cctor != null && cctor.HasBody && ins.Count > 0) {
            var il = cctor.Body.Instructions;
            for (int k = ins.Count - 1; k >= 0; k--) il.Insert(0, ins[k]);
        }
        Console.WriteLine("[agfix] inserted STR=" + nStr + " B64=" + nB64 + " INT=" + nInt + " at cctor head");

        // 2)+3) 全方法手术
        int nBlock = 0, nCheck = 0;
        foreach (var mm in ag.Methods) {
            if (!mm.HasBody) continue;
            nBlock += FixBlocks(mm.Body);
            nCheck += FixCheckers(mm.Body);
        }
        Console.WriteLine("[agfix] decrypt blocks noped=" + nBlock + " checker segments removed=" + nCheck);

        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(a[2], opts);
        Console.WriteLine("[agfix] wrote " + a[2]);
    }

    // call WriteRequest → 首个 stloc(含) 整段 NOP, stloc 前补类型匹配的默认值
    static int FixBlocks(CilBody body) {
        var il = body.Instructions;
        int n = 0;
        for (int i = 0; i < il.Count; i++) {
            if (il[i].OpCode.Code != Code.Call) continue;
            var im = il[i].Operand as IMethod;
            if (im == null || im.Name != "WriteRequest") continue;
            int j = i + 1, end = -1;
            for (; j < il.Count && j < i + 40; j++) {
                var c = il[j].OpCode.Code;
                if (c == Code.Stloc || c == Code.Stloc_S || c == Code.Stloc_0 || c == Code.Stloc_1 || c == Code.Stloc_2 || c == Code.Stloc_3) { end = j; break; }
                if (c == Code.Ret || c == Code.Br || c == Code.Br_S || c == Code.Brtrue || c == Code.Brtrue_S || c == Code.Brfalse || c == Code.Brfalse_S || c == Code.Switch) break;
            }
            if (end < 0) continue;
            for (int k = i; k < end; k++) il[k].OpCode = OpCodes.Nop;
            // stloc.0-3 无 Local 操作数 — 按 opcode 推导局部索引
            Local loc = il[end].Operand as Local;
            if (loc == null) {
                int idx = il[end].OpCode.Code == Code.Stloc_0 ? 0 : il[end].OpCode.Code == Code.Stloc_1 ? 1 : il[end].OpCode.Code == Code.Stloc_2 ? 2 : il[end].OpCode.Code == Code.Stloc_3 ? 3 : -1;
                if (idx >= 0 && idx < body.Variables.Count) loc = body.Variables[idx];
            }
            var lt = loc != null ? loc.Type : null;
            var et = lt != null ? lt.GetElementType() : ElementType.Object;
            foreach (var ins in DefaultFor(lt, et, loc)) il.Insert(end++, ins);
            n++;
            i = end;
        }
        return n;
    }
    // 按局部类型生成栈类型匹配的默认值指令序列
    static IEnumerable<Instruction> DefaultFor(TypeSig lt, ElementType et, Local loc) {
        if (lt == null) { yield return new Instruction(OpCodes.Ldc_I4_0); yield break; }
        switch (et) {
            case ElementType.I4: case ElementType.U4: case ElementType.I1: case ElementType.U1:
            case ElementType.I2: case ElementType.U2: case ElementType.Boolean: case ElementType.Char:
                yield return new Instruction(OpCodes.Ldc_I4_0); yield break;
            case ElementType.I8: case ElementType.U8:
                yield return new Instruction(OpCodes.Ldc_I8) { Operand = 0L }; yield break; // 修复: 不能用 ldc.i4.0 冒充 I8
            case ElementType.R4:
                yield return new Instruction(OpCodes.Ldc_R4) { Operand = 0f }; yield break;
            case ElementType.R8:
                yield return new Instruction(OpCodes.Ldc_R8) { Operand = 0d }; yield break;
            case ElementType.I: case ElementType.U:
                yield return new Instruction(OpCodes.Ldc_I4_0); yield return new Instruction(OpCodes.Conv_I); yield break;
        }
        bool isRef = et == ElementType.Object || et == ElementType.String || et == ElementType.Class || et == ElementType.SZArray || et == ElementType.Array
                  || et == ElementType.ByRef || et == ElementType.Ptr || et == ElementType.FnPtr || et == ElementType.GenericInst && lt.ToTypeDefOrRef() is TypeSpec;
        // 类/数组/接口 → ldnull; 其余(值类型/泛型值类型) → ldloca+initobj+ldloc
        if (isRef) yield return new Instruction(OpCodes.Ldnull);
        else if (loc != null) {
            yield return new Instruction(OpCodes.Ldloca) { Operand = loc };
            yield return new Instruction(OpCodes.Initobj) { Operand = lt.ToTypeDefOrRef() };
            yield return new Instruction(OpCodes.Ldloc) { Operand = loc };
        } else yield return new Instruction(OpCodes.Ldnull);
    }

    // ldsfld ArrangeAggregator → nop; 其后 call ExecuteExplorer → pop+ldc.i4.0
    static int FixCheckers(CilBody body) {
        var il = body.Instructions;
        int n = 0;
        for (int i = 0; i < il.Count; i++) {
            if (il[i].OpCode.Code != Code.Ldsfld) continue;
            var fld = il[i].Operand as IField;
            if (fld == null || fld.FullName == null || !fld.FullName.Contains("ArrangeAggregator")) continue;
            il[i].OpCode = OpCodes.Nop;
            for (int j = i + 1; j < il.Count && j < i + 6; j++) {
                if (il[j].OpCode.Code == Code.Call && il[j].Operand is IMethod m2 && m2.Name == "ExecuteExplorer") {
                    il[j].OpCode = OpCodes.Pop;
                    il.Insert(j + 1, new Instruction(OpCodes.Ldc_I4_0));
                    n++;
                    break;
                }
            }
        }
        return n;
    }
}
