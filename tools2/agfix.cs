using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// agfix <in.exe> <snapshot.txt> <out.exe> <agCctorTokenHex>
// AG.cctor 手术三件套:
//  1) 开头插快照恢复: AG.* STR→ldstr+stsfld / INT→ldc+stsfld / B64→FromBase64String+stsfld
//  2) 体内解密块 NOP 化: call WriteRequest → ... → stloc (含) 整段 NOP, stloc 前补 ldc.i4.0
//  3) 校验段拆除: ldsfld ArrangeAggregator → nop; call ExecuteExplorer → pop+ldc.i4.0
class AgFix {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var ag = mod.Find("AirExplorer.Values.ArgumentGateway", false);
        if (ag == null) { Console.WriteLine("[agfix] AG type not found"); return; }
        var cctor = ag.FindMethod(".cctor");
        if (cctor == null || !cctor.HasBody) { Console.WriteLine("[agfix] cctor null"); return; }

        // 1) 收集快照 AG 字段值
        var agVals = new List<KeyValuePair<FieldDef, string[]>>(); // field, snap行
        var flds = new Dictionary<string, FieldDef>();
        foreach (var f in ag.Fields) if (f.IsStatic) flds[f.Name.String] = f;
        foreach (var ln in File.ReadAllLines(a[1])) {
            var sp = ln.Split(' ');
            if (sp.Length < 2 || !sp[1].StartsWith("AG.")) continue;
            var fname = sp[1].Substring(3);
            FieldDef f;
            if (!flds.TryGetValue(fname, out f)) continue;
            agVals.Add(new KeyValuePair<FieldDef, string[]>(f, sp));
        }
        Console.WriteLine("[agfix] snapshot AG fields=" + agVals.Count);

        var ins = new List<Instruction>();
        int nStr = 0, nInt = 0, nB64 = 0;
        foreach (var kv in agVals) {
            var f = kv.Key; var sp = kv.Value;
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
                long v;
                if (sp[2] == "True") ins.Add(new Instruction(OpCodes.Ldc_I4_1));
                else if (sp[2] == "False") ins.Add(new Instruction(OpCodes.Ldc_I4_0));
                else if (!long.TryParse(sp[2], out v)) continue;
                else ins.Add(new Instruction(OpCodes.Ldc_I4, (int)v));
                ins.Add(new Instruction(OpCodes.Stsfld, f));
                nInt++;
            }
        }
        // 插到 cctor 开头
        var il = cctor.Body.Instructions;
        for (int k = ins.Count - 1; k >= 0; k--) il.Insert(0, ins[k]);
        Console.WriteLine("[agfix] inserted STR=" + nStr + " B64=" + nB64 + " INT=" + nInt + " at cctor head");

        // 2) 解密块 NOP 化: call WriteRequest → 首个 stloc(含), stloc 前补 ldc.i4.0
        //    (跳过已替换块: 区间内不能有 ldstr/stsfld)
        int nBlock = 0;
        for (int i = 0; i < il.Count; i++) {
            if (il[i].OpCode.Code != Code.Call) continue;
            var im = il[i].Operand as IMethod;
            if (im == null || im.Name != "WriteRequest") continue;
            int j = i + 1, end = -1;
            for (; j < il.Count && j < i + 40; j++) {
                var c = il[j].OpCode.Code;
                if (c == Code.Stloc || c == Code.Stloc_S || c == Code.Stloc_0 || c == Code.Stloc_1 || c == Code.Stloc_2 || c == Code.Stloc_3) { end = j; break; }
                // 控制流出块即失败(ITP/PatchList 等 call 全部属于块)
                if (c == Code.Ret || c == Code.Br || c == Code.Br_S || c == Code.Brtrue || c == Code.Brtrue_S || c == Code.Brfalse || c == Code.Brfalse_S || c == Code.Switch) break;
            }
            if (end < 0) { Console.WriteLine("[agfix] block @" + il[i].Offset.ToString("X4") + " no stloc end, skipped"); continue; }
            // 区间 NOP 化(不含 stloc)
            for (int k2 = i; k2 < end; k2++) il[k2].OpCode = OpCodes.Nop;
            il.Insert(end, new Instruction(OpCodes.Ldc_I4_0));
            nBlock++;
            i = end;
        }
        Console.WriteLine("[agfix] decrypt blocks noped=" + nBlock);

        // 3) 校验段拆除: ldsfld ArrangeAggregator → nop; 其后 call ExecuteExplorer → pop+ldc.i4.0
        int nCheck = 0;
        for (int i = 0; i < il.Count; i++) {
            if (il[i].OpCode.Code != Code.Ldsfld) continue;
            var fld = il[i].Operand as IField;
            if (fld == null || fld.FullName == null || !fld.FullName.Contains("ArrangeAggregator")) continue;
            il[i].OpCode = OpCodes.Nop;
            // 找下一个 call ExecuteExplorer
            for (int j = i + 1; j < il.Count && j < i + 6; j++) {
                if (il[j].OpCode.Code == Code.Call && il[j].Operand is IMethod m2 && m2.Name == "ExecuteExplorer") {
                    il[j].OpCode = OpCodes.Pop;
                    il.Insert(j + 1, new Instruction(OpCodes.Ldc_I4_0));
                    nCheck++;
                    break;
                }
            }
        }
        Console.WriteLine("[agfix] checker segments removed=" + nCheck);

        // 4) 同样手术应用到 AG 其他方法? 暂只做 cctor。
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll;
        mod.Write(a[2], opts);
        Console.WriteLine("[agfix] wrote " + a[2]);
    }
}
