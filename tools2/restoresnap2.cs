using System;
using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// restoresnap2 <in.exe> <snapshot.txt> <out.exe>
// v116: 恢复代码插 r6cf451d0d(0600459C) 开头 — 自建容器 + 恢复 <Module>{} 实例字段 + DI.*/TA.* 静态字段
// (先于 InstantiateAccessibleProcessor 的 IGC 状态依赖)
class RestoreSnap2 {
    static ModuleDef mod;
    static Dictionary<long, string> strMap = new Dictionary<long, string>(); // base64 明文字段

    static void Main(string[] a) {
        mod = ModuleDefMD.Load(a[0]);
        var snap = File.ReadAllLines(a[1]);
        var gmt = FindType("<Module>{a8c2e9b2");
        var di = mod.Find("CloudClient.Templating.DispatcherInitializer", false);
        var ta = mod.Find("CloudClient.Templating.TemplateArgument", false);
        var initM = mod.ResolveToken(0x0600459Cu) as MethodDef;   // r6cf451d0d
        if (gmt == null || initM == null) { Console.WriteLine("type null"); return; }

        FieldDef cont = null;
        foreach (var f in gmt.Fields) if (f.IsStatic) { cont = f; break; }
        var instFlds = new Dictionary<string, FieldDef>();
        foreach (var f in gmt.Fields) if (!f.IsStatic) instFlds[f.Name.String] = f;
        var diFlds = new Dictionary<string, FieldDef>();
        foreach (var f in di.Fields) if (f.IsStatic) diFlds[f.Name.String] = f;
        var taFlds = new Dictionary<string, FieldDef>();
        if (ta != null) foreach (var f in ta.Fields) if (f.IsStatic) taFlds[f.Name.String] = f;

        var il = initM.Body.Instructions;
        var ins = new List<Instruction>();
        // 1) 自建容器(若 r6cf451d0d 不自行 new, 提前建好)
        var ctor = gmt.FindMethod(".ctor");
        if (ctor != null) {
            ins.Add(new Instruction(OpCodes.Newobj, ctor));
            ins.Add(new Instruction(OpCodes.Stsfld, cont));
        }
        int nInst = 0, nDi = 0, nTa = 0;
        foreach (var ln in snap) {
            var sp = ln.Split(' ');
            if (sp.Length < 2) continue;
            var tag = sp[1];
            if (tag.Contains(".m_") && tag.StartsWith("<Module>{")) {
                // <Module>{} 实例字段
                var fname = tag.Substring(tag.LastIndexOf('.') + 1);
                if (!instFlds.TryGetValue(fname, out var f)) continue;
                if (sp[0] == "INT" && sp.Length >= 3 && long.TryParse(sp[2], out var v)) {
                    ins.Add(new Instruction(OpCodes.Ldsfld, cont));
                    ins.Add(new Instruction(OpCodes.Ldc_I4, (int)v));
                    ins.Add(new Instruction(OpCodes.Stfld, f));
                    nInst++;
                }
            } else if (tag.StartsWith("DI.")) {
                var fname = tag.Substring(3);
                if (!diFlds.TryGetValue(fname, out var f)) continue;
                f.Attributes = (f.Attributes & ~FieldAttributes.FieldAccessMask) | FieldAttributes.Public;
                EmitStatic(ins, sp, f, ref nDi);
            } else if (tag.StartsWith("TA.")) {
                var fname = tag.Substring(3);
                if (!taFlds.TryGetValue(fname, out var f)) continue;
                f.Attributes = (f.Attributes & ~FieldAttributes.FieldAccessMask) | FieldAttributes.Public;
                EmitStatic(ins, sp, f, ref nTa);
            }
        }
        // 插到方法开头
        for (int k = ins.Count - 1; k >= 0; k--) il.Insert(0, ins[k]);
        Console.WriteLine("[restore2] inst=" + nInst + " DI=" + nDi + " TA=" + nTa + " → r6cf451d0d now " + il.Count + " instrs");
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
        mod.Write(a[2], opts);
        Console.WriteLine("[restore2] wrote " + a[2]);
    }

    static void EmitStatic(List<Instruction> ins, string[] sp, FieldDef f, ref int n) {
        if (sp[0] == "INT" && sp.Length >= 3 && long.TryParse(sp[2], out var v)) {
            ins.Add(new Instruction(OpCodes.Ldc_I4, (int)v));
            ins.Add(new Instruction(OpCodes.Stsfld, f));
            n++;
        } else if (sp[0] == "B64" && sp.Length >= 3) {
            ins.Add(new Instruction(OpCodes.Ldstr, sp[2]));
            ins.Add(new Instruction(OpCodes.Call, MR("System", "Convert", "FromBase64String",
                MethodSig.CreateStatic(new SZArraySig(mod.CorLibTypes.Byte), mod.CorLibTypes.String))));
            ins.Add(new Instruction(OpCodes.Stsfld, f));
            n++;
        } else if (sp[0] == "STR" && sp.Length >= 3) {
            ins.Add(new Instruction(OpCodes.Ldstr, sp[2]));
            ins.Add(new Instruction(OpCodes.Call, MR("System", "Convert", "FromBase64String",
                MethodSig.CreateStatic(new SZArraySig(mod.CorLibTypes.Byte), mod.CorLibTypes.String))));
            var encRef = new TypeRefUser(mod, "System.Text", "Encoding", mod.CorLibTypes.AssemblyRef);
            ins.Add(new Instruction(OpCodes.Call, new MemberRefUser(mod, "get_UTF8",
                MethodSig.CreateStatic(new ClassSig(encRef)), encRef)));
            ins.Add(new Instruction(OpCodes.Callvirt, new MemberRefUser(mod, "GetString",
                MethodSig.CreateInstance(mod.CorLibTypes.String, new SZArraySig(mod.CorLibTypes.Byte)), encRef)));
            ins.Add(new Instruction(OpCodes.Stsfld, f));
            n++;
        }
    }

    static MemberRef MR(string ns, string cls, string name, MethodSig sig) {
        return new MemberRefUser(mod, name, sig, new TypeRefUser(mod, ns, cls, mod.CorLibTypes.AssemblyRef));
    }
    static TypeDef FindType(string n) {
        foreach (var t in mod.GetTypes()) if (t.FullName.Contains(n)) return t;
        return null;
    }
}
