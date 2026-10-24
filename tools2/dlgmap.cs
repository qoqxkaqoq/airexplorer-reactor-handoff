// dlgmap <in.exe> <map.tsv> <out.exe> — 按 MapScan dump 的官方绑定表(fieldTok→valTok)静态注入全部委托赋值
// val 格式: TrackCompiler 语义 — bit30(0x40000000)=实例目标(callvirt), 低30位=token(0x06 MethodDef / 0x0A MemberRef)
// 静态目标: ldnull; ldftn <m>; newobj <dlgctor>; stsfld <fld>  → 注入声明类型 cctor 开头
// 实例目标: 生成 trampoline 静态方法(复制官方 DynamicMethod 形态: ldargs→cast/unbox this→tail.callvirt→ret) 后同样绑定
// 注入位置: cctor 最前(先于 TrackCompiler — TrackCompiler 的 map 解密在 v132 线已断, 失败被静默吞)
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class DlgMap {
    static ModuleDefMD mod;
    static int nStatic = 0, nInst = 0, nSkip = 0;

    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: dlgmap <in> <map.tsv> <out>"); return; }
        mod = ModuleDefMD.Load(a[0]);
        var rows = System.IO.File.ReadAllLines(a[1]);
        // 先收集要注入的内容, 按声明类型分组
        var byType = new Dictionary<TypeDef, List<Injection>>();
        foreach (var ln in rows) {
            var p = ln.Split('|');
            if (p.Length < 3 || p[0] != "MAPENTRY") continue;
            uint fieldTok = Convert.ToUInt32(p[1], 16);
            uint val = Convert.ToUInt32(p[2], 16);
            bool inst = (val & 0x40000000) != 0;
            uint mtok = val & 0x3FFFFFFFu;
            var fd = mod.ResolveToken((int)fieldTok) as FieldDef;
            if (fd == null) { nSkip++; continue; }
            var dt = fd.DeclaringType;
            var cctor = dt.FindMethod(".cctor");
            if (cctor == null || !cctor.HasBody) { nSkip++; continue; }
            IMethod target = null;
            try { target = mod.ResolveToken((int)mtok) as IMethod; } catch { }
            if (target == null) { nSkip++; continue; }
            var dctor = dt.Methods.FirstOrDefault(m => m.Name == ".ctor" && m.MethodSig.Params.Count == 2);
            if (dctor == null) { nSkip++; continue; }

            IMethod bind;
            MethodDef tramp = null;
            if (!inst) {
                bind = target;
                nStatic++;
            } else {
                tramp = MakeTrampoline(dt, fd, target);
                if (tramp == null) { nSkip++; continue; }
                bind = tramp;
                nInst++;
            }
            if (!byType.TryGetValue(dt, out var list)) byType[dt] = list = new List<Injection>();
            list.Add(new Injection { Field = fd, Bind = bind, Dctor = dctor });
        }
        // 注入: 每类型 cctor 开头(逆序插入保持顺序)
        foreach (var kv in byType) {
            var body = kv.Key.FindMethod(".cctor").Body;
            var ins = kv.Value;
            for (int i = ins.Count - 1; i >= 0; i--) {
                var seq = new[] {
                    new Instruction(OpCodes.Ldnull),
                    new Instruction(OpCodes.Ldftn, mod.Import(ins[i].Bind)),
                    new Instruction(OpCodes.Newobj, mod.Import(ins[i].Dctor)),
                    new Instruction(OpCodes.Stsfld, mod.Import(ins[i].Field)),
                };
                for (int j = seq.Length - 1; j >= 0; j--) body.Instructions.Insert(0, seq[j]);
            }
            body.KeepOldMaxStack = false;
            body.MaxStack = (ushort)Math.Max((int)body.MaxStack, 4);
        }
        Console.WriteLine("[dlgmap] static=" + nStatic + " instance=" + nInst + " skipped=" + nSkip + " types=" + byType.Count);
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
        foreach (var t in mod.GetTypes()) foreach (var m in t.Methods) if (m.HasBody) m.Body.KeepOldMaxStack = true;
        mod.Write(a[2], opts);
        Console.WriteLine("[dlgmap] wrote " + a[2]);
    }

    class Injection { public FieldDef Field; public IMethod Bind; public MethodDef Dctor; }

    // 生成 trampoline: 签名复制委托 Invoke; 体: ldarg.0 → (cast/unbox 目标声明类型) → ldarg.1.. → tail. → call/callvirt target → ret
    static MethodDef MakeTrampoline(TypeDef dlgType, FieldDef fd, IMethod target) {
        var invoke = dlgType.Methods.FirstOrDefault(m => m.Name == "Invoke");
        if (invoke == null || invoke.MethodSig == null) return null;
        var tSig = target.MethodSig;
        if (tSig == null) return null;
        var decl = target.DeclaringType;
        if (decl == null) return null;

        var tramp = new MethodDefUser(
            "DlgTramp_" + fd.MDToken.Raw.ToString("X8"),
            MethodSig.CreateStatic(invoke.MethodSig.RetType, invoke.MethodSig.Params.ToArray()),
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig);
        tramp.Body = new CilBody();

        var il = tramp.Body.Instructions;
        il.Add(new Instruction(OpCodes.Ldarg_0));
        var p0 = invoke.MethodSig.Params.Count > 0 ? invoke.MethodSig.Params[0] : null;
        var declSig = decl.ToTypeSig();
        bool isVal = decl.IsValueType;
        if (isVal) {
            il.Add(new Instruction(OpCodes.Unbox_Any, mod.Import(decl)));
        } else if (p0 != null && p0.FullName != declSig.FullName) {
            il.Add(new Instruction(OpCodes.Castclass, mod.Import(decl)));
        }
        for (int i = 1; i < invoke.MethodSig.Params.Count; i++) {
            if (i == 1) il.Add(new Instruction(OpCodes.Ldarg_1));
            else if (i == 2) il.Add(new Instruction(OpCodes.Ldarg_2));
            else if (i == 3) il.Add(new Instruction(OpCodes.Ldarg_3));
            else il.Add(new Instruction(OpCodes.Ldarg_S, tramp.Parameters[i]));
        }
        il.Add(new Instruction(OpCodes.Tailcall));
        il.Add(new Instruction(tSig.HasThis ? OpCodes.Callvirt : OpCodes.Call, mod.Import(target)));
        il.Add(new Instruction(OpCodes.Ret));
        tramp.Body.MaxStack = (ushort)(invoke.MethodSig.Params.Count + 2);
        dlgType.Methods.Add(tramp);
        return tramp;
    }
}
