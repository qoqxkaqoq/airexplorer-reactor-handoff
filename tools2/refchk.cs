// refchk.cs — 统计/修复 IL 里"指不到实体"的成员引用
//
// 根因线索: VerifyCombinedStateRequest 在磁盘上是
//   1e | 00 | 28 82 42 00 06 | 2a
//   即 nop; call <token 0x06420082>; ret
// 0x06420082 的 rid = 0x420082 = 4328578, 而整个程序集只有 22930 个方法 -> token 越界,
// CLR 编译该方法时解析不到目标, 抛 InvalidProgramException。
// 这是 nb_slayer 重建 IL 时写坏的引用, 需要按名字重新绑回本模块内的真实定义。
//
// 用法: refchk <in.exe> <out.exe> [--list N]
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class RefChk {
    static void Main(string[] a) {
        string inPath = a[0], outPath = a[1];
        bool list = a.Contains("--list");
        var mod = ModuleDefMD.Load(inPath);

        int badMethod = 0, badField = 0, fixedM = 0, fixedF = 0, methods = 0;
        var samples = new List<string>();

        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                methods++;
                foreach (var ins in m.Body.Instructions) {
                    var op = ins.Operand;

                    // --- 方法引用 ---
                    var im = op as IMethod;
                    if (im != null && !(im is MethodDef)) {
                        bool ok;
                        try { ok = im.ResolveMethodDef() != null; } catch { ok = false; }
                        if (!ok) {
                            badMethod++;
                            if (samples.Count < 25 && list)
                                samples.Add("  call bad: " + t.FullName + "::" + m.Name + " -> " + Safe(im));
                            // 按 声明类型名 + 方法名 + 签名 在本模块内找真实定义
                            var target = FindMethod(mod, im);
                            if (target != null) { ins.Operand = target; fixedM++; }
                        }
                    }

                    // --- 字段引用 ---
                    var fld = op as IField;
                    if (fld != null && !(fld is FieldDef)) {
                        bool ok;
                        try { ok = fld.ResolveFieldDef() != null; } catch { ok = false; }
                        if (!ok) {
                            badField++;
                            var target = FindField(mod, fld);
                            if (target != null) { ins.Operand = target; fixedF++; }
                        }
                    }
                }
            }
        }

        Console.WriteLine("[refchk] 有体方法 " + methods);
        Console.WriteLine("[refchk] 解析不到的方法引用 " + badMethod + " (已重绑 " + fixedM + ")");
        Console.WriteLine("[refchk] 解析不到的字段引用 " + badField + " (已重绑 " + fixedF + ")");
        foreach (var s in samples) Console.WriteLine(s);

        if (fixedM + fixedF == 0) { Console.WriteLine("[refchk] 无可修内容, 不写盘"); return; }
        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(outPath, wopt);
        Console.WriteLine("[refchk] 写出: " + outPath);
    }

    static string Safe(IMethod im) {
        try { return im.FullName; } catch { return "?"; }
    }

    static MethodDef FindMethod(ModuleDef mod, IMethod im) {
        if (im.DeclaringType == null) return null;
        string tn = im.DeclaringType.FullName.Replace('+', '/');
        string full = tn;
        var td = mod.Find(full, false) ?? mod.Find(tn, false);
        if (td == null) {
            // 退一步: 按类型短名匹配
            string shortName = tn.Contains('.') ? tn.Substring(tn.LastIndexOf('.') + 1) : tn;
            td = mod.GetTypes().FirstOrDefault(x => x.Name.String == shortName);
        }
        if (td == null) return null;
        string sig = im.MethodSig == null ? null : im.MethodSig.ToString();
        var m = td.Methods.FirstOrDefault(x => x.Name.String == im.Name.String &&
                                               (sig == null || (x.MethodSig != null && x.MethodSig.ToString() == sig)));
        return m ?? td.Methods.FirstOrDefault(x => x.Name.String == im.Name.String);
    }

    static FieldDef FindField(ModuleDef mod, IField f) {
        if (f.DeclaringType == null) return null;
        string tn = f.DeclaringType.FullName.Replace('+', '/');
        var td = mod.Find(tn, false);
        if (td == null) {
            string shortName = tn.Contains('.') ? tn.Substring(tn.LastIndexOf('.') + 1) : tn;
            td = mod.GetTypes().FirstOrDefault(x => x.Name.String == shortName);
        }
        if (td == null) return null;
        return td.Fields.FirstOrDefault(x => x.Name.String == f.Name.String);
    }
}
