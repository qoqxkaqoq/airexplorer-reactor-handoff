using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// AirExplorerCmd 的字符串还原工具(两段式, 因为解密器只能在运行时跑):
//   cmdstr sites <in.exe> <sites.txt>
//       解析每个 call SetupReporter(int) 调用点: 记录 方法token / 指令序号 / 常量表达式 / 密钥字段名
//   cmdstr apply <in.exe> <sites.txt> <decoded.tsv> <out.exe>
//       把 "常量表达式 + ldsfld holder; ldfld key; xor; call" 整段替换成 ldstr 明文
class CmdStr {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: cmdstr sites|apply ..."); return; }
        if (a[0] == "sites") Sites(a[1], a[2]);
        else if (a[0] == "apply") Apply(a[1], a[2], a[3], a[4]);
    }

    // ---------- 第一阶段 ----------
    static void Sites(string inExe, string outTxt) {
        var mod = Load(inExe);
        var lines = new List<string>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                for (int i = 0; i < ins.Count; i++) {
                    if (ins[i].OpCode.Code != Code.Call) continue;
                    if (!(ins[i].Operand is IMethod im) || im.Name != "SetupReporter") continue;

                    // 往回找最近的 ldsfld(密钥持有者)
                    int j = i - 1;
                    while (j >= 0 && !(ins[j].OpCode.Code == Code.Ldsfld)) j--;
                    if (j < 1) { Console.WriteLine("[skip] no ldsfld before " + m.Name + " IL_" + ins[i].Offset.ToString("X4")); continue; }
                    var holderFld = (IField)ins[j].Operand;
                    // ldsfld 后面应当是 ldfld(实例 int 字段)
                    string keyFld = "";
                    int exprEnd = j;
                    if (j + 1 < i && ins[j + 1].OpCode.Code == Code.Ldfld && ins[j + 1].Operand is IField kf) {
                        keyFld = kf.Name.String;
                        exprEnd = j;                       // 表达式在 ldsfld 之前
                    } else {
                        Console.WriteLine("[warn] unexpected after ldsfld: " + ins[j + 1].OpCode);
                    }

                    // 往前收常量表达式
                    int k = exprEnd - 1;
                    var ops = new List<Instruction>();
                    while (k >= 0) {
                        var c = ins[k].OpCode.Code;
                        if (c == Code.Ldc_I4 || c == Code.Ldc_I4_S || c == Code.Ldc_I4_0 || c == Code.Ldc_I4_1 ||
                            c == Code.Ldc_I4_2 || c == Code.Ldc_I4_3 || c == Code.Ldc_I4_4 || c == Code.Ldc_I4_5 ||
                            c == Code.Ldc_I4_6 || c == Code.Ldc_I4_7 || c == Code.Ldc_I4_8 || c == Code.Ldc_I4_M1 ||
                            c == Code.Add || c == Code.Xor || c == Code.Sub) {
                            ops.Insert(0, ins[k]); k--;
                        } else break;
                    }
                    var expr = Eval(ops);
                    lines.Add(string.Join("\t", m.MDToken.Rid.ToString(), i.ToString(), expr.ToString(), keyFld, holderFld.Name.String));
                }
            }
        File.WriteAllLines(outTxt, lines);
        Console.WriteLine("[sites] " + lines.Count + " call sites -> " + outTxt);
    }

    static int Eval(List<Instruction> ops) {
        var st = new Stack<int>();
        foreach (var o in ops) {
            var c = o.OpCode.Code;
            if (c == Code.Add) { var b = st.Pop(); var x = st.Pop(); st.Push(unchecked(x + b)); }
            else if (c == Code.Sub) { var b = st.Pop(); var x = st.Pop(); st.Push(unchecked(x - b)); }
            else if (c == Code.Xor) { var b = st.Pop(); var x = st.Pop(); st.Push(x ^ b); }
            else st.Push(o.GetLdcI4Value());
        }
        return st.Count == 1 ? st.Pop() : 0;
    }

    // ---------- 第二阶段 ----------
    static void Apply(string inExe, string sitesTxt, string decodedTsv, string outExe) {
        var map = new Dictionary<string, string>();   // "rid|idx" -> plaintext
        foreach (var line in File.ReadAllLines(decodedTsv)) {
            var p = line.Split('\t');
            if (p.Length < 3) continue;
            if (p[0] != "S") continue;
            var txt = Encoding.UTF8.GetString(Convert.FromBase64String(p[3]));
            map[p[1] + "|" + p[2]] = txt;
        }
        Console.WriteLine("[apply] decoded entries = " + map.Count);

        var mod = Load(inExe);
        int patched = 0, missing = 0;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                var rid = m.MDToken.Rid.ToString();
                for (int i = ins.Count - 1; i >= 0; i--) {
                    if (ins[i].OpCode.Code != Code.Call) continue;
                    if (!(ins[i].Operand is IMethod im) || im.Name != "SetupReporter") continue;
                    string key = rid + "|" + i;
                    if (!map.TryGetValue(key, out string text)) { missing++; continue; }

                    int j = i - 1;
                    while (j >= 0 && ins[j].OpCode.Code != Code.Ldsfld) j--;
                    int k = j - 1;
                    while (k >= 0 && IsIntOp(ins[k].OpCode.Code)) k--;
                    int start = k + 1;
                    // 用 ldstr 替换 [start, i]
                    for (int x = i; x >= start; x--) ins.RemoveAt(x);
                    ins.Insert(start, OpCodes.Ldstr.ToInstruction(text));
                    patched++;
                }
            }
        Console.WriteLine("[apply] patched = " + patched + "  missing = " + missing);
        var wopt = new ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags = MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(outExe, wopt);
        Console.WriteLine("[apply] wrote " + outExe);
    }

    static bool IsIntOp(Code c) {
        return c == Code.Ldc_I4 || c == Code.Ldc_I4_S || c == Code.Add || c == Code.Xor || c == Code.Sub ||
               (c >= Code.Ldc_I4_0 && c <= Code.Ldc_I4_8) || c == Code.Ldc_I4_M1;
    }

    static ModuleDef Load(string path) {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        var res = new AssemblyResolver { EnableTypeDefCache = true };
        res.PostSearchPaths.Insert(0, dir);
        res.PreSearchPaths.Insert(0, dir);
        var ctx = new ModuleContext(res);
        res.DefaultModuleContext = ctx;
        var mod = ModuleDefMD.Load(path, ctx);
        // 与 patchcctor 相同: call-null 死代码要清掉, 否则 dnlib 写不了盘
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions)
                    if (ins.Operand == null && (ins.OpCode.Code == Code.Call || ins.OpCode.Code == Code.Callvirt))
                        ins.OpCode = OpCodes.Nop;
            }
        return mod;
    }
}
