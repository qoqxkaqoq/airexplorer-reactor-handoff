// rescan.cs — 定位 Reactor 的加密资源与其解密方法
//  1. 列出所有嵌入资源
//  2. 找出 IL 里 ldstr 引用了这些资源名的方法（Reactor 解密方法必然引用资源名）
//  3. 对候选方法输出: 签名/指令数/局部变量类型/是否含 XOR key 模式(ldind.i8+ldc.i8)/ia
//  4. 找 DNR 的 CompileMethod (jitter hook 签名),用于判定 Reactor 版本与解密路径
//  5. 把候选资源原样 dump 到 <file>.res_<name>.bin
// 用法: rescan <file.exe> [dumpdir]
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class Rescan {
    static void Main(string[] a) {
        string file = a[0];
        string dump = a.Length > 1 ? a[1] : null;
        var mod = ModuleDefMD.Load(file);

        var embResources = new Dictionary<string, EmbeddedResource>();
        foreach (var r in mod.Resources)
            if (r is EmbeddedResource er) {
                embResources[r.Name.String] = er;
                Console.WriteLine("[res] " + r.Name.String + "  " + er.CreateReader().Length + "B");
            }
        Console.WriteLine();

        // --- 1. 找出引用资源名字符串的方法 ---
        var candidates = new Dictionary<string, List<MethodDef>>();
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    if (ins.OpCode.Code != Code.Ldstr) continue;
                    var s = ins.Operand as string;
                    if (s == null || !embResources.ContainsKey(s)) continue;
                    if (!candidates.TryGetValue(s, out var list)) candidates[s] = list = new List<MethodDef>();
                    if (!list.Contains(m)) list.Add(m);
                }
            }
        }

        Console.WriteLine("=== 引用资源名的方法 (Reactor 解密方法候选) ===");
        foreach (var kv in candidates) {
            Console.WriteLine("资源: " + kv.Key + " (" + embResources[kv.Key].CreateReader().Length + "B)");
            foreach (var m in kv.Value) {
                var locs = m.Body.HasVariables
                    ? string.Join(",", m.Body.Variables.Select(v => v.Type.FullName))
                    : "";
                string xor = "no";
                var instrs = m.Body.Instructions;
                for (int i = 0; i < instrs.Count - 1; i++) {
                    if (instrs[i].OpCode.Code == Code.Ldind_I8) {
                        var n = instrs[i + 1];
                        if (n.IsLdcI4()) { xor = "xorKey=" + n.GetLdcI4Value(); break; }
                        if (n.OpCode.Code == Code.Ldc_I8) { xor = "xorKey=" + (long)n.Operand; break; }
                    }
                }
                Console.WriteLine(string.Format("   M {0}::{1}  sig={2} il={3} static={4} xor={5}",
                    m.DeclaringType.FullName, m.Name, m.MethodSig, m.Body.Instructions.Count, m.IsStatic, xor));
                Console.WriteLine("     locals: " + (locs.Length > 300 ? locs.Substring(0, 300) + "..." : locs));
            }
            Console.WriteLine();
        }

        // --- 2. 找 DNR CompileMethod (jitter hook) ---
        Console.WriteLine("=== DNR CompileMethod 候选 (jitter hook 签名) ===");
        int found = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.IsStatic || !m.HasBody) continue;
                var sig = m.MethodSig;
                if (sig == null || sig.Params.Count != 6) continue;
                if (sig.RetType.FullName != "System.UInt32") continue;
                Console.WriteLine("   [hook] " + t.FullName + "::" + m.Name + " sig=" + sig + " il=" + m.Body.Instructions.Count);
                found++;
            }
        }
        if (found == 0) Console.WriteLine("   (无 6 参数 uint 返回方法)");

        // --- 3. 找含 Rijndael/Aes + MemoryStream + BinaryReader 的方法 (DNR v4 资源解密特征) ---
        Console.WriteLine();
        Console.WriteLine("=== 含 Crypto/MemoryStream 的方法 ===");
        int crypto = 0;
        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                bool hasCrypto = false, hasBR = false, hasMS = false;
                foreach (var ins in m.Body.Instructions) {
                    if (ins.OpCode.Code != Code.Newobj && ins.OpCode.Code != Code.Call) continue;
                    var s = ins.Operand == null ? "" : ins.Operand.ToString();
                    if (s.Contains("RijndaelManaged") || s.Contains("AesManaged") || s.Contains("CryptoStream") || s.Contains("SymmetricAlgorithm")) hasCrypto = true;
                    if (s.Contains("BinaryReader")) hasBR = true;
                    if (s.Contains("MemoryStream")) hasMS = true;
                }
                if (hasCrypto && hasBR && hasMS) {
                    Console.WriteLine("   [crypto] " + t.FullName + "::" + m.Name + " il=" + m.Body.Instructions.Count + " static=" + m.IsStatic + " sig=" + m.MethodSig);
                    crypto++;
                }
            }
        }
        if (crypto == 0) Console.WriteLine("   (无)");

        // --- 4. dump 资源 ---
        if (dump != null) {
            Directory.CreateDirectory(dump);
            foreach (var kv in embResources) {
                string fn = Path.Combine(dump, "res_" + kv.Key + ".bin");
                File.WriteAllBytes(fn, kv.Value.CreateReader().ToArray());
                Console.WriteLine("[dump] " + fn);
            }
        }
    }
}
