using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// 分析 AirExplorerCmd 的字符串解密: 谁给 <Module>{...} 的 m_* 字段赋值,
// 调用点长什么样, 解密器被调用多少次
class CmdAn {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var keyFields = new HashSet<FieldDef>();
        TypeDef keyType = null;

        foreach (var t in mod.GetTypes())
            if (t.Name.String.Contains("883c023e")) keyType = t;
        Console.WriteLine("key type: " + (keyType == null ? "NOT FOUND" : keyType.FullName));
        if (keyType != null)
            foreach (var f in keyType.Fields) keyFields.Add(f);
        Console.WriteLine("key fields: " + keyFields.Count);

        // stsfld 到哪里
        var writers = new Dictionary<string, int>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions)
                    if (ins.OpCode.Code == Code.Stsfld && ins.Operand is FieldDef fd && keyFields.Contains(fd)) {
                        var k = t.FullName + "::" + m.Name;
                        writers[k] = writers.TryGetValue(k, out int c) ? c + 1 : 1;
                    }
            }
        Console.WriteLine("=== stsfld writers ===");
        foreach (var kv in writers.OrderByDescending(x => x.Value)) Console.WriteLine("  " + kv.Key + "  x" + kv.Value);

        // 解密器调用点
        MethodDef dec = null;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods)
                if (m.Name.String == "SetupReporter") dec = m;
        Console.WriteLine("decryptor: " + (dec == null ? "none" : dec.FullName));

        int total = 0; var shapes = new Dictionary<string, int>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var ins = m.Body.Instructions;
                for (int i = 0; i < ins.Count; i++) {
                    if (ins[i].OpCode.Code != Code.Call) continue;
                    if (!(ins[i].Operand is IMethod im) || im.Name != "SetupReporter") continue;
                    total++;
                    // 回看: ldsfld <keyfield>; xor; ldc B; ldc A  (顺序可能变)
                    var sb = new List<string>();
                    for (int j = Math.Max(0, i - 8); j < i; j++) {
                        var x = ins[j];
                        string s = x.OpCode.Name;
                        if (x.Operand is FieldDef f2) s += " " + (f2.DeclaringType == keyType ? "KEYFIELD" : f2.Name);
                        else if (x.OpCode.Code == Code.Ldc_I4 || x.OpCode.Code == Code.Ldc_I4_S) s += " " + x.GetLdcI4Value();
                        sb.Add(s);
                    }
                    var shape = string.Join(" ; ", sb);
                    if (shapes.Count < 6 && !shapes.ContainsKey(shape)) shapes[shape] = 1;
                }
            }
        Console.WriteLine("decryptor call sites: " + total);
        Console.WriteLine("=== 调用点前 8 条示例 ===");
        foreach (var s in shapes.Keys) Console.WriteLine("  " + s);
    }
}
