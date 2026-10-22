// uiscan.cs — 找出全部 WinForms 窗体类（BaseType 为 Form/UserControl/Control 链），
// 对比官方 vs v59：每个窗体类的方法体覆盖（RVA/桩/真体）+ 指令数差异 → UI 构建链薄弱点
// 用法: uiscan8 <exe> [输出tsv]
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class UiScan {
    static bool IsWinFormsBase(ITypeDefOrRef b, out string baseName) {
        baseName = b == null ? "" : b.FullName;
        return baseName == "System.Windows.Forms.Form"
            || baseName == "System.Windows.Forms.UserControl"
            || baseName == "System.Windows.Forms.ContainerControl"
            || baseName == "System.Windows.Forms.Control";
    }
    static void Walk(TypeDef t, List<TypeDef> acc) {
        string bn;
        if (IsWinFormsBase(t.BaseType, out bn)) acc.Add(t);
        foreach (var n in t.NestedTypes) Walk(n, acc);
    }
    static string Stat(MethodDef m) {
        if (!m.HasBody || m.RVA == 0) return "桩";
        int n = m.Body.Instructions.Count;
        if (n <= 4) {
            bool stubish = m.Body.Instructions.All(i => i.OpCode.Code == Code.Nop || i.OpCode.Code == Code.Ret || i.OpCode.Code == Code.Ldc_I4_0 || i.OpCode.Code == Code.Ldc_I4_1);
            if (stubish) return "桩(小)";
        }
        return n.ToString();
    }
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var forms = new List<TypeDef>();
        foreach (var t in mod.GetTypes()) Walk(t, forms);
        var sb = new System.Text.StringBuilder();
        int realTotal = 0, stubTotal = 0;
        foreach (var f in forms) {
            foreach (var m in f.Methods) {
                var st = Stat(m);
                if (st.StartsWith("桩")) stubTotal++; else realTotal++;
                sb.Append(f.FullName).Append('\t').Append(m.Name).Append('\t')
                  .Append(m.MDToken.Raw.ToString("X8")).Append('\t')
                  .Append(st).Append('\n');
            }
        }
        Console.WriteLine("[uiscan] " + Path.GetFileName(a[0]) + " 窗体类数=" + forms.Count
            + " 方法 真体=" + realTotal + " 桩=" + stubTotal);
        foreach (var f in forms.Take(12))
            Console.WriteLine("  Form: " + f.FullName + "  方法数=" + f.Methods.Count
                + "  桩=" + f.Methods.Count(m => Stat(m).StartsWith("桩")));
        if (a.Length > 1) File.WriteAllText(a[1], sb.ToString());
        return 0;
    }
}
