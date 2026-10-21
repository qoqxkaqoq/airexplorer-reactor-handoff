using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class DumpMeth {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        for (int k = 1; k + 1 < a.Length; k += 2) {
            string tfull = a[k].Replace('+', '/');
            string mname = a[k + 1];
            foreach (var t in mod.GetTypes())
                if (t.FullName == tfull)
                    foreach (var m in t.Methods)
                        if (m.Name.String == mname && m.HasBody) {
                            Console.WriteLine("===== " + tfull + "::" + mname + " (" + m.Body.Instructions.Count + " 指令) =====");
                            foreach (var ins in m.Body.Instructions)
                                Console.WriteLine("  " + ins.OpCode + (ins.Operand == null ? "" : " " + TrimOperand(ins.Operand)));
                        }
                        else if (m.Name.String == mname && !m.HasBody)
                            Console.WriteLine("===== " + tfull + "::" + mname + " (无体) =====");
        }
        return 0;
    }
    static string TrimOperand(object op) {
        var s = op.ToString();
        return s.Length > 90 ? s.Substring(0, 90) + "..." : s;
    }
}
