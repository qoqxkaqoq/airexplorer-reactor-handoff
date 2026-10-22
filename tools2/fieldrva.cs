using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// 列出所有带 FieldRVA 的静态字段及初始字节, 以及所有 "返回 string 且只吃一个 int" 的方法
class FieldRva {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        Console.WriteLine("=== fields with RVA ===");
        foreach (var t in mod.GetTypes()) {
            foreach (var f in t.Fields) {
                var iv = f.InitialValue;
                if (iv == null || iv.Length == 0) continue;
                var head = iv.Length > 16 ? iv.Take(16).ToArray() : iv;
                Console.WriteLine(string.Format("  {0}::{1}  type={2} size={3} bytes={4}",
                    t.FullName, f.Name, f.FieldType.TypeName, iv.Length, BitConverter.ToString(head)));
            }
        }

        Console.WriteLine("=== string-returning int-taking methods ===");
        var decs = new List<MethodDef>();
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.IsStatic || !m.HasBody) continue;
                if (m.MethodSig == null || m.MethodSig.RetType == null) continue;
                if (m.MethodSig.RetType.TypeName != "String") continue;
                if (m.MethodSig.Params.Count != 1) continue;
                if (m.MethodSig.Params[0].TypeName != "Int32") continue;
                decs.Add(m);
            }
        foreach (var m in decs) {
            int calls = CountCalls(mod, m);
            Console.WriteLine(string.Format("  {0}::{1}  instrs={2} callers/callsites={3}",
                m.DeclaringType.FullName, m.Name, m.Body.Instructions.Count, calls));
        }
    }

    static int CountCalls(ModuleDef mod, MethodDef target) {
        int n = 0;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions)
                    if ((ins.OpCode.Code == Code.Call || ins.OpCode.Code == Code.Callvirt) &&
                        ins.Operand is IMethod im && im.ResolveMethodDef() == target) n++;
            }
        return n;
    }
}
