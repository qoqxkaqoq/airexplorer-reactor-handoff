using System;
using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// restoresnap <in.exe> <snapshot.txt> <out.exe>
// 把官方运行时快照恢复为 <Module>.cctor 开头的 IL:
//   B64 → ldstr; call Convert.FromBase64String; stsfld
//   INT → ldc.i4; stsfld
//   STR → ldstr b64; FromBase64String; Encoding.UTF8.GetString; stsfld
// 只处理 DI.* (DispatcherInitializer 静态字段) — IGC 的哈希输入就在这里
class RestoreSnap {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var di = mod.Find("CloudClient.Templating.DispatcherInitializer", false);
        if (di == null) { Console.WriteLine("DI not found"); return; }
        var flds = new Dictionary<string, FieldDef>();
        foreach (var f in di.Fields) if (f.IsStatic) flds[f.Name.String] = f;
        // 插入点可参数化: ITP(06004196)=业务首次解密时恢复(配 IGC ret); IGC(06004192)=IGC 执行前
        var cctor = mod.ResolveToken(0x06000000u | Convert.ToUInt32(a[3], 16)) as MethodDef;
        if (cctor == null || !cctor.HasBody) { Console.WriteLine("IGC null"); return; }

        var il = cctor.Body.Instructions;
        var ins = new List<Instruction>();
        int nB64 = 0, nInt = 0, nStr = 0, nList = 0, skip = 0;
        var allLines = File.ReadAllLines(a[1]);
        for (int li = 0; li < allLines.Length; li++) {
            var ln = allLines[li];
            var sp = ln.Split(' ');
            if (sp.Length < 2) continue;
            if (!sp[1].StartsWith("DI.")) continue;
            var fname = sp[1].Substring(3);
            if (!flds.TryGetValue(fname, out var f)) continue;
            // LIST 恢复: newobj List<T>; dup; 元素 Add ×N; stsfld
            if (sp[0] == "LIST" && li + 1 < allLines.Length) {
                var nxt = allLines[li + 1].Split(' ');
                if (nxt.Length >= 2 && nxt[1] == sp[1] + "[]") {
                    var isStr = nxt[0] == "STR";
                    var listType = isStr ? "System.Collections.Generic.List`1<System.String>" : "System.Collections.Generic.List`1<System.Int32>";
                    var elSig = isStr ? mod.CorLibTypes.String : (TypeSig)mod.CorLibTypes.Int32;
                    var lr = new TypeRefUser(mod, "System.Collections.Generic", "List`1", mod.CorLibTypes.AssemblyRef);
                    var addRef = new MemberRefUser(mod, "Add", MethodSig.CreateInstance(mod.CorLibTypes.Void, elSig),
                        new ClassSig(new TypeRefUser(mod, "System.Collections.Generic", "List`1", mod.CorLibTypes.AssemblyRef)));
                    ins.Add(new Instruction(OpCodes.Newobj, new MemberRefUser(mod, ".ctor",
                        MethodSig.CreateInstance(mod.CorLibTypes.Void), lr)));
                    int added = 0;
                    for (int k2 = li + 1; k2 < allLines.Length; k2++) {
                        var e2 = allLines[k2].Split(' ');
                        if (e2.Length < 2 || e2[1] != sp[1] + "[]") break;
                        if (isStr && e2[0] == "STR") {
                            var s2 = Encoding.UTF8.GetString(Convert.FromBase64String(e2[2]));
                            ins.Add(new Instruction(OpCodes.Dup));
                            ins.Add(new Instruction(OpCodes.Ldstr, s2));
                            ins.Add(new Instruction(OpCodes.Callvirt, addRef));
                        } else if (!isStr && e2[0] == "INT" && long.TryParse(e2[2], out var iv)) {
                            ins.Add(new Instruction(OpCodes.Dup));
                            ins.Add(new Instruction(OpCodes.Ldc_I4, (int)iv));
                            ins.Add(new Instruction(OpCodes.Callvirt, addRef));
                        }
                        added++;
                        li = k2;
                    }
                    ins.Add(new Instruction(OpCodes.Stsfld, f));
                    nList++;
                    continue;
                }
            }
            f.Attributes = (f.Attributes & ~FieldAttributes.FieldAccessMask) | FieldAttributes.Public;
            if (sp[0] == "B64" && sp.Length >= 3) {
                ins.Add(new Instruction(OpCodes.Ldstr, sp[2]));
                ins.Add(new Instruction(OpCodes.Call, new MemberRefUser(mod, "FromBase64String",
                    MethodSig.CreateStatic(new SZArraySig(mod.CorLibTypes.Byte), mod.CorLibTypes.String),
                    new TypeRefUser(mod, "System", "Convert", mod.CorLibTypes.AssemblyRef))));
                ins.Add(new Instruction(OpCodes.Stsfld, f));
                nB64++;
            } else if (sp[0] == "INT" && sp.Length >= 3) {
                long v; if (!long.TryParse(sp[2], out v)) continue;
                ins.Add(new Instruction(OpCodes.Ldc_I4, (int)v));
                ins.Add(new Instruction(OpCodes.Stsfld, f));
                nInt++;
            } else if (sp[0] == "STR" && sp.Length >= 3) {
                ins.Add(new Instruction(OpCodes.Ldstr, sp[2]));
                ins.Add(new Instruction(OpCodes.Call, new MemberRefUser(mod, "FromBase64String",
                    MethodSig.CreateStatic(new SZArraySig(mod.CorLibTypes.Byte), mod.CorLibTypes.String),
                    new TypeRefUser(mod, "System", "Convert", mod.CorLibTypes.AssemblyRef))));
                ins.Add(new Instruction(OpCodes.Call, new MemberRefUser(mod, "get_UTF8",
                    MethodSig.CreateStatic(new ClassSig(new TypeRefUser(mod, "System.Text", "Encoding", mod.CorLibTypes.AssemblyRef))),
                    new TypeRefUser(mod, "System.Text", "Encoding", mod.CorLibTypes.AssemblyRef))));
                ins.Add(new Instruction(OpCodes.Callvirt, new MemberRefUser(mod, "GetString",
                    MethodSig.CreateInstance(mod.CorLibTypes.String, new SZArraySig(mod.CorLibTypes.Byte)),
                    new TypeRefUser(mod, "System.Text", "Encoding", mod.CorLibTypes.AssemblyRef))));
                ins.Add(new Instruction(OpCodes.Stsfld, f));
                nStr++;
            } else if (sp[0] == "SKIP" && fname == "automatedError") {
                var asmRef = new TypeRefUser(mod, "System.Reflection", "Assembly", mod.CorLibTypes.AssemblyRef);
                ins.Add(new Instruction(OpCodes.Call, new MemberRefUser(mod, "GetExecutingAssembly",
                    MethodSig.CreateStatic(new ClassSig(asmRef)), asmRef)));
                ins.Add(new Instruction(OpCodes.Stsfld, f));
            } else skip++;
        }
        // 插到 cctor 开头
        for (int k = ins.Count - 1; k >= 0; k--) il.Insert(0, ins[k]);
        Console.WriteLine("[restore] B64=" + nB64 + " INT=" + nInt + " STR=" + nStr + " LIST=" + nList + " skip=" + skip);
        Console.WriteLine("[restore] IGC now " + il.Count + " instrs");
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll;
        mod.Write(a[2], opts);
        Console.WriteLine("[restoresnap] wrote " + a[2]);
    }
}
