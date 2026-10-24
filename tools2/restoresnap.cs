using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

// restoresnap <in.exe> <snapshot.txt> <out.exe> <methodRVA-token-hex>
// 把官方运行时快照恢复为方法开头的 IL:
//   B64 → ldstr; call Convert.FromBase64String; stsfld
//   INT → ldc.i4; stsfld (含 bool True/False)
//   STR → ldstr b64; FromBase64String; Encoding.UTF8.GetString; stsfld
//   LIST → newobj List<T>; dup; 元素 Add ×N; stsfld (泛型参数取自字段签名)
// 容器: DI.=DispatcherInitializer TA.=TemplateArgument 静态字段
class RestoreSnap {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var flds = new Dictionary<string, FieldDef>();
        foreach (var pfx in new[] { "DI.", "TA." }) {
            var tn = pfx == "DI." ? "CloudClient.Templating.DispatcherInitializer" : "CloudClient.Templating.TemplateArgument";
            var ty = mod.Find(tn, false);
            if (ty == null) { Console.WriteLine(pfx + " type not found"); continue; }
            foreach (var f in ty.Fields) if (f.IsStatic) flds[pfx + f.Name.String] = f;
        }
        // 插入点可参数化: ITP(06004196)=业务首次解密时恢复(配 IGC ret); IGC(06004192)=IGC 执行前
        var cctor = mod.ResolveToken(0x06000000u | Convert.ToUInt32(a[3], 16)) as MethodDef;
        if (cctor == null || !cctor.HasBody) { Console.WriteLine("target method null"); return; }

        var il = cctor.Body.Instructions;
        var ins = new List<Instruction>();
        var only = System.Environment.GetEnvironmentVariable("RSONLY");
        int nB64 = 0, nInt = 0, nStr = 0, nList = 0, skip = 0;
        var allLines = File.ReadAllLines(a[1]);
        for (int li = 0; li < allLines.Length; li++) {
            var ln = allLines[li];
            var sp = ln.Split(' ');
            if (sp.Length < 2) continue;
            if (!flds.TryGetValue(sp[1], out var f)) continue;
            var fname = sp[1];
            // LIST 恢复: newobj List<T>(封闭泛型 TypeSpec 取自字段签名); dup; 元素 Add ×N; stsfld
            if (sp[0] == "LIST" && (only == null || only.StartsWith("LIST") || only == "ARR" || only == "ARR2" || only == "OBJ")) {
                if (only == "ARR" || only == "ARR2" || only == "OBJ") { /* 非泛型分支过滤在下方 */ }
                TypeSig elSig = null;
                if (f.FieldType is GenericInstSig) elSig = ((GenericInstSig)f.FieldType).GenericArguments.Count > 0 ? ((GenericInstSig)f.FieldType).GenericArguments[0] : null;
                if (elSig == null) {
                    // 非泛型集合: 数组(SZArraySig)静态化; 引用型集合(SortedList/Hashtable/Object数组)空构造; Object→ldnull
                    var ft = f.FieldType;
                    if (ft is SZArraySig sz && (sz.Next.GetElementType() == ElementType.I4 || sz.Next.GetElementType() == ElementType.U4) && (only == null || only == "ARR")) {
                        var elemTy = sz.Next;
                        var arrSpec = new TypeSpecUser(ft);
                        // 收集元素行(INT)
                        var elems = new List<string>();
                        int nEl = 0;
                        for (int k2 = li + 1; k2 < allLines.Length; k2++) {
                            var e2 = allLines[k2].Split(' ');
                            if (e2.Length < 2 || e2[1] != fname + "[]") break;
                            if (e2[0] == "INT" && e2.Length >= 3 && long.TryParse(e2[2], out var _)) { elems.Add(e2[2]); li = k2; }
                        }
                        nEl = elems.Count;
                        ins.Add(new Instruction(OpCodes.Ldc_I4, nEl));
                        ins.Add(new Instruction(OpCodes.Newarr, elemTy.ToTypeDefOrRef()));
                        for (int k2 = 0; k2 < nEl; k2++) {
                            ins.Add(new Instruction(OpCodes.Dup));
                            ins.Add(new Instruction(OpCodes.Ldc_I4, k2));
                            ins.Add(new Instruction(OpCodes.Ldc_I4, (int)long.Parse(elems[k2])));
                            ins.Add(new Instruction(OpCodes.Stelem_I4));
                        }
                        ins.Add(new Instruction(OpCodes.Stsfld, f));
                        nList++;
                        continue;
                    }
                    if (ft is SZArraySig sz2 && (only == null || only == "ARR2")) { // 对象数组: newarr(len) 默认 null 元素
                        int nEl = 0;
                        for (int k2 = li + 1; k2 < allLines.Length; k2++) {
                            var e2 = allLines[k2].Split(' ');
                            if (e2.Length < 2 || e2[1] != fname + "[]") break;
                            nEl++; li = k2;
                        }
                        ins.Add(new Instruction(OpCodes.Ldc_I4, nEl));
                        ins.Add(new Instruction(OpCodes.Newarr, sz2.Next.ToTypeDefOrRef()));
                        ins.Add(new Instruction(OpCodes.Stsfld, f));
                        nList++;
                        continue;
                    }
                    if (ft.GetElementType() == ElementType.Object && (only == null || only == "OBJ" || only == "OBJ1" || only == "OBJ2")) { // Object 字段, LIST 0 行 → null
                        if (only != "OBJ2") ins.Add(new Instruction(OpCodes.Ldnull));
                        if (only != "OBJ1") ins.Add(new Instruction(OpCodes.Stsfld, f));
                        nList++;
                        continue;
                    }
                    // SortedList/Hashtable/Dictionary 等非泛型引用集合 → newobj 无参 ctor(空集合)
                    if (only != null && only != "CT") { skip++; continue; }
                    // 复用官方已验证的 newobj 引用(自造 TypeRef 在 .NET FW 可能 MissingMethod)
                    var ctorRef = FindOfficialNewobj(mod, ft.FullName);
                    if (ctorRef == null) {
                        var fr = ft.ToTypeDefOrRef();
                        ctorRef = new MemberRefUser(mod, ".ctor", MethodSig.CreateInstance(mod.CorLibTypes.Void), fr);
                    }
                    ins.Add(new Instruction(OpCodes.Newobj, ctorRef));
                    ins.Add(new Instruction(OpCodes.Stsfld, f));
                    nList++;
                    continue;
                }
                // 直接复用官方 MemberRef(含原 sig) — Class 必须与字段类型完全一致(否则 callvirt 栈类型不匹配 → InvalidProgram)
                var addRef = FindOfficialAdd(mod, elSig, f.FieldType.FullName);
                var ctor2 = FindOfficialNewobj(mod, f.FieldType.FullName);
                if (ctor2 == null)
                    ctor2 = new MemberRefUser(mod, ".ctor", MethodSig.CreateInstance(mod.CorLibTypes.Void), new TypeSpecUser(f.FieldType));
                if (only != null && only != "LIST") { skip++; continue; }
                ins.Add(new Instruction(OpCodes.Newobj, ctor2));
                for (int k2 = li + 1; k2 < allLines.Length; k2++) {
                    var e2 = allLines[k2].Split(' ');
                    if (e2.Length < 2 || e2[1] != fname + "[]") break;
                    if (e2[0] == "STR" && e2.Length >= 3 && elSig.GetElementType() != ElementType.I4) {
                        var s2 = Encoding.UTF8.GetString(Convert.FromBase64String(e2[2]));
                        ins.Add(new Instruction(OpCodes.Dup));
                        ins.Add(new Instruction(OpCodes.Ldstr, s2));
                        ins.Add(new Instruction(OpCodes.Callvirt, addRef));
                    } else if (e2[0] == "INT" && e2.Length >= 3 && long.TryParse(e2[2], out var iv) && elSig.GetElementType() == ElementType.I4) {
                        ins.Add(new Instruction(OpCodes.Dup));
                        ins.Add(new Instruction(OpCodes.Ldc_I4, (int)iv));
                        ins.Add(new Instruction(OpCodes.Callvirt, addRef));
                    }
                    li = k2;
                }
                ins.Add(new Instruction(OpCodes.Stsfld, f));
                nList++;
                continue;
            }
            f.Attributes = (f.Attributes & ~FieldAttributes.FieldAccessMask) | FieldAttributes.Public;
            if (sp[0] == "B64" && sp.Length >= 3 && (only == null || only == "B64")) {
                ins.Add(new Instruction(OpCodes.Ldstr, sp[2]));
                ins.Add(new Instruction(OpCodes.Call, new MemberRefUser(mod, "FromBase64String",
                    MethodSig.CreateStatic(new SZArraySig(mod.CorLibTypes.Byte), mod.CorLibTypes.String),
                    new TypeRefUser(mod, "System", "Convert", mod.CorLibTypes.AssemblyRef))));
                ins.Add(new Instruction(OpCodes.Stsfld, f));
                nB64++;
            } else if (sp[0] == "INT" && sp.Length >= 3 && (only == null || only == "INT")) {
                long v;
                if (sp[2] == "True") { ins.Add(new Instruction(OpCodes.Ldc_I4_1)); ins.Add(new Instruction(OpCodes.Stsfld, f)); nInt++; continue; }
                if (sp[2] == "False") { ins.Add(new Instruction(OpCodes.Ldc_I4_0)); ins.Add(new Instruction(OpCodes.Stsfld, f)); nInt++; continue; }
                if (!long.TryParse(sp[2], out v)) continue;
                ins.Add(new Instruction(OpCodes.Ldc_I4, (int)v));
                ins.Add(new Instruction(OpCodes.Stsfld, f));
                nInt++;
            } else if (sp[0] == "STR" && sp.Length >= 3 && (only == null || only == "STR")) {
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
            } else if (sp[0] == "SKIP" && fname == "automatedError" && (only == null || only == "SKIP")) {
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
        opts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(a[2], opts);
        Console.WriteLine("[restoresnap] wrote " + a[2]);
    }

    // 在官方程序集里找已存在且能被 CLR 解析的引用(官方代码里出现过的 MemberRef 必然可解析)
    static MemberRef FindOfficialAdd(ModuleDef mod, TypeSig elSig, string listTypeFullName) {
        foreach (var t in mod.GetTypes()) foreach (var m in t.Methods) {
            if (!m.HasBody) continue;
            foreach (var oi in m.Body.Instructions) {
                if (oi.OpCode.Code != Code.Callvirt) continue;
                var mr = oi.Operand as MemberRef;
                if (mr == null || mr.Name != "Add" || mr.MethodSig == null || mr.MethodSig.Params.Count != 1) continue;
                var p0 = mr.MethodSig.Params[0];
                bool p0ok = p0 is GenericVar || p0 is GenericMVar || p0.FullName == elSig.FullName;
                if (p0ok && mr.Class != null && mr.Class.FullName == listTypeFullName) return mr;
            }
        }
        return null;
    }
    static MemberRef FindOfficialNewobj(ModuleDef mod, string typeFullName) {
        foreach (var t in mod.GetTypes()) foreach (var m in t.Methods) {
            if (!m.HasBody) continue;
            foreach (var oi in m.Body.Instructions) {
                if (oi.OpCode.Code != Code.Newobj) continue;
                var mr = oi.Operand as MemberRef;
                if (mr == null || mr.Class == null) continue;
                if (mr.Class.FullName == typeFullName && mr.MethodSig != null && mr.MethodSig.Params.Count == 0) return mr;
            }
        }
        return null;
    }
}
