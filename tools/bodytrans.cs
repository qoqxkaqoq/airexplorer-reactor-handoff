// bodytrans.cs — 方法体移植器: 从源模块克隆指定方法的完整 IL 体 (局部变量/token 重映射/异常表)
// 用法: bodytrans <src> <dst> <out> <TypeFullName> <MethodName> [<TypeFullName> <MethodName> ...]
// 实证需求: nb_slayer 的 SearchAdapter (入口 Main) 体无效, 而 nb_original 同名体可运行 (基座 token 不同)
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class BodyTrans {
    static ModuleDef curDstMod;   // 当前目标模块 (ImportSmart 全局成员重定向用)
    static int Main(string[] a) {
        if (a.Length > 5 && a[0] == "trace") return Trace(a);
        if (a.Length > 4 && a[0] == "clonetree") return CloneTree(a);
        if (a.Length > 2 && a[0] == "rbindall") return RbindAll(a);
        if (a.Length > 3 && a[0] == "clonetypes") return CloneTypes(a);
        if (a.Length > 3 && a[0] == "makepublic") return MakePublic(a);
        if (a.Length > 3 && a[0] == "fixmodrefs") return FixModRefs(a);
        if (a.Length > 4 && a[0] == "stub") return Stub(a);
        if (a.Length > 5 && a[0] == "jitdump") return JitDump(a);
        if (a.Length < 5 || (a.Length - 3) % 2 != 0) {
            Console.WriteLine("usage: bodytrans <src> <dst> <out> <Type> <Method> [...] | bodytrans jitdump <src> <dst> <out> <dumpdir> <Type> <Method> [...]");
            return 1;
        }
        var srcMod = ModuleDefMD.Load(a[0]);
        var dstMod = ModuleDefMD.Load(a[1]);
        var importer = new Importer(dstMod);
        curDstMod = dstMod;
        int n = 0;
        for (int k = 3; k + 1 < a.Length; k += 2) {
            string tfull = a[k].Replace('+', '/');
            string mname = StripGeneric(a[k + 1]);
            var srcM = FindMethod(srcMod, tfull, mname);
            var dstM = FindMethod(dstMod, tfull, mname);
            if (srcM == null) { Console.WriteLine("[trans] src 未找到: " + tfull + "::" + mname); continue; }
            if (!srcM.HasBody) { Console.WriteLine("[trans] src 无体: " + mname); continue; }
            // 防桩覆盖: 源体疑似桩 (≤4 指令且 ldnull/ret 或 ret-only) → 不移植 (v103 轮次12 实证: 桩覆盖了回填真身)
            if (srcM.Body.Instructions.Count <= 4) {
                var opcs = srcM.Body.Instructions.Select(x => x.OpCode.Code).ToList();
                bool retOnly = opcs.All(c => c == dnlib.DotNet.Emit.Code.Ret || c == dnlib.DotNet.Emit.Code.Nop);
                bool nullRet = opcs.SequenceEqual(new[] { dnlib.DotNet.Emit.Code.Ldnull, dnlib.DotNet.Emit.Code.Ret });
                bool ldc0Ret = opcs.SequenceEqual(new[] { dnlib.DotNet.Emit.Code.Ldc_I4_0, dnlib.DotNet.Emit.Code.Ret });
                if (retOnly || nullRet || ldc0Ret) {
                    Console.WriteLine("[trans] src 是桩(" + srcM.Body.Instructions.Count + " 指令), 跳过防覆盖: " + mname);
                    continue;
                }
            }
            if (dstM == null) {
                // dst 缺方法 → 整体克隆方法定义 (Slayer 削除的 NecroBit 相关方法, 如 VerifyActiveCalc)
                try {
                    var dstT = FindType(dstMod, tfull);
                    if (dstT == null) { Console.WriteLine("[trans] dst 缺类型: " + tfull); continue; }
                    var nm = new MethodDefUser(srcM.Name, importer.Import(srcM.MethodSig), srcM.ImplAttributes, srcM.Attributes);
                    // 返回类型/参数按源签名 (MethodSig 已含)
                    dstT.Methods.Add(nm);
                    dstM = nm;
                    Console.WriteLine("[trans] 克隆新方法: " + tfull + "::" + mname);
                } catch (Exception ex) { Console.WriteLine("[trans] 克隆失败 " + mname + ": " + ex.Message); continue; }
            }
            try {
                TransplantBody(dstM, srcM, importer);
                RebindRefs(dstM, dstMod);
                n++;
                Console.WriteLine("[trans] 移植: " + tfull + "::" + mname + " (" + srcM.Body.Instructions.Count + " 指令)");
            } catch (Exception ex) { Console.WriteLine("[trans] 失败 " + mname + ": " + ex.Message); }
        }
        return WriteOut(dstMod, a[2], n);
    }

    // ===== trace 模式: 在方法入口插入 File.AppendAllText 标记 (GUI 程序写文件)
    // 用法: bodytrans trace <dst> <out> <Type> <Method> <label> [logPath]
    static int Trace(string[] a) {
        var dstMod = ModuleDefMD.Load(a[1]);
        curDstMod = dstMod;
        var dstT = FindType(dstMod, a[3].Replace('+', '/'));
        if (dstT == null) { Console.WriteLine("[trace] 类型缺失: " + a[3]); return 2; }
        var m = dstT.Methods.FirstOrDefault(x => x.Name.String == StripGeneric(a[4]));
        if (m == null || !m.HasBody) { Console.WriteLine("[trace] 方法缺失/无体: " + a[4]); return 2; }
        // GUI 程序 Console.WriteLine 无输出 → 写文件 trace.log (工作目录 = run 目录)
        var sysIoT = new TypeRefUser(dstMod, "System.IO", "File", dstMod.CorLibTypes.AssemblyRef);
        var faSig = MethodSig.CreateStatic(dstMod.CorLibTypes.Void, dstMod.CorLibTypes.String, dstMod.CorLibTypes.String);
        var fa = new MemberRefUser(dstMod, "AppendAllText", faSig, sysIoT);
        // v121 实证: 插桩+2 栈槽后超原 maxstack → InvalidProgram (退出码 -532462766)
        m.Body.MaxStack = (ushort)Math.Min(65535, m.Body.MaxStack + 2);
        var i8 = Instruction.Create(OpCodes.Ldstr, a.Length > 6 ? a[6] : "trace.log");
        var i7 = Instruction.Create(OpCodes.Ldstr, "[TRACE] " + a[5] + "\r\n");
        var i6 = Instruction.Create(OpCodes.Call, fa);
        var i0 = m.Body.Instructions[0];
        m.Body.Instructions.Insert(0, i0);
        m.Body.Instructions.Insert(0, i6);
        m.Body.Instructions.Insert(0, i7);
        m.Body.Instructions.Insert(0, i8);
        Console.WriteLine("[trace] 已插桩: " + a[3] + "::" + a[4] + " ← " + a[5]);
        return WriteOut(dstMod, a[2], 1);
    }

    // ===== clonetree 模式: 从入口方法 BFS 调用树, dst 缺失/桩的方法批量从 src 移植 (v108 实证循环逐个撞太慢)
    // 用法: bodytrans clonetree <src> <dst> <out> <Type> <Method> [maxDepth]
    static int CloneTree(string[] a) {
        var srcMod = ModuleDefMD.Load(a[1]);
        var dstMod = ModuleDefMD.Load(a[2]);
        var importer = new Importer(dstMod);
        curDstMod = dstMod;
        int maxDepth = a.Length > 6 ? int.Parse(a[6]) : 3;
        var visited = new HashSet<string>();
        var queue = new Queue<Tuple<MethodDef, int>>();   // src 方法, 深度
        int n = 0;
        // 入口
        string tfull0 = a[4].Replace('+', '/');
        var sm0 = FindMethod(srcMod, tfull0, StripGeneric(a[5]));
        if (sm0 == null || !sm0.HasBody) { Console.WriteLine("[ctree] src 入口无体"); return 2; }
        queue.Enqueue(Tuple.Create(sm0, 0));
        while (queue.Count > 0) {
            var item = queue.Dequeue();
            var sm = item.Item1; int depth = item.Item2;
            string key = sm.DeclaringType.FullName + "::" + sm.Name + ":" + sm.MethodSig.Params.Count;
            if (!visited.Add(key)) continue;
            if (depth > maxDepth || n > 800) continue;
            // dst 侧定位
            string dtf = sm.DeclaringType.FullName.Replace('+', '/');
            var dt = FindType(dstMod, dtf);
            if (dt == null) { continue; }   // 类型缺 → 跳过 (cclonetypes 兜)
            MethodDef dm = null;
            foreach (var cand in dt.Methods)
                if (cand.Name.String == sm.Name.String && cand.MethodSig != null && sm.MethodSig != null &&
                    cand.MethodSig.Params.Count == sm.MethodSig.Params.Count && cand.IsStatic == sm.IsStatic) { dm = cand; break; }
            bool needTrans = false;
            if (dm == null) {
                // 克隆新方法 (同签名) — 克隆后必须移植体 (v109 实证: 无体=no RVA 崩)
                try {
                    dm = new MethodDefUser(sm.Name, importer.Import(sm.MethodSig), sm.ImplAttributes, sm.Attributes);
                    dt.Methods.Add(dm);
                    needTrans = true;
                    Console.WriteLine("[ctree] 克隆方法: " + dtf + "::" + sm.Name);
                } catch (Exception ex) { Console.WriteLine("[ctree] 克隆失败 " + sm.Name + ": " + ex.Message); continue; }
            } else if (!dm.HasBody || IsStubBody(dm)) {
                needTrans = true;   // dst 无体/桩 → 移植
            }
            // 字段同步: 对所有访问到的方法扫其体引用的 dst 缺失字段 (v110 实证 MissingField:
            // <PrivateImplementationDetails> 字符串数据字段; 循环克隆的方法体引用它但字段不在)
            if (sm.HasBody) {
                foreach (var ins in sm.Body.Instructions) {
                    var fld = ins.Operand as IField;
                    if (fld == null || fld.DeclaringType == null) continue;
                    var sft = fld.DeclaringType.ResolveTypeDef();
                    if (sft == null) continue;
                    var ddt2 = FindType(dstMod, sft.FullName.Replace('+', '/'));
                    if (ddt2 == null) continue;
                    // PrivateImplementationDetails 特例: dst 已有字段引用的 SAIT 家族 (=16/=24/=40...)
                    // 必须全量补齐, 只补一个其他仍悬空 → 验证器 "field of an illegal type" (v112 实证)
                    if (sft.Name.String.StartsWith("<PrivateImplementationDetails>")) {
                        int nfixS = 0;
                        foreach (var ssait in sft.NestedTypes) {
                            if (!ssait.Name.String.StartsWith("__StaticArrayInitTypeSize=")) continue;
                            if (ddt2.NestedTypes.Any(x => x.Name.String == ssait.Name.String)) continue;
                            var bs = ssait.BaseType != null && ssait.BaseType.FullName == "System.ValueType"
                                ? (dnlib.DotNet.ITypeDefOrRef)new TypeRefUser(dstMod, "System", "ValueType", dstMod.CorLibTypes.AssemblyRef)
                                : importer.Import(ssait.BaseType);
                            var ntd = new TypeDefUser(ssait.Namespace, ssait.Name, bs);
                            ntd.Attributes = ssait.Attributes;
                            if (ssait.ClassLayout != null) ntd.ClassLayout = new ClassLayoutUser(ssait.ClassLayout.PackingSize, ssait.ClassLayout.ClassSize);
                            ddt2.NestedTypes.Add(ntd);
                            nfixS++;
                        }
                        foreach (var sfld in sft.Fields) {
                            if (ddt2.Fields.Any(x => x.Name.String == sfld.Name.String)) continue;
                            var fsigT2 = importer.Import(sfld.FieldSig.Type);
                            var srt2 = fsigT2.TryGetTypeRef();
                            if (srt2 != null) {
                                var dstT2 = dstMod.Find(srt2.FullName, false) ?? ddt2.NestedTypes.FirstOrDefault(x => x.Name.String == srt2.Name.String);
                                if (dstT2 != null) fsigT2 = new ValueTypeSig(dstT2);   // 值类型必须 ValueTypeSig (ClassSig=CLASS 元素类型 → 验证器 illegal, v113 实证)
                            }
                            var nfd = new FieldDefUser(sfld.Name, new FieldSig(fsigT2), sfld.Attributes);
                            if (sfld.RVA != 0 && sfld.InitialValue != null) nfd.InitialValue = sfld.InitialValue;
                            ddt2.Fields.Add(nfd);
                            nfixS++;
                        }
                        if (nfixS > 0) { n += nfixS; Console.WriteLine("[ctree] PrivateImplDetails 家族补齐 " + nfixS + " 项"); }
                        continue;
                    }
                    if (!ddt2.Fields.All(x => x.Name.String != fld.Name.String)) continue;
                    var sf = fld.ResolveFieldDef();
                    if (sf == null) continue;
                    if (sf.Name.String.StartsWith("0E448EF5")) Console.WriteLine("[ctree-dbg] ddt2=" + ddt2.FullName + " 字段声明类型=" + sft.FullName);
                    // __StaticArrayInitTypeSize=N 类型 dst 缺失 → 克隆类型 (Import 对外部 TypeDef 生成
                    // TypeRef, 写入器解析不到 ClassLayout → size=0 ≠ InitialValue.Length → 写盘崩)
                    var sftt0 = sf.FieldSig.Type.TryGetTypeDef();
                    if (sf.Name.String.StartsWith("0E448EF5")) {
                        Console.WriteLine("[ctree-dbg] 字段0E44: sftt0=" + (sftt0 == null ? "null" : sftt0.FullName) + " dstFind=" + (sftt0 == null ? "-" : (dstMod.Find(sftt0.FullName, false) == null ? "null" : "存在")));
                    }
                    dnlib.DotNet.TypeDef dSAIT = null;
                    if (sftt0 != null && sftt0.Name.String.StartsWith("__StaticArrayInitTypeSize=")) {
                        // 父类型 layout 同步: dst 版本若丢 layout → "field of an illegal type"
                        if (ddt2.IsAutoLayout && !sft.IsAutoLayout) {
                            ddt2.Attributes = sft.Attributes;
                            if (sft.ClassLayout != null && ddt2.ClassLayout == null)
                                ddt2.ClassLayout = new ClassLayoutUser(sft.ClassLayout.PackingSize, sft.ClassLayout.ClassSize);
                        }
                        dSAIT = ddt2.NestedTypes.FirstOrDefault(x => x.Name.String == sftt0.Name.String);
                        if (dSAIT == null) {
                            // BaseType 手绑 corlib (importer 保留 nb_original scope → 运行时解析失败 → illegal type)
                            dnlib.DotNet.ITypeDefOrRef bt;
                            if (sftt0.BaseType.FullName == "System.ValueType") bt = new TypeRefUser(dstMod, "System", "ValueType", dstMod.CorLibTypes.AssemblyRef);
                            else if (sftt0.BaseType.FullName == "System.Object") bt = new TypeRefUser(dstMod, "System", "Object", dstMod.CorLibTypes.AssemblyRef);
                            else bt = importer.Import(sftt0.BaseType);
                            var ntd = new TypeDefUser(sftt0.Namespace, sftt0.Name, bt);
                            ntd.Attributes = sftt0.Attributes;   // SequentialLayout 必须复制 (AutoLayout+无字段 → GetClassSize=0 → 写盘崩)
                            ntd.ClassLayout = new ClassLayoutUser(1, sftt0.ClassLayout != null ? sftt0.ClassLayout.ClassSize : 16);
                            ddt2.NestedTypes.Add(ntd);
                            dSAIT = ntd;
                            Console.WriteLine("[ctree] 克隆嵌套类型: " + sftt0.Name);
                        }
                    }
                    dnlib.DotNet.TypeSig fsigT;
                    if (dSAIT != null) fsigT = new ValueTypeSig(dSAIT);   // 值类型必须 ValueTypeSig (ClassSig=CLASS → illegal)
                    else fsigT = importer.Import(sf.FieldSig.Type);
                    var nf = new FieldDefUser(sf.Name, new FieldSig(fsigT), sf.Attributes);
                    if (sf.HasConstant) nf.Constant = new dnlib.DotNet.ConstantUser(sf.Constant.Value);
                    if (sf.RVA != 0) {
                        byte[] iv = sf.InitialValue;
                        int wantSize = dSAIT != null && dSAIT.ClassLayout != null ? (int)dSAIT.ClassLayout.ClassSize : -1;
                        if (wantSize > 0 && (iv == null || iv.Length != wantSize)) {
                            var nv = new byte[wantSize];
                            if (iv != null) Array.Copy(iv, nv, Math.Min(iv.Length, wantSize));
                            iv = nv;
                        }
                        nf.InitialValue = iv;
                    }
                    ddt2.Fields.Add(nf);
                    n++;
                    Console.WriteLine("[ctree] 克隆字段: " + sft.FullName.Replace('+', '/') + "::" + sf.Name.String.Substring(0, System.Math.Min(24, sf.Name.String.Length)));
                }
            }
            if (needTrans && sm.HasBody && !IsStubBody(sm)) {
                try {
                    TransplantBody(dm, sm, importer);
                    RebindRefs(dm, dstMod);
                    n++;
                    Console.WriteLine("[ctree] 移植: " + dtf + "::" + sm.Name + " (" + sm.Body.Instructions.Count + " 指令)");
                } catch (Exception ex) { Console.WriteLine("[ctree] 移植失败 " + sm.Name + ": " + ex.Message); continue; }
            }
            // BFS: 展开 sm 调用的所有方法
            if (!sm.HasBody) continue;
            int d2 = needTrans || dm == null || !dm.HasBody ? depth + 1 : depth;   // 修过的才展开下一层
            foreach (var ins in sm.Body.Instructions) {
                var callee = ins.Operand as IMethod;
                if (callee == null) continue;
                MethodDef cs = null;
                try { cs = callee.ResolveMethodDef(); } catch { }
                if (cs == null && callee.DeclaringType != null && callee.DeclaringType.ResolveTypeDef() == sm.DeclaringType) {
                    foreach (var cand in sm.DeclaringType.Methods)
                        if (cand.Name.String == callee.Name.String && cand.MethodSig != null && callee.MethodSig != null && cand.MethodSig.Params.Count == callee.MethodSig.Params.Count) { cs = cand; break; }
                }
                if (cs != null && cs.HasBody && cs.DeclaringType != null && cs.Module == srcMod)
                    queue.Enqueue(Tuple.Create(cs, d2 + 1));
            }
        }
        Console.WriteLine("[ctree] 完成: " + n + " 处修改");
        return WriteOut(dstMod, a[3], n);
    }

    static bool IsStubBody(MethodDef m) {
        if (!m.HasBody) return true;
        var ic = m.Body.Instructions;
        if (ic.Count > 4) return false;
        bool allNop = ic.All(x => x.OpCode.Code == dnlib.DotNet.Emit.Code.Nop);
        bool retOnly = ic.All(x => x.OpCode.Code == dnlib.DotNet.Emit.Code.Ret || x.OpCode.Code == dnlib.DotNet.Emit.Code.Nop);
        bool nullRet = ic.Count == 2 && ic[0].OpCode.Code == dnlib.DotNet.Emit.Code.Ldnull && ic[1].OpCode.Code == dnlib.DotNet.Emit.Code.Ret;
        bool ldc0Ret = ic.Count == 2 && ic[0].OpCode.Code == dnlib.DotNet.Emit.Code.Ldc_I4_0 && ic[1].OpCode.Code == dnlib.DotNet.Emit.Code.Ret;
        return retOnly || nullRet || ldc0Ret || (allNop && ic.Count <= 2);
    }

    // ===== rbindall 模式: 全模块扫描 — 修所有方法中解析失败的 MemberRef (slayer tokmap 遗漏)
    // 用法: bodytrans rbindall <dst> <out>
    static int RbindAll(string[] a) {
        var dstMod = ModuleDefMD.Load(a[1]);
        curDstMod = dstMod;
        int methods = 0, maxfix = 0;
        foreach (var t in dstMod.GetTypes().ToList())
            foreach (var m in t.Methods.ToList()) {
                if (!m.HasBody || m.Body.Instructions.Count == 0) continue;
                RebindRefs(m, dstMod);
                methods++;
                // maxstack 修复: Slayer 恢复体 maxstack 普遍偏小 (DefineEfficientProfiler 9950 指令 maxstack=8,
                // 实际栈峰 ~282 → JIT InvalidProgram, v104 轮次1 实证)。大方法给安全值。
                if (m.Body.Instructions.Count > 60 && m.Body.MaxStack < 128) { m.Body.MaxStack = 512; maxfix++; }
            }
        Console.WriteLine("[bfix] 扫描 " + methods + " 方法, maxstack 修复 " + maxfix);
        return WriteOut(dstMod, a[2], maxfix);
    }

    // ===== clonetypes 模式: 按名前缀从源模块批量克隆缺失类型 (CILantro 的 GeneratedEnum_* 嵌套枚举)
    // 用法: bodytrans clonetypes <src> <dst> <out> <名称前缀> [...]
    static int CloneTypes(string[] a) {
        var srcMod = ModuleDefMD.Load(a[1]);
        var dstMod = ModuleDefMD.Load(a[2]);
        var importer = new Importer(dstMod);
        curDstMod = dstMod;
        int n = 0;
        for (int k = 4; k < a.Length; k++) {
            string prefix = a[k];
            foreach (var st in srcMod.GetTypes().Where(t => t.Name.String.StartsWith(prefix)).ToList()) {
                if (dstMod.Find(st.FullName, false) != null) continue;   // 已存在
                try { CloneTypeDef(st, srcMod, dstMod, importer); n++; }
                catch (Exception ex) { Console.WriteLine("[ct] 克隆失败 " + st.FullName + ": " + ex.Message); }
            }
        }
        Console.WriteLine("[ct] 克隆类型: " + n);
        return WriteOut(dstMod, a[3], n);
    }

    static void CloneTypeDef(dnlib.DotNet.TypeDef st, ModuleDefMD srcMod, ModuleDefMD dstMod, Importer importer) {
        // 父类型定位 (嵌套链)
        var parent = st.DeclaringType;
        dnlib.DotNet.TypeDef dstParent = null;
        if (parent != null) {
            dstParent = FindType(dstMod, parent.FullName.Replace('+', '/'));
            if (dstParent == null) {
                // 父类型也缺 → 递归克隆
                CloneTypeDef(parent, srcMod, dstMod, importer);
                dstParent = FindType(dstMod, parent.FullName.Replace('+', '/'));
                if (dstParent == null) throw new Exception("父类型仍缺: " + parent.FullName);
            }
        }
        var nt = new TypeDefUser(st.Name, importer.Import(st.BaseType));
        nt.Attributes = st.Attributes;
        foreach (var f in st.Fields) {
            var nf = new FieldDefUser(f.Name, f.FieldSig != null ? new dnlib.DotNet.FieldSig(importer.Import(f.FieldSig.Type)) : null, f.Attributes);
            if (f.HasConstant) nf.Constant = new dnlib.DotNet.ConstantUser(f.Constant.Value);
            nf.RVA = 0;
            nt.Fields.Add(nf);
        }
        foreach (var ifc in st.Interfaces) nt.Interfaces.Add(new InterfaceImplUser(importer.Import(ifc.Interface)));
        if (dstParent != null) {
            dstParent.NestedTypes.Add(nt);   // dnlib 自动设置 DeclaringType (先设会报 already owned)
        } else {
            dstMod.Types.Add(nt);
        }
        Console.WriteLine("[ct] 克隆: " + st.FullName);
    }

    // ===== makepublic 模式: MethodAccessException 修复 — 目标方法+嵌套类型链全放开可见性 =====
    // 用法: bodytrans makepublic <dst> <out> <TypeFullName> <MethodName> [...]
    static int MakePublic(string[] a) {
        var dstMod = ModuleDefMD.Load(a[1]);
        curDstMod = dstMod;
        int n = 0;
        for (int k = 3; k + 1 < a.Length; k += 2) {
            string tfull = a[k].Replace('+', '/');
            string mname = StripGeneric(a[k + 1]);
            var t = FindType(dstMod, tfull);
            if (t == null) { Console.WriteLine("[mp] 类型未找到: " + tfull); continue; }
            // 嵌套类型链全放开 (内→外)
            var chain = new List<dnlib.DotNet.TypeDef>();
            for (var cur = t; cur != null; cur = cur.DeclaringType) chain.Add(cur);
            foreach (var ct in chain) {
                if (ct.IsNested) ct.Attributes = (ct.Attributes & ~dnlib.DotNet.TypeAttributes.VisibilityMask) | dnlib.DotNet.TypeAttributes.NestedPublic;
                else ct.Attributes |= dnlib.DotNet.TypeAttributes.Public;
            }
            var target = FindMethod(dstMod, tfull, mname);
            if (target != null) {
                target.Attributes = (target.Attributes & ~dnlib.DotNet.MethodAttributes.MemberAccessMask) | dnlib.DotNet.MethodAttributes.Public;
                n++;
                Console.WriteLine("[mp] 放开: " + tfull + "::" + mname + " (方法+类型链 Public)");
            } else {
                // 方法不存在 → 连方法壳一起从签名建? MethodAccess 场景方法必存在, 仅记日志
                Console.WriteLine("[mp] 方法未找到: " + tfull + "::" + mname + " (类型已放开)");
                n++;  // 类型链放开本身也是有效修改
            }
        }
        return WriteOut(dstMod, a[2], n);
    }

    // ===== fixmodrefs 模式: 同步 <Module> 全局成员 + 改写 <Module>{MVID} 坏引用 =====
    // 用法: bodytrans fixmodrefs <nb_original> <dst> <out>
    // 根治: TypeLoadException "Could not load type '<Module>{guid}'" (Slayer 削除的全局成员被 Importer 生成了坏 TypeRef)
    static int FixModRefs(string[] a) {
        var srcMod = ModuleDefMD.Load(a[1]);
        var dstMod = ModuleDefMD.Load(a[2]);
        var importer = new Importer(dstMod);
        curDstMod = dstMod;
        var srcG = srcMod.GlobalType;
        var dstG = dstMod.GlobalType;
        int synced = 0, fixedRefs = 0;

        // 1) 同步全局方法 (跳过 .cctor — 保留 ccfix 剪过的版本)
        if (srcG != null && dstG != null) {
            foreach (var sm in srcG.Methods) {
                if (sm.Name.String == ".cctor") continue;
                var dm = dstG.Methods.FirstOrDefault(x => x.Name.String == sm.Name.String);
                if (dm == null) {
                    var nm = new MethodDefUser(sm.Name, importer.Import(sm.MethodSig), sm.ImplAttributes, sm.Attributes);
                    dstG.Methods.Add(nm);
                    dm = nm;
                    if (sm.HasBody) { try { TransplantBody(dm, sm, importer); } catch { } }
                    synced++;
                } else if (!dm.HasBody && sm.HasBody) {
                    try { TransplantBody(dm, sm, importer); synced++; } catch { }
                }
            }
            foreach (var sf in srcG.Fields) {
                var df = dstG.Fields.FirstOrDefault(x => x.Name.String == sf.Name.String);
                if (df == null) {
                    dstG.Fields.Add(new FieldDefUser(sf.Name, importer.Import(sf.FieldSig), sf.Attributes));
                    synced++;
                }
            }
        }
        Console.WriteLine("[fmr] 全局同步: " + synced + " 项");

        // 2) 改写所有方法中 parent 为 <Module>{...} 的引用 → dst 全局成员直接 token
        foreach (var t in dstMod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                foreach (var ins in m.Body.Instructions) {
                    var im = ins.Operand as IMethod;
                    if (im != null && im.DeclaringType != null && !UTF8String.IsNullOrEmpty(im.DeclaringType.Name) &&
                        im.DeclaringType.Name.String.StartsWith("<Module>")) {
                        var target = GetOrCreateGlobalMethod(dstMod, im);
                        if (target != null) { ins.Operand = target; fixedRefs++; }
                        else Console.WriteLine("[fmr] 全局方法无法建桩: " + im.Name + " (来自 " + m.FullName + ")");
                    }
                    var fi = ins.Operand as IField;
                    if (fi != null && fi.DeclaringType != null && !UTF8String.IsNullOrEmpty(fi.DeclaringType.Name) &&
                        fi.DeclaringType.Name.String.StartsWith("<Module>")) {
                        var target = GetOrCreateGlobalField(dstMod, fi);
                        if (target != null) { ins.Operand = target; fixedRefs++; }
                        else Console.WriteLine("[fmr] 全局字段无法建桩: " + fi.Name + " (来自 " + m.FullName + ")");
                    }
                }
            }
        }
        Console.WriteLine("[fmr] 引用改写: " + fixedRefs + " 处");
        try {
            return WriteOut(dstMod, a[3], 1);
        } catch (Exception ex) {
            Console.WriteLine("[fmr] 写盘失败 (降级跳过): " + ex.GetType().Name + ": " + ex.Message);
            return 2;
        }
    }

    // ===== stub 模式: 运行时生成体兜底 — 按返回类型合成最小桩 (Boolean→true 放行校验) =====
    // 用法: bodytrans stub <dst> <out> <TypeFullName> <MethodName> [...]
    static int Stub(string[] a) {
        var srcMod = ModuleDefMD.Load(a[1]);   // 签名源 (nb_original: 方法壳存在, 体 RVA=0)
        var dstMod = ModuleDefMD.Load(a[2]);
        var importer = new Importer(dstMod);
        curDstMod = dstMod;
        int n = 0;
        for (int k = 4; k + 1 < a.Length; k += 2) {
            string tfull = a[k].Replace('+', '/');
            string mname = StripGeneric(a[k + 1]);
            var dstM = FindMethod(dstMod, tfull, mname);
            if (dstM == null) {
                // dst 缺整个方法 (Slayer 削除) → 从 nb_original 克隆方法壳 (签名+属性)
                var srcM = FindMethod(srcMod, tfull, mname);
                var dstT = FindType(dstMod, tfull);
                if (srcM == null || dstT == null) { Console.WriteLine("[stub] src/dst 未找到: " + tfull + "::" + mname + " (src=" + (srcM != null) + " dstT=" + (dstT != null) + ")"); continue; }
                var nm = new MethodDefUser(srcM.Name, importer.Import(srcM.MethodSig), srcM.ImplAttributes, srcM.Attributes);
                dstT.Methods.Add(nm);
                dstM = nm;
                Console.WriteLine("[stub] 克隆方法壳: " + tfull + "::" + mname);
            }
            try {
                var body = new CilBody();
                body.KeepOldMaxStack = true;
                body.MaxStack = 1;
                var rt = dstM.ReturnType;
                string rtf = (rt == null ? "System.Void" : rt.FullName);
                Instruction push;
                if (rtf == "System.Boolean") push = Instruction.CreateLdcI4(1);   // 校验类: 放行
                else if (rtf == "System.Int32" || rtf == "System.UInt32" || rtf == "System.Int16" ||
                         rtf == "System.UInt16" || rtf == "System.SByte" || rtf == "System.Byte" ||
                         rtf == "System.Char" || rtf == "System.IntPtr" || rtf == "System.UIntPtr")
                    push = Instruction.CreateLdcI4(0);
                else if (rtf == "System.Int64" || rtf == "System.UInt64") push = new Instruction(OpCodes.Ldc_I8) { Operand = 0L };
                else if (rtf == "System.Single") push = new Instruction(OpCodes.Ldc_R4) { Operand = 0f };
                else if (rtf == "System.Double") push = new Instruction(OpCodes.Ldc_R8) { Operand = 0.0 };
                else if (rtf != "System.Void") push = new Instruction(OpCodes.Ldnull);
                else push = null;
                if (push != null) body.Instructions.Add(push);
                body.Instructions.Add(new Instruction(OpCodes.Ret));
                dstM.Body = body;
                n++;
                Console.WriteLine("[stub] 桩化: " + tfull + "::" + mname + " → " + (rtf == "System.Void" ? "ret" : rtf));
            } catch (Exception ex) { Console.WriteLine("[stub] 失败 " + mname + ": " + ex.Message); }
        }
        return WriteOut(dstMod, a[3], n);
    }

    // ===== jitdump 模式: 运行时生成体 (nb_original 中 RVA=0 无体) 从 JIT 转储恢复 =====
    // 用法: bodytrans jitdump <nb_original> <dst> <out> <dumpdir> <Type> <Method> [...]
    // m_XXXX.bin: [u32 token][u32 ilSize][12B 保留][u32 localsTok][原始IL...]; m_XXXX.eh: [u32 cnt][cnt x 28B]
    static int JitDump(string[] a) {
        var srcMod = ModuleDefMD.Load(a[1]);
        var dstMod = ModuleDefMD.Load(a[2]);
        string outPath = a[3];
        string dumpDir = a[4];
        var importer = new Importer(dstMod);
        curDstMod = dstMod;
        int n = 0;
        for (int k = 5; k + 1 < a.Length; k += 2) {
            string tfull = a[k].Replace('+', '/');
            string mname = StripGeneric(a[k + 1]);
            var srcM = FindMethod(srcMod, tfull, mname);
            if (srcM == null) { Console.WriteLine("[jit] src 未找到: " + tfull + "::" + mname); continue; }
            uint tok = (uint)srcM.MDToken.Raw;
            string tokHex = tok.ToString("X8");
            string binPath = System.IO.Path.Combine(dumpDir, "m_" + tokHex + ".bin");
            if (!System.IO.File.Exists(binPath)) { Console.WriteLine("[jit] dump 无此 token: m_" + tokHex + " (" + tfull + "::" + mname + ")"); continue; }
            var d = System.IO.File.ReadAllBytes(binPath);
            if (d.Length < 24) { Console.WriteLine("[jit] bin 过短: " + tokHex); continue; }
            uint localsTok = BitConverter.ToUInt32(d, 20);
            var body = new byte[d.Length - 24];
            Array.Copy(d, 24, body, 0, body.Length);
            var dstM = FindMethod(dstMod, tfull, mname);
            if (dstM == null) {
                var dstT = FindType(dstMod, tfull);
                if (dstT == null) { Console.WriteLine("[jit] dst 缺类型: " + tfull); continue; }
                var nm = new MethodDefUser(srcM.Name, importer.Import(srcM.MethodSig), srcM.ImplAttributes, srcM.Attributes);
                dstT.Methods.Add(nm);
                dstM = nm;
                Console.WriteLine("[jit] 克隆新方法: " + tfull + "::" + mname);
            }
            try {
                dstM.Body = DecodeRawBody(srcMod, body, localsTok, System.IO.Path.Combine(dumpDir, "m_" + tokHex + ".eh"), importer);
                RebindRefs(dstM, dstMod);
                n++;
                Console.WriteLine("[jit] 恢复: " + tfull + "::" + mname + " (token " + tokHex + ", " + body.Length + "B IL)");
            } catch (Exception ex) { Console.WriteLine("[jit] 解码失败 " + mname + ": " + ex.GetType().Name + ": " + ex.Message); }
        }
        return WriteOut(dstMod, outPath, n);
    }

    static int WriteOut(ModuleDef dstMod, string path, int n) {
        if (n == 0) { Console.WriteLine("[trans] 0 移植 — 无可写内容"); return 2; }
        try {
            var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(dstMod);
            wopt.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
            dstMod.Write(path, wopt);
            Console.WriteLine("[trans] 写出: " + path + " (" + n + " 方法)");
            return 0;
        } catch (Exception ex) {
            Console.WriteLine("[trans] 写盘失败 (降级): " + ex.GetType().Name + ": " + ex.Message);
            try { if (System.IO.File.Exists(path)) System.IO.File.Delete(path); } catch { }
            return 3;
        }
    }

    static System.Collections.Generic.Dictionary<ushort, OpCode> opMapCache;
    static System.Collections.Generic.Dictionary<ushort, OpCode> OpMap() {
        if (opMapCache != null) return opMapCache;
        var d = new System.Collections.Generic.Dictionary<ushort, OpCode>();
        foreach (var f in typeof(OpCodes).GetFields()) {
            if (f.FieldType != typeof(OpCode)) continue;   // 跳过 OpCodes.Values (OpCode[] 数组)
            var op = (OpCode)f.GetValue(null);
            d[(ushort)op.Value] = op;   // dnlib OpCode.Value 是 short
        }
        opMapCache = d;
        return d;
    }

    static CilBody DecodeRawBody(ModuleDefMD srcMod, byte[] il, uint localsTok, string ehPath, Importer importer) {
        var body = new CilBody();
        body.KeepOldMaxStack = true;
        body.MaxStack = 8;
        // 局部变量: StandaloneSig (0x11) token → LocalVarSig → Locals (纯反射, 免类型名依赖)
        if (localsTok != 0 && (localsTok >> 24) == 0x11) {
            try {
                object sig = srcMod.ResolveToken(localsTok);
                while (sig != null) {
                    if (sig.GetType().Name == "LocalVarSig") break;
                    var lvsProp = sig.GetType().GetProperty("LocalVarSig");
                    if (lvsProp == null) { sig = null; break; }
                    sig = lvsProp.GetValue(sig, null);
                }
                if (sig != null) {
                    var locs = sig.GetType().GetProperty("Locals").GetValue(sig, null) as System.Collections.IEnumerable;
                    if (locs != null)
                        foreach (var lv in locs) {
                            var lt = lv.GetType().GetProperty("Type").GetValue(lv, null) as TypeSig;
                            if (lt != null) body.Variables.Add(new Local(importer.Import(lt)));
                        }
                }
            } catch { }
        }
        // 解码指令: 分支/switch 先存绝对偏移, token 先存 uint, 后置两遍修补
        var map = OpMap();
        var instrs = new List<Instruction>();
        var atOffset = new Dictionary<int, Instruction>();
        int pos = 0;
        while (pos < il.Length) {
            int off = pos;
            ushort val = il[pos++];
            if (val == 0xFE) val = (ushort)(0xFE00 | il[pos++]);
            OpCode op;
            if (!map.TryGetValue(val, out op)) throw new Exception("未知操作码 0x" + val.ToString("X4") + " @+" + off);
            var ins = new Instruction(op);
            var ot = op.OperandType;
            if (ot == OperandType.ShortInlineBrTarget) { sbyte rel = (sbyte)il[pos++]; ins.Operand = pos + rel; }
            else if (ot == OperandType.InlineBrTarget) { int rel = BitConverter.ToInt32(il, pos); pos += 4; ins.Operand = pos + rel; }
            else if (ot == OperandType.ShortInlineI) ins.Operand = (sbyte)il[pos++];
            else if (ot == OperandType.ShortInlineVar) ins.Operand = il[pos++];
            else if (ot == OperandType.InlineVar) { ins.Operand = BitConverter.ToUInt16(il, pos); pos += 2; }
            else if (ot == OperandType.InlineI) { ins.Operand = BitConverter.ToInt32(il, pos); pos += 4; }
            else if (ot == OperandType.InlineI8) { ins.Operand = BitConverter.ToInt64(il, pos); pos += 8; }
            else if (ot == OperandType.ShortInlineR) { ins.Operand = BitConverter.ToSingle(il, pos); pos += 4; }
            else if (ot == OperandType.InlineR) { ins.Operand = BitConverter.ToDouble(il, pos); pos += 8; }
            else if (ot == OperandType.InlineString || ot == OperandType.InlineMethod || ot == OperandType.InlineField ||
                     ot == OperandType.InlineType || ot == OperandType.InlineTok || ot == OperandType.InlineSig) {
                ins.Operand = BitConverter.ToUInt32(il, pos); pos += 4;
            }
            else if (ot == OperandType.InlineSwitch) {
                int cnt = BitConverter.ToInt32(il, pos); pos += 4;
                var arr = new int[cnt];
                for (int k = 0; k < cnt; k++) { int rel = BitConverter.ToInt32(il, pos); pos += 4; arr[k] = pos + rel; }
                ins.Operand = arr;
            }
            instrs.Add(ins);
            atOffset[off] = ins;
        }
        foreach (var ins in instrs) body.Instructions.Add(ins);
        // 第二遍: 分支目标 → Instruction; token → 跨基座重绑
        foreach (var ins in instrs) {
            if (ins.Operand is int target) {
                Instruction t;
                if (!atOffset.TryGetValue(target, out t)) throw new Exception("分支目标越界 @" + target);
                ins.Operand = t;
            } else if (ins.Operand is int[] targets) {
                var arr = new Instruction[targets.Length];
                for (int k = 0; k < targets.Length; k++) {
                    Instruction t;
                    if (!atOffset.TryGetValue(targets[k], out t)) throw new Exception("switch 目标越界 @" + targets[k]);
                    arr[k] = t;
                }
                ins.Operand = arr;
            } else if (ins.Operand is uint tok) {
                ins.Operand = ImportToken(srcMod, tok, importer);
            }
        }
        // EH 表 (若 dump 提供)
        if (ehPath != null && System.IO.File.Exists(ehPath)) {
            var eh = System.IO.File.ReadAllBytes(ehPath);
            if (eh.Length >= 4) {
                uint cnt = BitConverter.ToUInt32(eh, 0);
                for (int c = 0; c < cnt && 4 + (c + 1) * 28 <= eh.Length; c++) {
                    int b = 4 + c * 28;
                    uint flags = BitConverter.ToUInt32(eh, b);
                    uint tryOff = BitConverter.ToUInt32(eh, b + 4);
                    uint tryLen = BitConverter.ToUInt32(eh, b + 8);
                    uint hOff = BitConverter.ToUInt32(eh, b + 12);
                    uint hLen = BitConverter.ToUInt32(eh, b + 16);
                    uint clsTok = BitConverter.ToUInt32(eh, b + 20);
                    dnlib.DotNet.Emit.ExceptionHandlerType ht = dnlib.DotNet.Emit.ExceptionHandlerType.Catch;
                    if (flags == 1) ht = dnlib.DotNet.Emit.ExceptionHandlerType.Filter;
                    else if (flags == 2) ht = dnlib.DotNet.Emit.ExceptionHandlerType.Finally;
                    else if (flags == 4) ht = dnlib.DotNet.Emit.ExceptionHandlerType.Fault;
                    var h = new ExceptionHandler(ht);
                    Instruction s;
                    if (atOffset.TryGetValue((int)tryOff, out s)) h.TryStart = s;
                    if (tryLen > 0 && atOffset.TryGetValue((int)(tryOff + tryLen), out s)) h.TryEnd = s;
                    if (atOffset.TryGetValue((int)hOff, out s)) h.HandlerStart = s;
                    if (hLen > 0 && atOffset.TryGetValue((int)(hOff + hLen), out s)) h.HandlerEnd = s;
                    if (ht == dnlib.DotNet.Emit.ExceptionHandlerType.Filter) {
                        if (atOffset.TryGetValue((int)clsTok, out s)) h.FilterStart = s;
                    } else if (clsTok != 0) {
                        var ct = ImportToken(srcMod, clsTok, importer);
                        if (ct is ITypeDefOrRef tdr) h.CatchType = tdr;
                    }
                    body.ExceptionHandlers.Add(h);
                }
            }
        }
        return body;
    }

    // 引用重绑: 跨模块移植产生的 MemberRef 其 Parent TypeRef 带源程序集 ResolutionScope →
    // 运行时解析失败 → InvalidProgramException (v101 轮次11 实证)。重绑到 dst 真实 TypeDef。
    static void RebindRefs(MethodDef dstM, ModuleDef dstMod) {
        int nfix = 0;
        foreach (var ins in dstM.Body.Instructions) {
            var im = ins.Operand as MemberRef;
            if (im != null && im.MethodSig != null) {
                // 只修解析失败的 (能解析的绝不动 — 模糊匹配会选错重载, v104 解密错乱实证)
                bool bad = false;
                try { bad = im.ResolveMethodDef() == null && im.Class is TypeRef; } catch { bad = im.Class is TypeRef; }
                if (!bad) continue;
                var tr = (TypeRef)im.Class;
                var dstT = dstMod.Find(tr.FullName.Replace('+', '/'), false);
                if (dstT != null) {
                    int pc = im.MethodSig.Params.Count;
                    string rsig = im.MethodSig.ToString();
                    var target = dstT.Methods.FirstOrDefault(x => x.Name.String == im.Name.String && x.MethodSig != null &&
                        x.MethodSig.ToString() == rsig);
                    if (target != null) { ins.Operand = target; nfix++; continue; }
                    var target2 = dstT.Methods.FirstOrDefault(x => x.Name.String == im.Name.String && x.MethodSig != null &&
                        x.MethodSig.Params.Count == pc && x.MethodSig.RetType.FullName == im.MethodSig.RetType.FullName);
                    if (target2 != null) { ins.Operand = target2; nfix++; continue; }
                    ins.Operand = new MemberRefUser(dstMod, im.Name, im.MethodSig, dstT);
                    nfix++;
                }
                continue;
            }
            var fi = ins.Operand as MemberRef;
            if (fi != null && fi.FieldSig != null) {
                bool badf = false;
                try { badf = fi.ResolveFieldDef() == null && fi.Class is TypeRef; } catch { badf = fi.Class is TypeRef; }
                if (!badf) continue;
                var ftr = (TypeRef)fi.Class;
                var dstT = dstMod.Find(ftr.FullName.Replace('+', '/'), false);
                if (dstT != null) {
                    var target = dstT.Fields.FirstOrDefault(x => x.Name.String == fi.Name.String);
                    if (target != null) { ins.Operand = target; nfix++; continue; }
                    ins.Operand = new MemberRefUser(dstMod, fi.Name, fi.FieldSig, dstT);
                    nfix++;
                }
            }
        }
        if (nfix > 0) Console.WriteLine("[rbind] 重绑 " + nfix + " 处引用 → dst 真实类型");
    }

    // 通用最小桩体 (按返回类型; Boolean→true 放行校验)
    static void MakeStubBody(MethodDef m) {
        var body = new CilBody();
        body.KeepOldMaxStack = true;
        body.MaxStack = 1;
        var rt = m.ReturnType;
        string rtf = (rt == null ? "System.Void" : rt.FullName);
        Instruction push;
        if (rtf == "System.Boolean") push = Instruction.CreateLdcI4(1);
        else if (rtf == "System.Int32" || rtf == "System.UInt32" || rtf == "System.Int16" || rtf == "System.UInt16" ||
                 rtf == "System.SByte" || rtf == "System.Byte" || rtf == "System.Char")
            push = Instruction.CreateLdcI4(0);
        else if (rtf == "System.Int64" || rtf == "System.UInt64") push = new Instruction(OpCodes.Ldc_I8) { Operand = 0L };
        else if (rtf == "System.Single") push = new Instruction(OpCodes.Ldc_R4) { Operand = 0f };
        else if (rtf == "System.Double") push = new Instruction(OpCodes.Ldc_R8) { Operand = 0.0 };
        else if (rtf != "System.Void") push = new Instruction(OpCodes.Ldnull);
        else push = null;
        if (push != null) body.Instructions.Add(push);
        body.Instructions.Add(new Instruction(OpCodes.Ret));
        m.Body = body;
    }

    // 取或创建全局方法 (缺失 → 按引用签名建桩, 根治悬空 <Module>{MVID} TypeRef)
    static MethodDef GetOrCreateGlobalMethod(ModuleDef dstMod, IMethod proto) {
        var g = dstMod.GlobalType;
        if (g == null) return null;
        foreach (var x in g.Methods) if (x.Name.String == proto.Name.String) return x;
        var nm = new MethodDefUser(proto.Name, proto.MethodSig, dnlib.DotNet.MethodImplAttributes.IL,
            dnlib.DotNet.MethodAttributes.Public | dnlib.DotNet.MethodAttributes.Static);
        MakeStubBody(nm);
        g.Methods.Add(nm);
        Console.WriteLine("[gog] 新建全局桩方法: " + proto.Name.String);
        return nm;
    }
    static FieldDef GetOrCreateGlobalField(ModuleDef dstMod, IField proto) {
        var g = dstMod.GlobalType;
        if (g == null) return null;
        foreach (var x in g.Fields) if (x.Name.String == proto.Name.String) return x;
        var nf = new FieldDefUser(proto.Name,
            new dnlib.DotNet.FieldSig(dstMod.CorLibTypes.Object),
            dnlib.DotNet.FieldAttributes.Public | dnlib.DotNet.FieldAttributes.Static);
        g.Fields.Add(nf);
        Console.WriteLine("[gog] 新建全局桩字段: " + proto.Name.String + " (object 型)");
        return nf;
    }

    // 模块全局成员重定向: src 全局方法/字段 → dst 同名全局成员 (避免 <Module>{MVID} TypeRef 运行时 TypeLoadException)
    static object ImportSmart(ModuleDef dstMod, Importer importer, object op) {
        var im = op as IMethod;
        if (im != null) {
            var md = im.ResolveMethodDef();
            bool isGlobal = md != null && md.DeclaringType != null && md.DeclaringType.IsGlobalModuleType;
            bool parentLooksGlobal = im.DeclaringType != null && !UTF8String.IsNullOrEmpty(im.DeclaringType.Name) &&
                                     im.DeclaringType.Name.String.StartsWith("<Module>");
            if (isGlobal || parentLooksGlobal) {
                var found = GetOrCreateGlobalMethod(dstMod, im);
                if (found != null) return found;
            }
            return importer.Import(im);
        }
        var fi = op as IField;
        if (fi != null) {
            var fd = fi.ResolveFieldDef();
            bool isGlobalF = fd != null && fd.DeclaringType != null && fd.DeclaringType.IsGlobalModuleType;
            bool parentLooksGlobalF = fi.DeclaringType != null && !UTF8String.IsNullOrEmpty(fi.DeclaringType.Name) &&
                                      fi.DeclaringType.Name.String.StartsWith("<Module>");
            if (isGlobalF || parentLooksGlobalF) {
                var found = GetOrCreateGlobalField(dstMod, fi);
                if (found != null) return found;
            }
            return importer.Import(fi);
        }
        return null;
    }

    static object ImportToken(ModuleDefMD srcMod, uint tok, Importer importer) {
        if ((tok >> 24) == 0x70) { // #US 字符串
            try { return srcMod.ReadUserString(tok); } catch { return ""; }
        }
        object res = srcMod.ResolveToken(tok);
        if (res is IMethod im2) return ImportSmart(curDstMod, importer, im2);
        if (res is IField fi2) return ImportSmart(curDstMod, importer, fi2);
        if (res is ITypeDefOrRef tdr) return importer.Import(tdr);
        if (res is TypeSig sig) return importer.Import(sig);
        if (res is MethodSpec ms) return importer.Import(ms);
        if (res is TypeSpec) { var ts = (TypeSpec)res; return importer.Import(ts.TypeSig); }
        throw new Exception("token 无法导入: 0x" + tok.ToString("X8") + " → " + (res == null ? "null" : res.GetType().Name));
    }

    static string StripGeneric(string s) {
        int i = s.IndexOf('['); if (i > 0) return s.Substring(0, i);
        int j = s.IndexOf('<'); if (j > 0) return s.Substring(0, j);
        return s;
    }

    static MethodDef FindMethod(ModuleDefMD mod, string tfull, string mname) {
        var t = FindType(mod, tfull);
        if (t == null) return null;
        foreach (var m in t.Methods)
            if (m.Name == mname) return m;
        return null;
    }
    static dnlib.DotNet.TypeDef FindType(ModuleDefMD mod, string tfull) {
        foreach (var t in mod.GetTypes())
            if (t.FullName == tfull) return t;
        return null;
    }

    // ===== 移植 (同 nbpatch v14 实证版本) =====
    static void TransplantBody(MethodDef dst, MethodDef src, Importer importer) {
        if (src.HasBody && src.Body.Instructions.Count > 60 && src.Body.MaxStack < 128) { }

        var sb = src.Body;
        var body = new CilBody();
        body.InitLocals = sb.InitLocals;
        body.KeepOldMaxStack = true;
        body.MaxStack = sb.MaxStack;
        if (sb.Instructions.Count > 60 && sb.MaxStack < 128) body.MaxStack = 512;   // 移植体 maxstack 防偏小

        var localMap = new Dictionary<Local, Local>();
        foreach (var l in sb.Variables) {
            var nl = new Local(importer.Import(l.Type));
            body.Variables.Add(nl);
            localMap[l] = nl;
        }
        var instrMap = new Dictionary<Instruction, Instruction>();
        foreach (var i in sb.Instructions) {
            var ni = new Instruction(i.OpCode);
            instrMap[i] = ni;
            body.Instructions.Add(ni);
        }
        foreach (var i in sb.Instructions) {
            var ni = instrMap[i];
            var op = i.Operand;
            if (op == null) continue;
            if (op is Instruction t) ni.Operand = instrMap[t];
            else if (op is Instruction[] ts) {
                var arr = new Instruction[ts.Length];
                for (int k = 0; k < ts.Length; k++) arr[k] = instrMap[ts[k]];
                ni.Operand = arr;
            }
            else if (op is Local l2) ni.Operand = localMap[l2];
            else if (op is ITypeDefOrRef tdr) ni.Operand = importer.Import(tdr);
            else if (op is IMethod im) ni.Operand = ImportSmart(curDstMod, importer, im);
            else if (op is IField fi) ni.Operand = ImportSmart(curDstMod, importer, fi);
            else if (op is TypeSig sig) ni.Operand = importer.Import(sig);
            else ni.Operand = op;
        }
        foreach (var eh in sb.ExceptionHandlers) {
            var neh = new ExceptionHandler(eh.HandlerType);
            if (eh.TryStart != null) neh.TryStart = instrMap[eh.TryStart];
            if (eh.TryEnd != null) neh.TryEnd = instrMap[eh.TryEnd];
            if (eh.HandlerStart != null) neh.HandlerStart = instrMap[eh.HandlerStart];
            if (eh.HandlerEnd != null) neh.HandlerEnd = instrMap[eh.HandlerEnd];
            if (eh.FilterStart != null) neh.FilterStart = instrMap[eh.FilterStart];
            if (eh.CatchType != null) neh.CatchType = importer.Import(eh.CatchType);
            body.ExceptionHandlers.Add(neh);
        }
        dst.Body = body;
    }
}
