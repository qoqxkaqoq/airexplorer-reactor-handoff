// nbpatch.cs — v14: 方法体移植术
// 根因链 (v13 铁证): nb_original 的 InstantiateStatelessUser 仅 4 指令 (return null 空壳),
//   而 18KB NecroBit VM 真身在原版 exe (纯托管: 无 DllImport/Marshal, 程序库自内嵌资源装载)。
//   autoreaktor 链把 VM 也"恢复"成了空壳 → 一切 VM 程序 (44/45/~46+) 全断。
// v14 补丁:
//   1.【核心】批量移植: nb_original 所有平凡空壳方法 ← 原版同名方法真身 (指令+局部变量+异常表, token 重映射)
//   2. 资源对齐: 原版有而 nb_original 缺的内嵌资源 → 复制 (VM 程序库 ValidatorAllocator.ValidatorProc /
//      字符串表源 GlobalValidator.FactoryValidator)
//   3. 中和原生引导 (DefineEfficientProfiler, v9 证实挂点) + 反调试 (DefineActiveEvent)
//   4. InstantiateGlobalCalculator 降级最小字段初始化 (lock+assembly)
//   5. 可见性放行: _ExtractorVisitors + modT 状态字段族 (VM 程序跨类型写入)
// 用法: nbpatch <nb_original.exe> <original.exe> <out.exe> <state.json>
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

class NBPatch {
    static int Main(string[] args) {
        if (args.Length < 6) { Console.WriteLine("usage: nbpatch <nb_original> <srcA_jit(e8runnable)> <srcB_cilantro> <out.exe> <state.json> <renames.json>"); return 3; }
        try {
            var mod = ModuleDefMD.Load(args[0]);
            // 全体未触碰方法: 保留旧 maxstack (绕过混淆体的非法栈计算)
            foreach (var t in mod.GetTypes())
                foreach (var m in t.Methods)
                    if (m.HasBody) m.Body.KeepOldMaxStack = true;

            // ===== v23 fixtypes 纯外科模式 =====
            // dst=Hybrid: 原生布局+cctor+912真身完好, 仅3个类型的方法体是内存垃圾体 (JIT InvalidProgram/AV/FieldToken)
            // 从 srcA(=nb_original, Slayer 合成干净桥 IL) 无条件换入, 其余一切不动, 直接写出
            if (args.Length >= 7 && args[6] == "fixtypes") {
                var srcAf = ModuleDefMD.Load(args[1]);
                var impf = new Importer(mod);
                string[] fixTypes = {
                    "CloudClient.Templating.DispatcherInitializer",
                    "CloudClient.Templating.TemplateArgument/TemplateThread", // dnlib 嵌套分隔符是 '/'
                    "CloudClient.Models.StatelessModel"
                };
                foreach (var tfn in fixTypes) {
                    TypeDef dt = null;
                    foreach (var t in mod.GetTypes()) if (t.FullName == tfn || t.ReflectionFullName == tfn) { dt = t; break; }
                    TypeDef st = null;
                    foreach (var t in srcAf.GetTypes()) if (t.FullName == tfn || t.ReflectionFullName == tfn) { st = t; break; }
                    if (dt == null || st == null) { Console.WriteLine("FIXTYPE MISS: " + tfn + " dst=" + (dt != null) + " src=" + (st != null)); continue; }
                    int n = 0;
                    foreach (var dm in dt.Methods) {
                        if (!dm.HasBody || dm.IsConstructor) continue;
                        MethodDef sm = null; int cnt = 0;
                        foreach (var m in st.Methods) {
                            if (m.Name != dm.Name || m.Parameters.Count != dm.Parameters.Count) continue;
                            sm = m; cnt++;
                        }
                        if (cnt != 1 || sm == null || !sm.HasBody) continue;
                        try { TransplantBody(dm, sm, impf); n++; }
                        catch (Exception ex) { Console.WriteLine("  FIX FAIL " + tfn + "::" + dm.Name + ": " + ex.Message); }
                    }
                    Console.WriteLine("FIXTYPE[" + tfn + "]: " + n + " 个方法体换入");
                }
                // ===== v29: 中和原生引导 (v28 ClrMD 挂栈实锤: <Module>.cctor -> DispatcherInitializer.DefineEfficientProfiler 忙转 45s 无窗) =====
                // v15 全模式同款三件套: 反调试中和 + 引导器中和 + 计算器最小字段初始化
                {
                    TypeDef diT29 = null;
                    foreach (var t in mod.GetTypes()) if (t.FullName == "CloudClient.Templating.DispatcherInitializer" || t.ReflectionFullName == "CloudClient.Templating.DispatcherInitializer") { diT29 = t; break; }
                    if (diT29 == null) { Console.WriteLine("v29: DispatcherInitializer NOT FOUND"); }
                    else {
                        var dae29 = diT29.Methods.FirstOrDefault(m => m.Name == "DefineActiveEvent");
                        if (dae29 != null && dae29.HasBody) {
                            var b29a = new CilBody(); b29a.KeepOldMaxStack = false;
                            b29a.Instructions.Add(Instruction.Create(OpCodes.Ret));
                            dae29.Body = b29a;
                            Console.WriteLine("v29: DefineActiveEvent 已中和");
                        } else Console.WriteLine("v29: DefineActiveEvent 未找到/无体");
                        var dep29 = diT29.Methods.FirstOrDefault(m => m.Name == "DefineEfficientProfiler");
                        // v50: 不再中和 — 状态机真跑 (v49 破译: isRecommenderObserver 门控, 530→449 推进/286 轮询)
                        Console.WriteLine("v50: DefineEfficientProfiler 保留真体 (37KB 状态机)");
                        var igc29 = diT29.Methods.FirstOrDefault(m => m.Name == "InstantiateGlobalCalculator");
                        var fLock29 = diT29.Fields.FirstOrDefault(f => f.Name == "templateSpecObj");
                        var fAsm29 = diT29.Fields.FirstOrDefault(f => f.Name == "automatedError");
                        if (igc29 != null && fLock29 != null && fAsm29 != null) {
                            var b29c = new CilBody(); b29c.KeepOldMaxStack = false;
                            b29c.Instructions.Add(Instruction.Create(OpCodes.Newobj, impf.Import(typeof(object).GetConstructor(Type.EmptyTypes))));
                            b29c.Instructions.Add(Instruction.Create(OpCodes.Stsfld, fLock29));
                            b29c.Instructions.Add(Instruction.Create(OpCodes.Call, impf.Import(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly", Type.EmptyTypes))));
                            b29c.Instructions.Add(Instruction.Create(OpCodes.Stsfld, fAsm29));
                            b29c.Instructions.Add(Instruction.Create(OpCodes.Ret));
                            igc29.Body = b29c;
                            Console.WriteLine("v29: InstantiateGlobalCalculator 已重写 (最小字段初始化)");
                        } else Console.WriteLine("v29: InstantiateGlobalCalculator 重写跳过 (igc=" + (igc29 != null) + " fLock29=" + (fLock29 != null) + " fAsm29=" + (fAsm29 != null) + ")");
                    }
                }
                // ===== v30: 中和 <Module>.r6cf 桥链入口 (v29 实测: cctor 过 DefineEfficientProfiler 后下一挂点 r6cf->InstantiateAccessibleProcessor->TemplateThread.GenerateAdaptableExtractor AV; e8runnable 先例: 桥链缺失仍可出窗) =====
                {
                    var gt30 = mod.GetTypes().FirstOrDefault(t => t.FullName.IndexOf("a8c2e9b2", StringComparison.OrdinalIgnoreCase) >= 0);
                    if (gt30 != null) {
                        MethodDef r630 = null;
                        foreach (var mm in gt30.Methods) if (!UTF8String.IsNullOrEmpty(mm.Name) && mm.Name.String.StartsWith("r6cf")) { r630 = mm; break; }
                        if (r630 != null && r630.HasBody) {
                            var b30 = new CilBody(); b30.KeepOldMaxStack = false;
                            b30.Instructions.Add(Instruction.Create(OpCodes.Ret));
                            r630.Body = b30;
                            Console.WriteLine("v30: <Module>." + r630.Name.String + " 已中和 (r6cf 桥链入口)");
                        } else Console.WriteLine("v30: r6cf 方法未找到/无体");
                    } else Console.WriteLine("v30: <Module>{GUID} 类型未找到");
                }
                // v32: 不再提前写出 — 直通全模式 (放行 + renames 回写 + VM 移植 + 批量移植 + 嫁接 + 中和 + 注桩)
            }

            // 1. 定位关键成员
            var ta = mod.GetTypes().FirstOrDefault(t => t.Name == "TemplateArgument");
            if (ta == null) { Console.WriteLine("TemplateArgument NOT FOUND"); return 2; }
            var target = ta.Methods.FirstOrDefault(m => m.Name == "InstantiateStatelessUser");
            if (target == null) { Console.WriteLine("InstantiateStatelessUser NOT FOUND"); return 2; }
            var modT = mod.GetTypes().FirstOrDefault(t => t.FullName.IndexOf("a8c2e9b2", StringComparison.OrdinalIgnoreCase) >= 0);
            if (modT == null) { Console.WriteLine("Module-guid type NOT FOUND"); return 2; }
            var stateField = modT.Fields.FirstOrDefault(f => f.IsStatic && f.Name.Contains("m_0d0b"));
            if (stateField == null) { Console.WriteLine("m_0d0b field NOT FOUND"); return 2; }
            var ctor = modT.FindDefaultConstructor();
            if (ctor == null) { Console.WriteLine("default ctor NOT FOUND"); return 2; }
            var di = mod.GetTypes().FirstOrDefault(t => t.Name == "DispatcherInitializer");
            if (di == null) { Console.WriteLine("DispatcherInitializer NOT FOUND"); return 2; }
            var strField = di.Fields.FirstOrDefault(f => f.Name == "_ExtractorVisitors");
            // 可见性提升: TemplateArgument.InstantiateStatelessUser (跨类型) 需要写这些私有成员
            // (JIT 编译方法体时对任何跨类型私有成员引用都会抛 FieldAccess/MethodAccess — 必须全部放行)
            if (strField != null) {
                strField.Attributes &= ~FieldAttributes.FieldAccessMask;
                strField.Attributes |= FieldAttributes.Public;
                Console.WriteLine("_ExtractorVisitors 已提升为 public");
            }
            if (strField == null) { Console.WriteLine("_ExtractorVisitors NOT FOUND"); return 2; }
            // a) 静态实例字段 m_0d0b
            stateField.Attributes &= ~FieldAttributes.FieldAccessMask;
            stateField.Attributes |= FieldAttributes.Public;
            // b) 全部实例字段 (124 个 int 键)
            int promoted = 0;
            foreach (var f in modT.Fields) {
                if (f.IsStatic) continue;
                f.Attributes &= ~FieldAttributes.FieldAccessMask;
                f.Attributes |= FieldAttributes.Public;
                promoted++;
            }
            // c) 默认构造函数 (newobj 跨类型)
            if (ctor != null) {
                ctor.Attributes &= ~MethodAttributes.MemberAccessMask;
                ctor.Attributes |= MethodAttributes.Public;
            }
            Console.WriteLine("modT 成员放行: stateField + " + promoted + " 实例字段 + ctor");

            // 2. 解析状态 JSON (诊断参考 — v13 起 VM 自装载, 不再依赖)
            var ints = new Dictionary<string, int>();
            foreach (var line in File.ReadAllLines(args[4])) {
                var m = Regex.Match(line, "\"(m_[0-9a-fA-F]+)\"\\s*:\\s*(-?\\d+)");
                if (m.Success) ints[m.Groups[1].Value] = int.Parse(m.Groups[2].Value);
            }
            Console.WriteLine("state ints (诊断参考): " + ints.Count);

            // 3.【v20 双源】srcA = JIT 转储恢复版 (e8runnable, 语义可信), srcB = CILantro 静态恢复版 (兜底)
            var srcA = ModuleDefMD.Load(args[1]);
            var srcMod = ModuleDefMD.Load(args[2]);
            if (target != null && target.HasBody) {
                var ops = string.Join(" | ", target.Body.Instructions.Select(i => i.OpCode.Name.ToString()));
                Console.WriteLine("VM pre-transplant(dst): " + target.Body.Instructions.Count + " instrs: " + ops);
                Action<string, ModuleDef> diagVM = delegate(string tag, ModuleDef src) {
                    TypeDef srcTA = null;
                    foreach (var t in src.GetTypes()) if (t.FullName == ta.FullName) { srcTA = t; break; }
                    if (srcTA == null) { foreach (var t in src.GetTypes()) if (t.Name == "TemplateArgument") { srcTA = t; break; } }
                    Console.WriteLine(tag + " TemplateArgument: " + (srcTA != null ? srcTA.FullName : "NOT FOUND"));
                    if (srcTA != null) {
                        foreach (var m in srcTA.Methods) {
                            if (m.Name != "InstantiateStatelessUser") continue;
                            Console.WriteLine("  " + tag + " VM params=" + m.Parameters.Count
                                + " generic=" + m.GenericParameters.Count + " instrs=" + (m.HasBody ? m.Body.Instructions.Count : -1));
                        }
                    }
                };
                diagVM("srcA(e8jit)", srcA);
                diagVM("srcB(cil)", srcMod);
            } else { Console.WriteLine("WARNING: InstantiateStatelessUser 无方法体!"); return 2; }
            var importer = new Importer(mod);

            // 3a.【v16 核心】CILantro 改名回写: 生成的 Generated* 名 → 原始名 (renames.json 逆向)
            //     CILantro 把混淆名/匿名类型改成 GeneratedEnum_x/GeneratedType_x/generatedField_x,
            //     移植体引用这些名会在 nb_original 中悬空 (v15 崩: TypeLoadException GeneratedEnum_0425)。
            //     逆向改名后 Importer 按原名在 dst 解析, 一切引用自动对齐。
            if (args.Length >= 6 && File.Exists(args[5])) {
                var renText = File.ReadAllText(args[5]);
                var invT = new Dictionary<string, string>();  // genTypeFullName -> origTypeFullName
                var invF = new Dictionary<string, string>();  // "genType::genField" -> origField (名)
                var invM = new Dictionary<string, string>();  // "genType::genMethod" -> origMethod (名)
                foreach (Match m in Regex.Matches(renText, "\"((?:[^\"\\\\]|\\\\.)*)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")) {
                    var k = m.Groups[1].Value; var v = m.Groups[2].Value;
                    // 条目格式: "P:<名> <TYPE>::<名>"  (k=输入/原始侧, v=生成侧)
                    if (k.StartsWith("T:") && v.StartsWith("T:")) {
                        invT[v.Substring(2)] = k.Substring(2);
                    } else if ((k.StartsWith("F:") && v.StartsWith("F:")) || (k.StartsWith("M:") && v.StartsWith("M:"))) {
                        var sp = k.IndexOf(' '); var vd = v.IndexOf(' ') >= 0 ? v.Substring(v.IndexOf(' ') + 1) : v;
                        if (sp >= 0) {
                            var kDesc = k.Substring(sp + 1);  // "origType::origMember"
                            var sepK = kDesc.LastIndexOf("::");
                            if (sepK >= 0) {
                                var origMember = kDesc.Substring(sepK + 2);
                                // 键用生成侧完整描述 "genType::genMember" (查找时当前名即生成名)
                                if (k.StartsWith("F:")) invF[vd] = origMember; else invM[vd] = origMember;
                            }
                        }
                    }
                }
                Console.WriteLine("renames: invT=" + invT.Count + " invF=" + invF.Count + " invM=" + invM.Count);
                // 字段/方法改名回写 (先于类型改名: 查找键用生成名)
                int renF = 0, renM = 0, renT = 0;
                foreach (var t in srcMod.GetTypes()) {
                    foreach (var f in t.Fields) {
                        if (invF.TryGetValue(t.FullName + "::" + f.Name, out var origF)) { f.Name = origF; renF++; }
                    }
                    foreach (var mm in t.Methods) {
                        if (invM.TryGetValue(t.FullName + "::" + mm.Name, out var origM)) { mm.Name = origM; renM++; }
                    }
                }
                // 类型改名回写 (TypeDef 本体)
                foreach (var t in srcMod.GetTypes()) {
                    if (invT.TryGetValue(t.FullName, out var origFull)) {
                        var slash = origFull.LastIndexOf('/');
                        var simple = slash >= 0 ? origFull.Substring(slash + 1)
                            : (origFull.LastIndexOf('.') >= 0 ? origFull.Substring(origFull.LastIndexOf('.') + 1) : origFull);
                        t.Name = simple;
                        if (slash < 0) t.Namespace = origFull.LastIndexOf('.') >= 0 ? origFull.Substring(0, origFull.LastIndexOf('.')) : "";
                        renT++;
                    }
                }
                Console.WriteLine("rename-back(TypeDef): types=" + renT + " fields=" + renF + " methods=" + renM);

                // 引用级回写: TypeRef/MemberRef/MethodSpec (CILantro 重生成的体按名引用自有类型,
                // TypeDef 改名不会传播 — 必须原地改共享引用对象)
                int refsFixed = 0;
                Action<TypeSig> fixSig = null;
                Action<object> fixRef = null;
                fixRef = delegate(object op) {
                    var tr = op as TypeRef;
                    if (tr != null) {
                        if (invT.TryGetValue(tr.FullName, out var origFull)) {
                            var slash = origFull.LastIndexOf('/');
                            if (slash >= 0) { tr.Name = origFull.Substring(slash + 1); }
                            else {
                                var dot = origFull.LastIndexOf('.');
                                if (dot >= 0) { tr.Namespace = origFull.Substring(0, dot); tr.Name = origFull.Substring(dot + 1); }
                                else { tr.Namespace = ""; tr.Name = origFull; }
                            }
                            refsFixed++;
                        }
                        return;
                    }
                    var ms = op as MethodSpec;
                    if (ms != null) { if (fixRef != null) fixRef(ms.Method); return; }
                    if (op is MemberRef mr) {
                        var key = (mr.DeclaringType != null ? mr.DeclaringType.FullName : "") + "::" + mr.Name;
                        fixRef(mr.DeclaringType);
                        if (invF.TryGetValue(key, out var origF)) { mr.Name = origF; refsFixed++; }
                        else if (invM.TryGetValue(key, out var origM)) { mr.Name = origM; refsFixed++; }
                        return;
                    }
                };
                fixSig = delegate(TypeSig sig) {
                    if (sig == null) return;
                    var tdrs = sig as TypeDefOrRefSig;
                    if (tdrs != null) { fixRef(tdrs.TypeDefOrRef); return; }
                    var gis = sig as GenericInstSig;
                    if (gis != null) { fixSig(gis.GenericType); foreach (var a in gis.GenericArguments) fixSig(a); return; }
                    fixSig(sig.Next);
                };
                foreach (var t in srcMod.GetTypes()) {
                    foreach (var mm in t.Methods) {
                        if (!mm.HasBody) continue;
                        foreach (var i in mm.Body.Instructions) fixRef(i.Operand);
                        foreach (var l in mm.Body.Variables) fixSig(l.Type);
                        foreach (var eh in mm.Body.ExceptionHandlers) fixRef(eh.CatchType);
                    }
                }
                Console.WriteLine("rename-back(refs): " + refsFixed);
            } else { Console.WriteLine("renames.json 未提供 (args[5]) — 跳过改名回写"); }

            // ===== v32: VM 本体强制移植 — InstantiateStatelessUser ← srcB(cil) 自装载版 =====
            //      (v31 实证: Hybrid 自有真身走 PlanRunner->GenerateAdaptableExtractor 抛 Exception("AirExplorer") 保护检查;
            //       e8 先例: 换 cilantro 静态恢复的 18KB 自装载 VM 后无需原生引导即可初始化)
            {
                var taV32 = mod.GetTypes().FirstOrDefault(t => t.Name == "TemplateArgument");
                var vmDst32 = taV32 != null ? taV32.Methods.FirstOrDefault(m => m.Name == "InstantiateStatelessUser" && m.HasBody) : null;
                TypeDef taSrc32 = null;
                if (taV32 != null) { foreach (var t in srcMod.GetTypes()) if (t.FullName == taV32.FullName) { taSrc32 = t; break; } }
                if (taSrc32 == null) { foreach (var t in srcMod.GetTypes()) if (t.Name == "TemplateArgument") { taSrc32 = t; break; } }
                var vmSrc32 = taSrc32 != null ? taSrc32.Methods.FirstOrDefault(m => m.Name == "InstantiateStatelessUser" && m.HasBody) : null;
                if (vmDst32 != null && vmSrc32 != null) {
                    try {
                        Console.WriteLine("v32 VM pre: dst=" + vmDst32.Body.Instructions.Count + "i src=" + vmSrc32.Body.Instructions.Count + "i");
                        TransplantBody(vmDst32, vmSrc32, importer);
                        Console.WriteLine("v32: InstantiateStatelessUser 已强制移植 <- cilantro 自装载 VM");
                    } catch (Exception ex) { Console.WriteLine("v32: VM 移植失败: " + ex.Message); }
                } else Console.WriteLine("v32: VM 移植跳过 (dst=" + (vmDst32 != null) + " src=" + (vmSrc32 != null) + ")");
            }

            // 3b.【v20】full 模式: 批量方法体移植 (双源两遍): srcA 优先 → srcB 兜底
            //      匹配规则: 同类型 FullName + 同方法名 + 同参数个数; 门: dst ≤8 指令空壳
            //      第二遍天然只处理仍为空壳的方法 (第一遍移植后方法体变大, 过门条件自动失效)
            var passA = TransplantPass(mod, srcA, importer, "A(e8jit)");
            var passB = TransplantPass(mod, srcMod, importer, "B(cil)");

            // 3d.【v18 核心】缺失类型嫁接: src 有而 dst 无的类型整株克隆
            //     (v17b 崩: TypeLoad URqFYq3xtmntT2OcLub`1 — TemplateArgument 嵌套 lambda 显示类,
            //      原版有但 nb_original 缺 — autoreaktor 合并丢了部分嵌套类型)
            var dstFullNames = new HashSet<string>();
            foreach (var t in mod.GetTypes()) dstFullNames.Add(t.FullName);
            var srcTypeList = new List<TypeDef>();
            foreach (var t in srcMod.GetTypes()) srcTypeList.Add(t);
            int srcMissing = 0, grafted = 0;
            var graftLog = new List<string>();
            // 先统计缺失数, 再按 GetTypes 先序 (父先于嵌套) 逐株嫁接
            foreach (var st in srcTypeList) {
                if (dstFullNames.Contains(st.FullName)) continue;
                srcMissing++;
                try {
                    GraftType(mod, st, importer);
                    grafted++;
                    if (graftLog.Count < 25) graftLog.Add("+ " + st.FullName);
                } catch (Exception ex) {
                    if (graftLog.Count < 25) graftLog.Add("- FAIL " + st.FullName + ": " + ex.Message);
                }
            }
            Console.WriteLine("GRAFT: " + grafted + " / " + srcMissing + " missing (src " + srcTypeList.Count + " / dst " + dstFullNames.Count + ")");
            foreach (var l in graftLog) Console.WriteLine("  " + l);

            // 3c. 资源诊断: 核查 VM 程序库/字符串表源是否在 nb_original 中 (缺失则下轮补复制)
            var dstResNames = new HashSet<string>();
            foreach (var r in mod.Resources) dstResNames.Add(r.Name.ToString());
            Console.WriteLine("RESOURCES: nb_original " + dstResNames.Count + " / 原版 " + srcMod.Resources.Count);
            foreach (var key in new[] { "ValidatorAllocator.ValidatorProc", "GlobalValidator.FactoryValidator" }) {
                bool hasDst = false, hasSrc = false;
                foreach (var r in mod.Resources) if (r.Name.ToString().EndsWith(key)) { hasDst = true; break; }
                foreach (var r in srcMod.Resources) if (r.Name.ToString().EndsWith(key)) { hasSrc = true; break; }
                Console.WriteLine("  资源 " + key + ": nb=" + (hasDst ? "OK" : "MISSING") + " 原版=" + (hasSrc ? "OK" : "MISSING"));
            }

            // 5. 反调试中和: DefineActiveEvent -> ret
            var dae = di.Methods.FirstOrDefault(m => m.Name == "DefineActiveEvent");
            if (dae != null && dae.HasBody) {
                var b2 = new CilBody();
                b2.Instructions.Add(Instruction.Create(OpCodes.Ret));
                b2.KeepOldMaxStack = false;
                dae.Body = b2;
                Console.WriteLine("DefineActiveEvent 已中和");
            }

            // 5b. 原生启动链中和 (追踪证实挂死在 DefineEfficientProfiler 状态机):
            //     恢复版不需要原生引导 (字符串表/状态键已由补丁直供)
            var dep2 = di.Methods.FirstOrDefault(m => m.Name == "DefineEfficientProfiler");
            if (dep2 != null && dep2.HasBody) {
                var b3 = new CilBody();
                b3.KeepOldMaxStack = false;
                b3.Instructions.Add(Instruction.Create(OpCodes.Ret));
                dep2.Body = b3;
                Console.WriteLine("DefineEfficientProfiler 已中和 (原生引导器, 挂点)");
            }
            var igc2 = di.Methods.FirstOrDefault(m => m.Name == "InstantiateGlobalCalculator");
            if (igc2 != null) {
                var fLock = di.Fields.FirstOrDefault(f => f.Name == "templateSpecObj");
                var fAsm = di.Fields.FirstOrDefault(f => f.Name == "automatedError");
                var b4 = new CilBody();
                b4.KeepOldMaxStack = false;
                // templateSpecObj = new object();
                b4.Instructions.Add(Instruction.Create(OpCodes.Newobj, importer.Import(typeof(object).GetConstructor(Type.EmptyTypes))));
                b4.Instructions.Add(Instruction.Create(OpCodes.Stsfld, fLock));
                // automatedError = Assembly.GetExecutingAssembly();
                b4.Instructions.Add(Instruction.Create(OpCodes.Call, importer.Import(typeof(System.Reflection.Assembly).GetMethod("GetExecutingAssembly", Type.EmptyTypes))));
                b4.Instructions.Add(Instruction.Create(OpCodes.Stsfld, fAsm));
                b4.Instructions.Add(Instruction.Create(OpCodes.Ret));
                igc2.Body = b4;
                Console.WriteLine("InstantiateGlobalCalculator 已重写 (字段初始化替代原生引导)");
            }

            // 6. 启动路径追踪注入 (trace.log 定位挂起点)
            var appendAll = importer.Import(typeof(File).GetMethod("AppendAllText", new[] { typeof(string), typeof(string) }));
            Action<MethodDef, string> inject = delegate(MethodDef md, string tag) {
                if (md == null || !md.HasBody) { Console.WriteLine("trace skip: " + tag + " (无方法/无体)"); return; }
                md.Body.KeepOldMaxStack = false;
                md.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, appendAll));
                md.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Ldstr, tag + "\n"));
                md.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Ldstr, "trace.log"));
                Console.WriteLine("trace ok: " + tag + " -> " + md.Name);
            };
            var globalT = mod.GlobalType;
            var r6 = modT.Methods.FirstOrDefault(m => m.Name.String.StartsWith("r6cf"));
            var ep = mod.EntryPoint;
            var ss = di.Methods.FirstOrDefault(m => m.Name == "SearchStrategy");
            var itp = di.Methods.FirstOrDefault(m => m.Name == "InstantiateTransferableProgram");
            var dep = di.Methods.FirstOrDefault(m => m.Name == "DefineEfficientProfiler");
            var igc = di.Methods.FirstOrDefault(m => m.Name == "InstantiateGlobalCalculator");
            var mcct = globalT != null ? globalT.Methods.FirstOrDefault(m => m.IsConstructor && m.IsStatic) : null;
            var gcct = modT.Methods.FirstOrDefault(m => m.IsConstructor && m.IsStatic);
            // VM 本体不注桩 (18KB 混淆控制流, 插桩+重算 maxstack 风险高) — 注入其非泛型包装器
            var ia = ta.Methods.FirstOrDefault(m => m.Name == "InstantiateAccessibleProcessor");
            var dts = ta.Methods.FirstOrDefault(m => m.Name == "DefineTransformableService");
            // v12 NRE 侦查: RequestWorker.WriteRequest (崩溃栈首帧调用者)
            var rw = mod.GetTypes().FirstOrDefault(t => t.Name == "RequestWorker");
            var rwm = rw != null ? rw.Methods.FirstOrDefault(m => m.Name == "WriteRequest") : null;
            inject(mcct, "01-module-cctor");
            inject(dep, "02-di-profiler");
            inject(igc, "03-di-calc");
            inject(gcct, "04-guid-cctor");
            inject(r6, "05-r6cf");
            inject(ia, "06-dispatch");
            inject(dts, "06b-transform");
            inject(ss, "07-searchstrategy");
            inject(itp, "08-str-decrypt");
            inject(ep, "09-entrypoint");
            inject(rwm, "10-requestworker");

            // 7. 写出 (args[2] = out.exe — v14 起第 2 参是原版)
            var opts = new ModuleWriterOptions(mod);
            opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll;

// ===== v34: e8 公式复刻 — 字符串链桩化 (e8 实证: 链为 ret 桩时窗口仍可构造) =====
//      InstantiateTransferableProgram 返回 "" (防空引用), 其余链方法 ret 桩
{
    string[][] stubsV34 = new string[][] {
        new string[] { "CloudClient.Templating.DispatcherInitializer", "InstantiateTransferableProgram" },
        new string[] { "CloudClient.Templating.DispatcherInitializer", "SearchStrategy" },
        new string[] { "CloudClient.Templating.TemplateArgument", "InstantiateStatelessUser" },
        new string[] { "CloudClient.Templating.TemplateArgument/TemplateThread", "PlanRunner" },
        new string[] { "CloudClient.Templating.TemplateArgument/TemplateThread", "GenerateAdaptableExtractor" },
    };
    foreach (var pair34 in stubsV34) {
        TypeDef t34 = null;
        foreach (var t in mod.GetTypes()) { if (t.FullName == pair34[0] || t.ReflectionFullName == pair34[0]) { t34 = t; break; } }
        if (t34 == null) { Console.WriteLine("v34 MISS type: " + pair34[0]); continue; }
        foreach (var dm34 in t34.Methods) {
            if (dm34.Name != pair34[1] || !dm34.HasBody) continue;
            var b34 = new CilBody(); b34.KeepOldMaxStack = false;
            if (dm34.ReturnType != null && dm34.ReturnType.ElementType != dnlib.DotNet.ElementType.Void) {
                // 非空返回类型 -> 压一个默认值: String -> "", 其他 -> null/0
                if (dm34.ReturnType.ElementType == dnlib.DotNet.ElementType.String) {
                    b34.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldstr, ""));
                } else {
                    b34.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldnull));
                }
            }
            b34.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ret));
            dm34.Body = b34;
            Console.WriteLine("v34: " + pair34[1] + " 已桩化 (" + dm34.ReturnType.FullName + ")");
        }
    }

// ===== v35: <Module>.cctor 头部注入 m_0d0b 状态实例 (v34 实证: ArgumentGateway.cctor null.ldfld m_df3c... NRE) =====
//      状态实例本由原生引导创建 (已中和) — 模块 cctor 先于一切托管代码运行, 头部建实例保证非空
{
    var modT35 = mod.GetTypes().FirstOrDefault(t => t.FullName.IndexOf("a8c2e9b2", StringComparison.OrdinalIgnoreCase) >= 0);
    if (modT35 != null) {
        var fState35 = modT35.Fields.FirstOrDefault(f => f.IsStatic && f.Name.String.StartsWith("m_0d0b"));
        var ctor35 = modT35.FindDefaultConstructor();
        var mcct35 = modT35.Methods.FirstOrDefault(x => x.IsConstructor && x.IsStatic && x.HasBody);
        if (fState35 != null && ctor35 != null && mcct35 != null) {
            // v50: 门控标志注入 — isRecommenderObserver=true (原生侧本应置位, 重建体中无人置位 → 永轮询)
            {
                var diT50 = mod.GetTypes().FirstOrDefault(t => t.FullName == "CloudClient.Templating.DispatcherInitializer" || t.ReflectionFullName == "CloudClient.Templating.DispatcherInitializer");
                var fGate50 = diT50 != null ? diT50.Fields.FirstOrDefault(f => f.Name == "isRecommenderObserver") : null;
                if (fGate50 != null) {
                    fGate50.Attributes &= ~FieldAttributes.FieldAccessMask; fGate50.Attributes |= FieldAttributes.Public;
                    mcct35.Body.Instructions.Insert(0, dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldc_I4_1));
                    mcct35.Body.Instructions.Insert(1, dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Stsfld, fGate50));
                    Console.WriteLine("v50: isRecommenderObserver=true 已注入 <Module>.cctor");
                } else Console.WriteLine("v50: isRecommenderObserver 字段未找到");
            }
            mcct35.Body.Instructions.Insert(0, dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Newobj, ctor35));
            mcct35.Body.Instructions.Insert(1, dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Stsfld, fState35));
            mcct35.Body.KeepOldMaxStack = false;
            Console.WriteLine("v35: <Module>.cctor 头部注入 m_0d0b = new modT() (111 键默认0)");
        } else Console.WriteLine("v35: 注入跳过 fState=" + (fState35 != null) + " ctor=" + (ctor35 != null) + " mcct=" + (mcct35 != null));
    } else Console.WriteLine("v35: modT 未找到");
}

// ===== v65: TLS 链中和 — 全模块纯签名扫描 (SecurityProtocol 类型命中即中和; 名字无关) =====
{
    int n65 = 0;
    var seen65 = new System.Collections.Generic.HashSet<MethodDef>();
    foreach (var t65 in mod.GetTypes()) {
        foreach (var m65 in t65.Methods) {
            if (!m65.HasBody) continue;
            bool hit65 = ((string)m65.MethodSig.RetType.TypeName).Contains("SecurityProtocol");
            if (!hit65) { foreach (var p65 in m65.MethodSig.Params) { if (((string)p65.TypeName).Contains("SecurityProtocol")) { hit65 = true; break; } } }
            if (!hit65) continue;
            seen65.Add(m65);
            Console.WriteLine("v65-HIT: " + (string)t65.FullName + "::" + (string)m65.Name + " [" + (string)m65.MethodSig.RetType.TypeName + "(" + string.Join(",", System.Linq.Enumerable.Select(m65.MethodSig.Params, p => (string)p.TypeName)) + ")]");
        }
    }
    foreach (var m65b in seen65) {
        var b65 = new CilBody(); b65.KeepOldMaxStack = false;
        if (m65b.MethodSig.RetType.ElementType != dnlib.DotNet.ElementType.Void) b65.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
        b65.Instructions.Add(Instruction.Create(OpCodes.Ret));
        m65b.Body = b65;
        n65++;
    }
    Console.WriteLine("v65: 共中和 " + n65 + " 个 (签名命中)");
}

// ===== v69: SearchAdapter 语义等价体重写 (v68 实证: ret0 → 进程即退 = 该方法即整个主流程; 重写为成功路径精华) =====
//      路径: ctx = InitializerReg::ValidateDynamicEncryptor(); LiteralContextValidator::ExecuteExplorer(ctx, ResetNotifier) ← UI 启动
{
    var smT69 = mod.GetTypes().FirstOrDefault(t => t.FullName == "CloudClient.Models.StatelessModel" || t.ReflectionFullName == "CloudClient.Models.StatelessModel");
    var sa69 = smT69 != null ? smT69.Methods.FirstOrDefault(m => m.Name == "SearchAdapter") : null;
    if (sa69 == null) { Console.WriteLine("v69: SearchAdapter 未找到"); }
    else {
        // 按签名定位三要素 (名字无关)
        MethodDef mCtx = null, mExec = null; FieldDef fNot = null; FieldDef fArgs = null;
        foreach (var t69 in mod.GetTypes()) {
            foreach (var mm69 in t69.Methods) {
                if (mCtx == null && mm69.MethodSig.Params.Count == 0 && ((string)mm69.MethodSig.RetType.TypeName).Contains("InitializerReg")) mCtx = mm69;
                if (mExec == null && ((string)mm69.Name).Contains("ExecuteExplorer")) {
                    var ps69 = mm69.MethodSig.Params;
                    if (ps69.Count == 2 && ((string)ps69[0].TypeName).Contains("ApplicationContext") && ((string)ps69[1].TypeName).Contains("LiteralContextValidator")) mExec = mm69;
                }
            }
            if (((string)t69.Name) == "LiteralContextValidator") {
                foreach (var f69 in t69.Fields) if (((string)f69.FieldType.TypeName).Contains("LiteralContextValidator")) { fNot = f69; break; }
            }
            if (smT69 != null && t69 == smT69) {
                foreach (var f69 in t69.Fields) if (((string)f69.FieldType.TypeName).Contains("String[]")) { fArgs = f69; break; }
            }
        }
        Console.WriteLine("v69: ctx=" + (mCtx != null ? (string)mCtx.DeclaringType.FullName + "::" + (string)mCtx.Name : "未找到") + " exec=" + (mExec != null ? (string)mExec.DeclaringType.FullName + "::" + (string)mExec.Name : "未找到") + " notifier=" + (fNot != null ? (string)fNot.Name : "未找到") + " argsFld=" + (fArgs != null ? (string)fArgs.Name : "未找到"));
        if (mCtx != null && mExec != null && fNot != null) {
            var b69 = new CilBody(); b69.KeepOldMaxStack = false;
            if (fArgs != null) {
                b69.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
                b69.Instructions.Add(Instruction.Create(OpCodes.Stsfld, fArgs));
            }
            // v72: 从 mExec 的参数签名构造 ApplicationContext::.ctor MemberRef
            IMethod ctorCtx71 = null;
            try {
                var p0_72 = mExec.MethodSig.Params[0];
                dnlib.DotNet.ITypeDefOrRef tdr72 = null;
                if (p0_72 is dnlib.DotNet.ClassOrValueTypeSig) tdr72 = ((dnlib.DotNet.ClassOrValueTypeSig)p0_72).TypeDefOrRef;
                if (tdr72 != null) {
                    var sig72 = MethodSig.CreateInstance(mod.CorLibTypes.Void);
                    ctorCtx71 = new MemberRefUser(mod, ".ctor", sig72, tdr72);
                }
            } catch (Exception ex72) { Console.WriteLine("v72: ctor 构造异常: " + ex72.Message); }
            Console.WriteLine("v71: ApplicationContext ctor = " + (ctorCtx71 != null ? "已定位" : "未找到"));
            // v76: 主窗体直启 (v75b 实证: mainForm=0 独立 Show; 候选 TreeFunction 273B)
            MethodDef mShow76 = null; MethodDef mCtor76 = null; TypeDef tTree76 = null; IMethod showRef77 = null;
            foreach (var t76 in mod.GetTypes()) {
                if (((string)t76.Name) == "TreeFunction" && ((string)t76.Namespace).Contains("DataStructures")) {
                    tTree76 = t76; break;
                }
            }
            if (tTree76 != null) {
                foreach (var mm76 in tTree76.Methods) {
                    if (((string)mm76.Name) == ".ctor" && mm76.MethodSig.Params.Count == 0) mCtor76 = mm76;
                    if (((string)mm76.Name) == "Show" && mm76.MethodSig.Params.Count == 0) mShow76 = mm76;
                }
            }
            // v77c: Show 引用 — 直接构造到 TreeFunction 基类 (Form::Show 无参 void)
            if (mShow76 == null && tTree76 != null && tTree76.BaseType != null) {
                var sig77 = MethodSig.CreateInstance(mod.CorLibTypes.Void);
                showRef77 = new MemberRefUser(mod, "Show", sig77, tTree76.BaseType);
            }
            Console.WriteLine("v76: TreeFunction=" + (tTree76 != null) + " ctor=" + (mCtor76 != null) + " show=" + (mShow76 != null) + " showRef=" + (showRef77 != null));
            if (mCtor76 != null && (mShow76 != null || showRef77 != null)) {
                b69.Instructions.Add(Instruction.Create(OpCodes.Newobj, mCtor76));
                b69.Instructions.Add(Instruction.Create(OpCodes.Callvirt, showRef77 != null ? showRef77 : (IMethod)mShow76));
                // Application.Run() — 从 mExec 所在类型找? 不 — 用 ExecutionContext? 简化: ExecuteExplorer(ctx,notifier) 已跑消息循环, Show 只需窗体注册
                // 稳妥: 仍走 ExecuteExplorer 链 (消息循环) + Show 窗体
                b69.Instructions.Add(Instruction.Create(OpCodes.Newobj, ctorCtx71));
                b69.Instructions.Add(Instruction.Create(OpCodes.Ldsfld, fNot));
                b69.Instructions.Add(Instruction.Create(OpCodes.Call, mExec));
            } else {
                b69.Instructions.Add(Instruction.Create(OpCodes.Newobj, ctorCtx71));
                b69.Instructions.Add(Instruction.Create(OpCodes.Ldsfld, fNot));
                b69.Instructions.Add(Instruction.Create(OpCodes.Call, mExec));
            }
            b69.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4_0));
            b69.Instructions.Add(Instruction.Create(OpCodes.Ret));
            sa69.Body = b69;
            Console.WriteLine("v69: SearchAdapter 已重写 (语义等价 5 指令)");
        } else Console.WriteLine("v69: 三要素不全, 保留原体");
    }
}

// ===== v78: 资源解析链中和 (v77c 崩溃链: 资源名解密为空 → GetManifestResourceStream("") ArgumentException) =====
{
    foreach (var t78 in mod.GetTypes()) {
        if (((string)t78.Name) != "WrapperProvider") continue;
        foreach (var m78 in t78.Methods) {
            var nm78 = (string)m78.Name;
            if (nm78 == "EncapsulateMixedDispatcher" || nm78 == "WrapCommonSorter" || nm78 == "VerifySortedConfiguration") {
                var b78 = new CilBody(); b78.KeepOldMaxStack = false;
                if (m78.MethodSig.RetType.ElementType != dnlib.DotNet.ElementType.Void) b78.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
                b78.Instructions.Add(Instruction.Create(OpCodes.Ret));
                m78.Body = b78;
                Console.WriteLine("v78: WrapperProvider::" + nm78 + " 已中和 (ret " + (m78.MethodSig.RetType.ElementType != dnlib.DotNet.ElementType.Void ? "null" : "void") + ")");
            }
        }
    }
}

// ===== v79: 资源读取包装器中和 (v78 崩溃链: TagReg→StoreGenericSchema→AccessibleCalculatorValidator::ExecuteExplorer→ResourceManager 崩) =====
{
    foreach (var t79 in mod.GetTypes()) {
        if (((string)t79.Name) != "AccessibleCalculatorValidator") continue;
        foreach (var m79 in t79.Methods) {
            if (((string)m79.Name) != "ExecuteExplorer") continue;
            var ps79 = m79.MethodSig.Params;
            if (ps79.Count != 3) continue;
            if (ps79[0].ElementType != dnlib.DotNet.ElementType.Object) continue;
            var b79 = new CilBody(); b79.KeepOldMaxStack = false;
            if (m79.MethodSig.RetType.ElementType != dnlib.DotNet.ElementType.Void) b79.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            b79.Instructions.Add(Instruction.Create(OpCodes.Ret));
            m79.Body = b79;
            Console.WriteLine("v79: AccessibleCalculatorValidator::ExecuteExplorer(3参) 已中和 (资源读取)");
        }
    }
}

// ===== v80: TagReg 构造器桩化 (v79 实证: 崩链 [TagReg.ctor→StoreGenericSchema→ImageList], 整个构造链为资源装载层) =====
{
    foreach (var t80 in mod.GetTypes()) {
        if (((string)t80.Name) != "TagReg") continue;
        foreach (var m80 in t80.Methods) {
            if (((string)m80.Name) == ".ctor" && m80.MethodSig.Params.Count == 0) {
                var b80 = new CilBody(); b80.KeepOldMaxStack = false;
                b80.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
                var bt80 = t80.BaseType;
                IMethod baseCtor80 = null;
                if (bt80 != null) {
                    foreach (var mm80 in t80.Methods) { }
                    // 基类 ctor 引用: 构造 MemberRef
                    var sig80 = MethodSig.CreateInstance(mod.CorLibTypes.Void);
                    baseCtor80 = new MemberRefUser(mod, ".ctor", sig80, bt80);
                }
                if (baseCtor80 != null) b80.Instructions.Add(Instruction.Create(OpCodes.Call, baseCtor80));
                b80.Instructions.Add(Instruction.Create(OpCodes.Ret));
                m80.Body = b80;
                Console.WriteLine("v80: TagReg::.ctor 已桩化 (基类链保留)");
            }
        }
    }
}

// ===== v81: 资源重命名 (v80 崩溃链: get_sync16x16 → "CloudClient.Properties.Resources.resources" 未找到; 2.3MB 图像 blob 对号) =====
{
    int n81 = 0;
    foreach (var r81 in mod.Resources) {
        var nm81 = (string)r81.Name;
        var tgt81 = "";
        if (nm81 == "ValidatorGenerator.DefinitionError") tgt81 = "CloudClient.Properties.Resources.resources";   // 2.3MB 图像
        else if (nm81 == "ErrorReceiver.ValidatorViewer") tgt81 = "CloudClient.Properties.Resources.resources";     // 备选 (两者择一生效即可)
        if (tgt81 != "") {
            if (mod.Resources.Count(x => (string)x.Name == tgt81) == 0) {
                r81.Name = tgt81;
                n81++;
                Console.WriteLine("v81: 资源 " + nm81 + " → " + tgt81);
            }
        }
    }
    // 保底: 若一个都没改成, 任意一个改名
    if (n81 == 0 && mod.Resources.Count > 0) {
        mod.Resources[0].Name = "CloudClient.Properties.Resources.resources";
        Console.WriteLine("v81: 兜底重命名 " + (string)mod.Resources[0].Name);
    }
}

// ===== v82: TreeFunction 构造器最小化 (v81b 实证: 资源为 Reactor 加密格式, 标准读取必败; 先出空白窗) =====
{
    foreach (var t82 in mod.GetTypes()) {
        if (((string)t82.Name) != "TreeFunction") continue;
        foreach (var m82 in t82.Methods) {
            if (((string)m82.Name) == ".ctor" && m82.MethodSig.Params.Count == 0) {
                var b82 = new CilBody(); b82.KeepOldMaxStack = false;
                b82.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
                IMethod baseCtor82 = null;
                if (t82.BaseType != null) {
                    var sig82 = MethodSig.CreateInstance(mod.CorLibTypes.Void);
                    baseCtor82 = new MemberRefUser(mod, ".ctor", sig82, t82.BaseType);
                }
                if (baseCtor82 != null) b82.Instructions.Add(Instruction.Create(OpCodes.Call, baseCtor82));
                // v83: 标题设置 (v82 已出窗 262250; 加 Text)
                if (t82.BaseType != null) {
                    var sig83 = MethodSig.CreateInstance(mod.CorLibTypes.Void, mod.CorLibTypes.String);
                    var setTxt83 = new MemberRefUser(mod, "set_Text", sig83, t82.BaseType);
                    b82.Instructions.Add(Instruction.Create(OpCodes.Ldarg_0));
                    b82.Instructions.Add(new Instruction(OpCodes.Ldstr, "Air Explorer v5.11.0"));
                    b82.Instructions.Add(Instruction.Create(OpCodes.Callvirt, setTxt83));
                }
                b82.Instructions.Add(Instruction.Create(OpCodes.Ret));
                m82.Body = b82;
                Console.WriteLine("v82: TreeFunction::.ctor 已最小化 (基类链+Text+ret)");
            }
        }
    }
}

// ===== v67: 全模块 NoInlining (v65/66 挂栈仅 SearchAdapter 单帧 = JIT 内联吞帧; 关内联让挂栈露真) =====
{
    int n67 = 0;
    foreach (var t67 in mod.GetTypes()) {
        foreach (var m67 in t67.Methods) {
            try {
                m67.ImplAttributes &= ~MethodImplAttributes.AggressiveInlining;
                m67.ImplAttributes |= MethodImplAttributes.NoInlining;
                n67++;
            } catch { }
        }
    }
    Console.WriteLine("v67: NoInlining 已设于 " + n67 + " 个方法 (诊断通道)");
}

// ===== v36: e8 桩对齐 (e8 实证: EvaluateVisibleAttribute 等为 ret 桩时窗口仍出) =====
{
    string[][] stubsV36 = new string[][] {
        new string[] { "AirExplorer.Values.ArgumentGateway", "EvaluateVisibleAttribute" },
        new string[] { "CloudClient.Templating.TemplateInitializer", "DefineTransferableRecord" },
        new string[] { "CloudClient.Templating.TemplateInitializer", "InstantiateRandomIterator" },
        new string[] { "CloudClient.Templating.TemplateInitializer", "InstantiateSeparatedChooser" },
        new string[] { "AirExplorer.Networking.RequestWorker", "WriteRequest" },
        new string[] { "AirExplorer.Processing.AggregatorLogger", "ParseFlexibleAuthorizer" },
        new string[] { "AirExplorer.Values.ArgumentGateway", "UpdateState" },  // e8 同款: ldc.i4.1; ret (返回 true)
    };
    foreach (var pair36 in stubsV36) {
        TypeDef t36 = null;
        foreach (var t in mod.GetTypes()) { if (t.FullName == pair36[0] || t.ReflectionFullName == pair36[0]) { t36 = t; break; } }
        if (t36 == null) { Console.WriteLine("v36 MISS type: " + pair36[0]); continue; }
        foreach (var dm36 in t36.Methods) {
            if (dm36.Name != pair36[1] || !dm36.HasBody) continue;
            var b36 = new CilBody(); b36.KeepOldMaxStack = false;
            var et36 = dm36.ReturnType.ElementType;
            if (et36 == dnlib.DotNet.ElementType.Boolean || (et36 >= dnlib.DotNet.ElementType.I1 && et36 <= dnlib.DotNet.ElementType.U4) || et36 == dnlib.DotNet.ElementType.Char) {
                bool wantTrue36 = (dm36.Name == "UpdateState");
                b36.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(wantTrue36 ? dnlib.DotNet.Emit.OpCodes.Ldc_I4_1 : dnlib.DotNet.Emit.OpCodes.Ldc_I4_0));
            } else if (et36 == dnlib.DotNet.ElementType.I8 || et36 == dnlib.DotNet.ElementType.U8) {
                b36.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldc_I8, 0L));
            } else if (et36 == dnlib.DotNet.ElementType.R4) {
                b36.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldc_R4, 0f));
            } else if (et36 == dnlib.DotNet.ElementType.R8) {
                b36.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldc_R8, 0.0));
            } else if (et36 != dnlib.DotNet.ElementType.Void) {
                b36.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldnull));
            }
            b36.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ret));
            dm36.Body = b36;
            Console.WriteLine("v36: " + pair36[1] + " 已桩化 (e8 对齐, 返回 " + dm36.ReturnType.FullName + ")");
        }
    }
}
}

// ===== v39: 真字符串直供 (收割自原版运行态 strings.json, 整体重写 ArgumentGateway.cctor) =====
if (args.Length >= 8 && File.Exists(args[7])) {
    var sv39 = new System.Collections.Generic.Dictionary<string, string>();
    foreach (var line39 in File.ReadAllLines(args[7])) {
        var mm39 = Regex.Match(line39, "^\\s*\"([^\"]+)::([^\"]+)\"\\s*:\\s*\"(.*)\",\\s*$");
        if (mm39.Success) sv39[mm39.Groups[1].Value + "::" + mm39.Groups[2].Value] = Regex.Unescape(mm39.Groups[3].Value);
    }
    Console.WriteLine("v39: 收割字符串 " + sv39.Count + " 条");
    var byType39 = new System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<string[]>>();
    foreach (var kv39 in sv39) {
        var p39 = kv39.Key.Split(new string[]{"::"}, StringSplitOptions.None);
        if (p39.Length != 2) continue;
        if (!byType39.ContainsKey(p39[0])) byType39[p39[0]] = new System.Collections.Generic.List<string[]>();
        byType39[p39[0]].Add(new string[]{ p39[1], kv39.Value });
    }
    int injected39 = 0;
    foreach (var bt39 in byType39) {
        bool safeReplace39 = (bt39.Key == "AirExplorer.Values.ArgumentGateway");
        TypeDef t39 = null;
        foreach (var t in mod.GetTypes()) { if (t.FullName == bt39.Key || t.ReflectionFullName == bt39.Key) { t39 = t; break; } }
        if (t39 == null) { Console.WriteLine("v39: 类型未找到 " + bt39.Key); continue; }
        var c39 = t39.Methods.FirstOrDefault(x => x.IsConstructor && x.IsStatic && x.HasBody);
        if (c39 == null) { Console.WriteLine("v39: " + bt39.Key + " 无 cctor"); continue; }
        if (!safeReplace39) { Console.WriteLine("v39: 跳过(非白名单) " + bt39.Key + " " + bt39.Value.Count + " 条"); continue; }
        var b39 = new CilBody(); b39.KeepOldMaxStack = false;
        foreach (var pair39 in bt39.Value) {
            var f39 = t39.Fields.FirstOrDefault(x => x.Name == pair39[0] && x.IsStatic);
            if (f39 == null) { Console.WriteLine("v39: 字段未找到 " + pair39[0]); continue; }
            b39.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldstr, pair39[1]));
            b39.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Stsfld, f39));
            injected39++;
        }
        b39.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ret));
        c39.Body = b39;
        Console.WriteLine("v39: " + bt39.Key + ".cctor 已重写 (ldstr 直供)");
    }
    Console.WriteLine("v39: 共注入 " + injected39 + " 个字符串字段");
} else Console.WriteLine("v39: strings.json 未提供 (args[7])");

// ===== v45: 键→串查表直供 — InstantiateTransferableProgram 重写为编译期查表 =====
//      键全集来自 state.json 收割 (125 个运行时真键), 串来自对原版的反射收割
if (args.Length >= 10 && File.Exists(args[9])) {
    var diT45 = mod.GetTypes().FirstOrDefault(t => t.Name == "DispatcherInitializer");
    var itp45 = diT45 != null ? diT45.Methods.FirstOrDefault(m => m.Name == "InstantiateTransferableProgram" && m.HasBody) : null;
    if (itp45 == null) { Console.WriteLine("v45: InstantiateTransferableProgram 未找到"); }
    else {
        var b45 = new CilBody(); b45.KeepOldMaxStack = false;
        var jumps45 = new System.Collections.Generic.List<dnlib.DotNet.Emit.Instruction>();
        int n45 = 0;
        foreach (var ln45 in File.ReadAllLines(args[9])) {
            var t45 = ln45.Split('\t');
            if (t45.Length != 2) continue;
            int k45; if (!int.TryParse(t45[0].Trim(), out k45)) continue;
            var s45 = t45[1].Replace("\\t", "\t").Replace("\\n", "\n").Replace("\\r", "\r").Replace("\\\\", "\\");
            b45.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldarg_0));
            b45.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldc_I4, k45));
            var br45 = dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Bne_Un, (dnlib.DotNet.Emit.Instruction)null);
            b45.Instructions.Add(br45);
            jumps45.Add(br45);
            b45.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldstr, s45));
            b45.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ret));
            n45++;
        }
        var defA45 = dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldstr, "");
        var defR45 = dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ret);
        b45.Instructions.Add(defA45);
        b45.Instructions.Add(defR45);
        foreach (var j45 in jumps45) j45.Operand = defA45;
        itp45.Body = b45;
        Console.WriteLine("v45: InstantiateTransferableProgram 已重写为查表 (" + n45 + " 键)");
    }
} else Console.WriteLine("v45: keystrings.tsv 未提供 (args[9])");

// ===== v43: 对象图重建 — objects.tsv (args[8]) → v43Init, 由 <Module>.cctor 头部调用 =====
if (args.Length >= 9 && File.Exists(args[8])) {
    var statics43 = new System.Collections.Generic.List<string[]>();   // type, field, objId
    var objects43 = new System.Collections.Generic.Dictionary<string, string[]>(); // objId -> [type, parentObjId, parentField]
    var fields43 = new System.Collections.Generic.List<string[]>();    // objId, fieldName, kind, value
    foreach (var ln43 in File.ReadAllLines(args[8])) {
        if (string.IsNullOrEmpty(ln43)) continue;
        var p43 = ln43.Split('\t');
        if (p43.Length < 4) continue;
        if (p43[0] == "S") statics43.Add(new string[]{ p43[1], p43[2], p43[3] });
        else if (p43[0] == "O" && p43.Length >= 5) objects43[p43[1]] = new string[]{ p43[2], p43[3], p43[4] };
        else if (p43[0] == "F" && p43.Length >= 5) fields43.Add(new string[]{ p43[1], p43[2], p43[3], p43[4] });
    }
    Console.WriteLine("v43: 对象图 S=" + statics43.Count + " O=" + objects43.Count + " F=" + fields43.Count);
    Func<string, TypeDef> tdef43 = delegate(string fullName) {
        foreach (var t in mod.GetTypes()) { if (t.FullName == fullName || t.ReflectionFullName == fullName) return t; }
        return null;
    };
    var objTypes43 = new System.Collections.Generic.Dictionary<string, TypeDef>();
    var objCtors43 = new System.Collections.Generic.Dictionary<string, MethodDef>();
    foreach (var kv43 in objects43) {
        var td43 = tdef43(kv43.Value[0]);
        if (td43 == null) { Console.WriteLine("v43: 类型未找到 " + kv43.Value[0]); continue; }
        var ct43 = td43.FindDefaultConstructor();
        if (ct43 == null) { Console.WriteLine("v43: 无参 ctor 缺 " + kv43.Value[0]); continue; }
        objTypes43[kv43.Key] = td43; objCtors43[kv43.Key] = ct43;
        foreach (var ff43 in td43.Fields) { ff43.Attributes &= ~FieldAttributes.FieldAccessMask; ff43.Attributes |= FieldAttributes.Public; }
        ct43.Attributes &= ~MethodAttributes.MemberAccessMask; ct43.Attributes |= MethodAttributes.Public;
    }
    Console.WriteLine("v43: 可构造对象 " + objCtors43.Count + "/" + objects43.Count);
    var modT43 = mod.GetTypes().FirstOrDefault(t => t.FullName.IndexOf("a8c2e9b2", StringComparison.OrdinalIgnoreCase) >= 0);
    if (modT43 != null && objCtors43.Count > 0) {
        var m43 = new MethodDefUser("v43Init", MethodSig.CreateStatic(mod.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static);
        modT43.Methods.Add(m43);
        // 静态字段放行
        foreach (var s43 in statics43) {
            var tdS43 = tdef43(s43[0]);
            var sf43 = tdS43 != null ? tdS43.Fields.FirstOrDefault(x => x.Name == s43[1] && x.IsStatic) : null;
            if (sf43 != null) { sf43.Attributes &= ~FieldAttributes.FieldAccessMask; sf43.Attributes |= FieldAttributes.Public; }
        }
        Action<string> emitAddr43 = null;
        emitAddr43 = delegate(string objId43) {
            var meta43 = objects43[objId43];
            if (meta43[1] == "") {
                FieldDef sf43 = null;
                foreach (var s43 in statics43) if (s43[2] == objId43) { var tdS43 = tdef43(s43[0]); if (tdS43 != null) sf43 = tdS43.Fields.FirstOrDefault(x => x.Name == s43[1] && x.IsStatic); break; }
                if (sf43 == null) throw new Exception("v43 静态字段缺失 " + objId43);
                m43.Body.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldsfld, sf43));
                return;
            }
            emitAddr43(meta43[1]);
            var ptd43 = objTypes43.ContainsKey(meta43[1]) ? objTypes43[meta43[1]] : null;
            FieldDef pf43 = ptd43 != null ? ptd43.Fields.FirstOrDefault(x => x.Name == meta43[2]) : null;
            if (pf43 == null) throw new Exception("v43 父字段缺失 " + meta43[1] + "::" + meta43[2]);
            m43.Body.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldfld, pf43));
        };
        // 1) 全部对象构造 (根静态 + 嵌套)
        foreach (var kv43 in objects43) {
            if (!objCtors43.ContainsKey(kv43.Key)) continue;
            var meta43 = kv43.Value;
            if (meta43[1] == "") {
                FieldDef sf43 = null;
                foreach (var s43 in statics43) if (s43[2] == kv43.Key) { var tdS43 = tdef43(s43[0]); if (tdS43 != null) sf43 = tdS43.Fields.FirstOrDefault(x => x.Name == s43[1] && x.IsStatic); break; }
                if (sf43 == null) continue;
                m43.Body.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Newobj, objCtors43[kv43.Key]));
                m43.Body.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Stsfld, sf43));
            } else {
                var ptd43 = objTypes43.ContainsKey(meta43[1]) ? objTypes43[meta43[1]] : null;
                FieldDef pf43 = ptd43 != null ? ptd43.Fields.FirstOrDefault(x => x.Name == meta43[2]) : null;
                if (ptd43 == null || pf43 == null) continue;
                try { emitAddr43(meta43[1]); } catch (Exception e43) { Console.WriteLine("v43: " + e43.Message); continue; }
                m43.Body.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Newobj, objCtors43[kv43.Key]));
                m43.Body.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Stfld, pf43));
            }
        }
        // 2) 字段赋值 [addr][value][stfld]
        int nSet43 = 0;
        foreach (var f43 in fields43) {
            var objId43 = f43[0];
            if (!objTypes43.ContainsKey(objId43)) continue;
            var fd43 = objTypes43[objId43].Fields.FirstOrDefault(x => x.Name == f43[1]);
            if (fd43 == null) continue;
            var kind43 = f43[2]; var val43 = f43[3];
            if (kind43 == "skip") continue;
            try { emitAddr43(objId43); } catch (Exception e43) { continue; }
            try {
                if (kind43 == "obj") { emitAddr43(val43); }
                else if (kind43 == "null") m43.Body.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldnull));
                else if (kind43 == "str") m43.Body.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldstr, val43.Replace("\\t", "\t").Replace("\\n", "\n").Replace("\\r", "\r").Replace("\\\\", "\\")));
                else if (kind43 == "i4" || kind43 == "b1") { int iv43; if (!int.TryParse(val43, out iv43)) throw new Exception("parse"); m43.Body.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldc_I4, iv43)); }
                else if (kind43 == "i8") { long lv43; if (!long.TryParse(val43.TrimEnd('L'), out lv43)) throw new Exception("parse"); m43.Body.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ldc_I8, lv43)); }
                else throw new Exception("kind " + kind43);
                m43.Body.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Stfld, fd43));
                nSet43++;
            } catch (Exception) { m43.Body.Instructions.RemoveAt(m43.Body.Instructions.Count - 1); }
        }
        m43.Body.Instructions.Add(dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Ret));
        m43.Body.KeepOldMaxStack = false;
        Console.WriteLine("v43: v43Init 生成, 赋值 " + nSet43 + " 字段");
        var mcct43 = modT43.Methods.FirstOrDefault(x => x.IsConstructor && x.IsStatic && x.HasBody);
        if (mcct43 != null) {
            mcct43.Body.Instructions.Insert(0, dnlib.DotNet.Emit.Instruction.Create(dnlib.DotNet.Emit.OpCodes.Call, m43));
            Console.WriteLine("v43: v43Init 已挂接 <Module>.cctor 头部");
        }
    } else Console.WriteLine("v43: modT 未找到或无可构造对象");
} else Console.WriteLine("v43: objects.tsv 未提供 (args[8])");
            mod.Write(args[3], opts);
            Console.WriteLine("PATCHED -> " + args[3]);
            return 0;
        } catch (Exception e) {
            Console.WriteLine("PATCH FAIL: " + e);
            return 1;
        }
    }

    // 批量方法体移植一遍: dst ≤8 指令空壳 ← src 同名真身 (名字+参数数匹配)
    static List<string> TransplantPass(ModuleDef dst, ModuleDef src, Importer importer, string tag) {
        int transplanted = 0, ambig = 0, notfound = 0, toosmall = 0, gate = 0;
        var transLog = new List<string>();
        foreach (var dt in dst.GetTypes()) {
            TypeDef st = null;
            foreach (var t in src.GetTypes()) if (t.FullName == dt.FullName) { st = t; break; }
            if (st == null) continue;
            foreach (var dm in dt.Methods) {
                if (!dm.HasBody) continue;
                if (dm.Body.Instructions.Count > 8) { gate++; continue; }
                MethodDef sm = null; int cnt = 0;
                foreach (var m in st.Methods) {
                    if (m.Name != dm.Name) continue;
                    if (m.Parameters.Count != dm.Parameters.Count) continue;
                    sm = m; cnt++;
                }
                if (cnt > 1) { ambig++; continue; }
                if (sm == null || !sm.HasBody) { notfound++; continue; }
                if (sm.Body.Instructions.Count < dm.Body.Instructions.Count + 5) { toosmall++; continue; }
                try {
                    TransplantBody(dm, sm, importer);
                    transplanted++;
                    if (transLog.Count < 30) transLog.Add("+ " + dt.Name + "::" + dm.Name + " <- " + sm.Body.Instructions.Count + "i");
                } catch (Exception ex) {
                    if (transLog.Count < 30) transLog.Add("- FAIL " + dt.Name + "::" + dm.Name + ": " + ex.Message);
                }
            }
        }
        Console.WriteLine("TRANSPLANT[" + tag + "]: " + transplanted + " (gate=" + gate + " ambig=" + ambig + " notfound=" + notfound + " toosmall=" + toosmall + ")");
        foreach (var l in transLog) Console.WriteLine("  " + l);
        return transLog;
    }

    // 类型整株嫁接: src TypeDef → dst (含泛型参数/字段/方法体; 嵌套挂到 dst 同名父)
    //   依赖 srcMod.GetTypes() 先序: 父类型先于嵌套类型处理
    //   (dnlib 惯例: 抽象 TypeDef/MethodDef/FieldDef → 用 TypeDefUser/MethodDefUser/FieldDefUser 实例化)
    static void GraftType(ModuleDef dstMod, TypeDef st, Importer importer) {
        var nt = new TypeDefUser(st.Name);
        if (!st.IsNested) nt.Namespace = st.Namespace;
        if (st.BaseType != null) nt.BaseType = importer.Import(st.BaseType);
        nt.Attributes = st.Attributes;
        if (st.IsNested) {
            var parentFull = st.DeclaringType.FullName;
            TypeDef parent = null;
            foreach (var t in dstMod.GetTypes()) if (t.FullName == parentFull) { parent = t; break; }
            if (parent == null) throw new Exception("parent missing: " + parentFull);
            parent.NestedTypes.Add(nt);
        } else {
            dstMod.Types.Add(nt);
        }
        foreach (var gp in st.GenericParameters) nt.GenericParameters.Add(new GenericParamUser(gp.Number, (GenericParamAttributes)0, gp.Name));
        foreach (var sf in st.Fields) {
            var nf = new FieldDefUser(sf.Name, new FieldSig(importer.Import(sf.FieldType)), sf.Attributes);
            nt.Fields.Add(nf);
        }
        foreach (var sm in st.Methods) {
            var srcSig = sm.Signature as MethodSig;
            if (srcSig == null) throw new Exception("方法签名非 MethodSig: " + st.FullName + "::" + sm.Name);
            var sig = srcSig.HasThis ? MethodSig.CreateInstance(importer.Import(srcSig.RetType))
                                     : MethodSig.CreateStatic(importer.Import(srcSig.RetType));
            foreach (var p in srcSig.Params) sig.Params.Add(importer.Import(p));
            if (srcSig.GenParamCount > 0) sig.GenParamCount = srcSig.GenParamCount;
            var nm = new MethodDefUser(sm.Name, sig, sm.ImplAttributes, sm.Attributes);
            foreach (var gp in sm.GenericParameters) nm.GenericParameters.Add(new GenericParamUser(gp.Number, (GenericParamAttributes)0, gp.Name));
            nt.Methods.Add(nm);
            if (sm.HasBody) TransplantBody(nm, sm, importer);
        }
    }

    // 平凡空壳判定: ≤6 指令且全为 nop/ret/pop/ldnull/ldarg 族
    static bool IsTrivialStub(MethodDef m) {
        var instrs = m.Body.Instructions;
        if (instrs.Count == 0) return true;
        foreach (var i in instrs) {
            var c = i.OpCode.Code;
            if (c == Code.Nop || c == Code.Ret || c == Code.Pop || c == Code.Ldnull) continue;
            if (c == Code.Ldarg_0 || c == Code.Ldarg_1 || c == Code.Ldarg_2 || c == Code.Ldarg_3) continue;
            if (c == Code.Ldarg_S || c == Code.Ldarg) continue;
            return false;
        }
        return true;
    }

    // 方法体移植: src (原版) → dst (nb_original), 指令克隆 + token/局部变量/异常表重映射
    static void TransplantBody(MethodDef dst, MethodDef src, Importer importer) {
        var sb = src.Body;
        var body = new CilBody();
        body.InitLocals = sb.InitLocals;
        body.KeepOldMaxStack = true;
        body.MaxStack = sb.MaxStack;

        // 局部变量 (含泛型签名按位置重绑定)
        var localMap = new Dictionary<Local, Local>();
        foreach (var l in sb.Variables) {
            var nl = new Local(importer.Import(l.Type));
            body.Variables.Add(nl);
            localMap[l] = nl;
        }
        // 指令骨架
        var instrMap = new Dictionary<Instruction, Instruction>();
        foreach (var i in sb.Instructions) {
            var ni = new Instruction(i.OpCode);
            instrMap[i] = ni;
            body.Instructions.Add(ni);
        }
        // 操作数重映射
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
            else if (op is IMethod im) ni.Operand = importer.Import(im);
            else if (op is IField fi) ni.Operand = importer.Import(fi);
            else if (op is TypeSig sig) ni.Operand = importer.Import(sig);
            else ni.Operand = op;  // 字面量: int/long/float/double/string/sbyte
        }
        // 异常处理表
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
