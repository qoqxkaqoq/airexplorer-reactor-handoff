// probe2 — v132 反射探针 (Windows CI, net48)
// 用法: probe2 <exe> <mode> [timeoutSec]
//   mode=ag   触发 AG.cctor → 读全部 AG 静态字段 → 调 EvaluateVisibleAttribute → 抓完整异常链
//   mode=itp  触发引导 → 抽样调 ITP(id) 验证解密器语义
//   mode=mem  静态字段全dump + 全方法IL dump + 反射invoke解密链 + 自进程堆扫描(transform/key/大byte[])
// 所有调用都在独立 STA 线程 + 看门狗(默认 90s, 超时强杀进程, 防状态机死循环)
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Linq;
using System.Text;
using System.Threading;

class Probe2 {
    static int TimeoutSec = 90;
    static string OutFile = "probe2.log";
    static object Lock = new object();

    static void Log(string s) {
        lock (Lock) {
            Console.WriteLine(s);
            try { File.AppendAllText(OutFile, s + Environment.NewLine); } catch {}
        }
    }

    static int Main(string[] a) {
        if (a.Length < 2) { Console.WriteLine("usage: probe2 <exe> <ag|itp> [timeoutSec]"); return 1; }
        string exe = Path.GetFullPath(a[0]);
        string mode = a[1];
        if (a.Length > 2) TimeoutSec = int.Parse(a[2]);
        if (File.Exists(OutFile)) File.Delete(OutFile);
        using (var md5 = MD5.Create())
        using (var fs = File.OpenRead(exe))
            Log("[probe2] exe=" + exe + " md5=" + BitConverter.ToString(md5.ComputeHash(fs)).Replace("-", ""));
        Log("[probe2] mode=" + mode + " timeout=" + TimeoutSec + "s clr=" + Environment.Version);

        // 看门狗: 主逻辑挂死(状态机死循环)时强杀, exit code 42
        var wd = new Thread(delegate() {
            Thread.Sleep(TimeoutSec * 1000);
            Log("[probe2] WATCHDOG TIMEOUT — killing process");
            Environment.Exit(42);
        });
        wd.IsBackground = true;
        wd.Start();

        // ---- mtrack4: BIG356K 触发冻结态全内存快照 ----
        if (mode == "mtrack4") {
            var w4 = new Thread(delegate() {
                try { MT4_RunWorker(exe); }
                catch (Exception ex) { Log("[mtrack4] worker FAIL " + ex.GetType().FullName + ": " + ex.Message); }
            });
            w4.SetApartmentState(ApartmentState.STA);
            w4.Start();
            MT4_FreezerLoop(w4);
            w4.Join(20000);
            Log("[probe2] mtrack4 DONE");
            return 0;
        }

        // ---- mtrack3: worker 跑解密链, 主线程 SuspendThread 冻结世界扫描 ----
        if (mode == "mtrack3") {
            var w3 = new Thread(delegate() {
                try { RunMTrack3Worker(exe); }
                catch (Exception ex) { Log("[mtrack3] worker FAIL " + ex.GetType().FullName + ": " + ex.Message); }
            });
            w3.SetApartmentState(ApartmentState.STA);
            w3.Start();
            MT3_FreezerLoop(w3);
            w3.Join(20000);
            Log("[probe2] mtrack3 DONE");
            return 0;
        }

        Exception runEx = null;
        var worker = new Thread(delegate() {
            try {
                if (mode == "mtrack") RunMTrack(exe);
                else if (mode == "mtrack2") RunMTrack2(exe);
                else Run(exe, mode);
                Log("[probe2] DONE");
            }
            catch (Exception ex) { runEx = ex; Log("[probe2] RUN-FAIL " + ex.GetType().FullName + ": " + ex.Message); }
        });
        worker.SetApartmentState(ApartmentState.STA);
        worker.Start();
        worker.Join((TimeoutSec + 10) * 1000);
        return runEx != null ? 3 : 0;
    }

    static void Run(string exe, string mode) {
        Directory.SetCurrentDirectory(Path.GetDirectoryName(exe));
        var asm = Assembly.LoadFrom(exe);
        Log("[probe2] loaded " + asm.FullName);
        // 引导: 模块 cctor(解密链) — 失败不致命, 继续
        foreach (var m in asm.GetModules()) {
            try { RuntimeHelpers.RunModuleConstructor(m.ModuleHandle); Log("[probe2] module cctor OK"); }
            catch (Exception ex) { Log("[probe2] module cctor FAIL: " + (ex.InnerException ?? ex).GetType().FullName + ": " + (ex.InnerException ?? ex).Message); }
        }

        if (mode == "ag") {
            var ag = asm.GetType("AirExplorer.Values.ArgumentGateway");
            Log("[probe2] AG type = " + (ag == null ? "NULL!" : ag.FullName));
            if (ag == null) return;
            // 1) 触发 cctor
            try { RuntimeHelpers.RunClassConstructor(ag.TypeHandle); Log("[probe2] AG.cctor OK"); }
            catch (Exception ex) { Log("[probe2] AG.cctor FAIL: " + Chain(ex)); }
            // 2) 读全部静态字段(cctor 明文终值)
            var flags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
            foreach (var f in ag.GetFields(flags)) {
                object v = null;
                try { v = f.GetValue(null); } catch (Exception ex) { Log("[probe2] AG." + f.Name + " READ-FAIL " + ex.GetType().Name); continue; }
                var s = v as string;
                Log("[probe2] AG." + f.Name + " = " + (v == null ? "NULL" : (s != null ? "\"" + s + "\"" : v.GetType().Name + " " + v)));
            }
            // 3) 调 EvaluateVisibleAttribute
            var mEva = ag.GetMethod("EvaluateVisibleAttribute", flags, null, Type.EmptyTypes, null);
            if (mEva == null) { Log("[probe2] EvaluateVisibleAttribute NOT FOUND"); return; }
            Log("[probe2] calling EvaluateVisibleAttribute...");
            try { mEva.Invoke(null, null); Log("[probe2] EVA returned OK (no exception)"); }
            catch (Exception ex) { Log("[probe2] EVA EXCEPTION: " + Chain(ex)); }
            // 4) 顺带: WriteRequest()._RequestSorter 状态核查(定 NRE 源)
            try {
                var rw = asm.GetType("AirExplorer.Networking.RequestWorker");
                var wr = rw.GetMethod("WriteRequest", flags);
                var inst = wr.Invoke(null, null);
                Log("[probe2] WriteRequest() = " + (inst == null ? "NULL" : "inst"));
                if (inst != null) {
                    var sf = rw.GetField("_RequestSorter", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
                    var sorter = sf.GetValue(inst);
                    Log("[probe2] _RequestSorter = " + (sorter == null ? "NULL" : sorter.GetType().FullName));
                    if (sorter != null) {
                        var gt = sorter.GetType().GetField("globalTemplate", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
                        var ht = gt.GetValue(sorter) as System.Collections.IDictionary;
                        if (ht == null) Log("[probe2] sorter.globalTemplate = NULL");
                        else {
                            Log("[probe2] sorter.globalTemplate = Hashtable Count=" + ht.Count);
                            int i = 0;
                            foreach (System.Collections.DictionaryEntry e in ht) {
                                Log("[probe2] TI.key[" + i + "]=" + e.Key + " val=" + (e.Value == null ? "null" : e.Value.GetType().FullName + " " + e.Value));
                                if (++i > 50) { Log("[probe2] TI.key... (truncated)"); break; }
                            }
                        }
                        foreach (var fn in new[] { "_DividedTemplateTitle", "literalTemplateLabel", "statelessTemplateName", "listenerPublisherNote" }) {
                            var ff = sorter.GetType().GetField(fn, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
                            if (ff != null) Log("[probe2] TI." + fn + " = " + (ff.GetValue(sorter) ?? "NULL"));
                        }
                    }
                }
            } catch (Exception ex) { Log("[probe2] RW check FAIL: " + Chain(ex)); }
            // 5) 手动重放 ValidateManager→GenerateAdjustableAggregator 链条, 逐环节打印
            try {
                var flagsS = BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public;
                var flagsI = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
                var tiT = asm.GetType("CloudClient.Templating.TemplateInitializer");
                var rw2 = asm.GetType("AirExplorer.Networking.RequestWorker");
                var sorter = rw2.GetField("_RequestSorter", flagsI).GetValue(rw2.GetMethod("WriteRequest", flagsS).Invoke(null, null));
                if (sorter != null) {
                    string dir = (string)sorter.GetType().GetField("_DividedTemplateTitle", flagsI).GetValue(sorter);
                    string label = (string)sorter.GetType().GetField("literalTemplateLabel", flagsI).GetValue(sorter);
                    Log("[probe2] CHAIN dir=" + dir + " label=" + label);
                    try { Log("[probe2] CHAIN File.Exists(combined)=" + System.IO.File.Exists(System.IO.Path.Combine(dir ?? "", label ?? ""))); } catch (Exception e2) { Log("[probe2] CHAIN File.Exists EX " + e2.Message); }
                    Type vsT = null; Type gvT = null;
                    try { foreach (var t in asm.GetTypes()) { if (t.Name == "ValidatorSchema" && vsT == null) vsT = t; if (t.Name == "GroupedValidator" && gvT == null) gvT = t; } }
                    catch (System.Reflection.ReflectionTypeLoadException rtle) {
                        for (int li = 0; li < rtle.LoaderExceptions.Length && li < 5; li++) {
                            var le = rtle.LoaderExceptions[li];
                            Log("[probe2] LOADEX: " + le.Message + " @ " + (le.StackTrace == null ? "" : le.StackTrace.Split('\n')[0]));
                        }
                        foreach (var t in rtle.Types) { if (t != null && t.Name == "ValidatorSchema" && vsT == null) vsT = t; if (t != null && t.Name == "GroupedValidator" && gvT == null) gvT = t; }
                    }
                    if (vsT == null || gvT == null) throw new Exception("ValidatorSchema/GroupedValidator not found: " + (vsT == null) + "/" + (gvT == null));
                    var cct = vsT.GetField("CheckCustomizableTransmitter", flagsS).GetValue(null);
                    var sBridge = vsT.GetMethod("ExecuteExplorer", flagsS);
                    var s = (string)sBridge.Invoke(null, new[] { (object)dir, label, cct });
                    Log("[probe2] CHAIN CheckCustomizableTransmitter(dir,label) = " + (s == null ? "NULL" : "\"" + s + "\" len=" + s.Length));
                    var vcl = gvT.GetField("VerifyCentralLocator", flagsS).GetValue(null);
                    var gBridge = gvT.GetMethod("ExecuteExplorer", flagsS);
                    var b1 = (bool)gBridge.Invoke(null, new[] { (object)s, vcl });
                    Log("[probe2] CHAIN VerifyCentralLocator(content) = " + b1);
                    var gaa = tiT.GetMethod("GenerateAdjustableAggregator", flagsI);
                    var b2 = (bool)gaa.Invoke(sorter, new[] { (object)s });
                    Log("[probe2] CHAIN GenerateAdjustableAggregator(content) = " + b2);
                    var ht2 = (System.Collections.IDictionary)sorter.GetType().GetField("globalTemplate", flagsI).GetValue(sorter);
                    Log("[probe2] CHAIN globalTemplate.Count=" + (ht2 == null ? -1 : ht2.Count));
                }
            } catch (Exception ex) { Log("[probe2] CHAIN FAIL: " + Chain(ex)); }
        } else if (mode == "itp") {
            var di = asm.GetType("CloudClient.Templating.DispatcherInitializer");
            var itp = di.GetMethod("InstantiateTransferableProgram", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
            int ok = 0, nullRet = 0, err = 0;
            int[] ids = { 0, 1, 2, 100, 1000, 12345, 0x40000000, -1 };
            foreach (var id in ids) {
                try {
                    var r = itp.Invoke(null, new object[] { id });
                    if (r == null) { nullRet++; Log("[probe2] ITP(" + id + ") = NULL"); }
                    else { ok++; Log("[probe2] ITP(" + id + ") = \"" + ((string)r).Substring(0, Math.Min(80, ((string)r).Length)) + "\" len=" + ((string)r).Length); }
                } catch (Exception ex) { err++; Log("[probe2] ITP(" + id + ") EX: " + (ex.InnerException ?? ex).GetType().Name + ": " + (ex.InnerException ?? ex).Message); }
            }
            Log("[probe2] ITP summary ok=" + ok + " null=" + nullRet + " err=" + err);
            // <Module> 容器字段值(ITP id 的 XOR 源)
            foreach (var t in asm.GetTypes()) {
                if (!t.FullName.Contains("<Module>{")) continue;
                var flags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
                foreach (var f in t.GetFields(flags)) {
                    try {
                        var v = f.GetValue(null);
                        if (v == null) { Log("[probe2] MOD." + f.Name + " = NULL"); continue; }
                        var iv = v.GetType().GetField("m_c1d686055a704fd0a5a081272107c4d3", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                        if (iv != null) Log("[probe2] MOD container." + f.Name + ".m_c1d686055a = " + iv.GetValue(v));
                    } catch (Exception ex) { Log("[probe2] MOD." + f.Name + " FAIL " + ex.GetType().Name); }
                }
            }
        } else if (mode == "mem") {
            MemRun(asm);
        } else if (mode == "r5") {
            R5Run(asm);
        } else if (mode == "trap") {
            TrapRun(asm);
        }
    }

    // ===================== mode=trap: 全类型 cctor 逐个触发, 死类型打印完整内层异常链+StackTrace =====================
    static void TrapRun(Assembly asm) {
        // FirstChanceException 钩子: 在原始 throw 点触发 (栈未被任何 catch 重写/重抛改写前),
        // 用于定位 'AirExplorer ' 守卫的真正构造方 (4523 catch `ldloc.s c; throw` 会重写栈)
        int fceHits = 0;
        AppDomain.CurrentDomain.FirstChanceException += delegate(object s, System.Runtime.ExceptionServices.FirstChanceExceptionEventArgs ea) {
            try {
                var ex3 = ea.Exception;
                if (ex3 == null || fceHits >= 12) return;
                if (ex3.GetType() != typeof(System.Exception)) return;
                var m3 = ex3.Message;
                if (m3 == null || !m3.StartsWith("AirExplorer")) return;
                fceHits++;
                Log("[trap] FCE#" + fceHits + " msg=[" + m3 + "] len=" + m3.Length);
                var st3 = ex3.StackTrace;
                if (string.IsNullOrEmpty(st3)) Log("[trap] FCE stack NULL");
                else Log("[trap] FCE stack: " + st3.Substring(0, Math.Min(st3.Length, 900)));
            } catch {}
        };
        Type[] ts = null;
        try { ts = asm.GetTypes(); }
        catch (ReflectionTypeLoadException ex) {
            ts = ex.Types;
            Log("[trap] GetTypes partial: " + ts.Count(t => t != null) + "/" + ts.Length + " loaderEx=" + ex.LoaderExceptions.Length);
        }
        int ok = 0, fail = 0;
        if (ts == null) { Log("[trap] no types"); return; }
        int ti = 0;
        foreach (var t in ts) {
            if (t == null) continue;
            Log("[trap] #" + ti + " " + t.FullName);
            ti++;
            try {
                RuntimeHelpers.RunClassConstructor(t.TypeHandle);
                ok++;
            } catch (TypeInitializationException tie) {
                fail++;
                var cur = tie.InnerException ?? tie;
                int depth = 0;
                Log("[trap] FAIL " + t.FullName);
                while (cur != null && depth < 8) {
                    Log("  [trap] inner" + depth + " " + cur.GetType().FullName + ": " + cur.Message);
                    var st = cur.StackTrace;
                    if (!string.IsNullOrEmpty(st)) Log("  [trap] stack" + depth + ": " + st.Substring(0, Math.Min(st.Length, 600)));
                    cur = cur.InnerException; depth++;
                }
                if (fail >= 6) { Log("[trap] stop after 6 failures"); break; }
            } catch (Exception ex2) {
                fail++;
                Log("[trap] FAIL " + t.FullName + " " + ex2.GetType().FullName + ": " + ex2.Message);
                if (fail >= 6) { Log("[trap] stop after 6 failures"); break; }
            }
        }
        Log("[trap] SUMMARY ok=" + ok + " fail=" + fail + " total=" + ts.Length);
    }

    // ===================== mode=r5: res5 哈希表资源 + RSA 静态实例抓取 =====================
    static void R5Run(Assembly asm) {
        var mod = asm.GetModules()[0];
        try { Directory.CreateDirectory(DumpDir); } catch {}

        // R5.A manifest 资源全清单 + res5 密文全 dump
        try {
            string[] names = asm.GetManifestResourceNames();
            Log("[r5] A. manifest resources=" + names.Length);
            foreach (var n in names) {
                using (var s = asm.GetManifestResourceStream(n)) {
                    if (s == null) { Log("[r5] A. res '" + n + "' NULL"); continue; }
                    var ms = new MemoryStream();
                    s.CopyTo(ms);
                    var buf = ms.ToArray();
                    Log("[r5] A. res '" + n + "' len=" + buf.Length + " head=" + BitConverter.ToString(buf, 0, Math.Min(32, buf.Length)).Replace("-", ""));
                    if (n == "ValidatorArgument.EmitterReporter") {
                        File.WriteAllBytes(Path.Combine(DumpDir, "res5_cipher.bin"), buf);
                        Log("[r5] A. res5_cipher.bin written (" + buf.Length + "B)");
                    }
                }
            }
        } catch (Exception ex) { Log("[r5] A FAIL " + Chain(ex)); }

        // R5.B DispatcherInitializer.m_ExtendedSchemaTemplate (RSA 静态实例) ExportParameters
        try {
            var diT = asm.GetType("CloudClient.Templating.DispatcherInitializer");
            var f = diT.GetField("m_ExtendedSchemaTemplate", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
            var v = f.GetValue(null);
            Log("[r5] B. m_ExtendedSchemaTemplate = " + (v == null ? "NULL" : v.GetType().FullName));
            if (v is RSACryptoServiceProvider) {
                var rsa = (RSACryptoServiceProvider)v;
                var p = rsa.ExportParameters(true);
                Log("[r5] B. RSA priv D=" + (p.D == null ? "NULL" : p.D.Length + "B") + " modulus=" + (p.Modulus == null ? "NULL" : p.Modulus.Length + "B"));
                using (var w = new StreamWriter(Path.Combine(DumpDir, "rsa_params.txt"))) {
                    w.WriteLine("D=" + (p.D == null ? "NULL" : BitConverter.ToString(p.D).Replace("-", "")));
                    w.WriteLine("DP=" + (p.DP == null ? "NULL" : BitConverter.ToString(p.DP).Replace("-", "")));
                    w.WriteLine("DQ=" + (p.DQ == null ? "NULL" : BitConverter.ToString(p.DQ).Replace("-", "")));
                    w.WriteLine("Exponent=" + (p.Exponent == null ? "NULL" : BitConverter.ToString(p.Exponent).Replace("-", "")));
                    w.WriteLine("InverseQ=" + (p.InverseQ == null ? "NULL" : BitConverter.ToString(p.InverseQ).Replace("-", "")));
                    w.WriteLine("Modulus=" + (p.Modulus == null ? "NULL" : BitConverter.ToString(p.Modulus).Replace("-", "")));
                    w.WriteLine("P=" + (p.P == null ? "NULL" : BitConverter.ToString(p.P).Replace("-", "")));
                    w.WriteLine("Q=" + (p.Q == null ? "NULL" : BitConverter.ToString(p.Q).Replace("-", "")));
                }
                Log("[r5] B. rsa_params.txt written");
            } else if (v != null) {
                DumpFieldValue("rsaStatic", v, "r5b", 0);
            }
        } catch (Exception ex) { Log("[r5] B FAIL " + Chain(ex)); }

        // R5.C 06004264 类型信息(BinaryReader 包装器)
        try {
            var mb = mod.ResolveMethod(0x06004264);
            var dt = mb.DeclaringType;
            Log("[r5] C. 06004264 decl=" + dt.FullName);
            foreach (var ff in dt.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
                Log("[r5] C. field " + ff.Name + " : " + ff.FieldType.FullName);
        } catch (Exception ex) { Log("[r5] C FAIL " + ex.Message); }

        // R5.D invoke 06004192(守卫1 自检: baseline 上应通过)
        try {
            var m = (MethodInfo)mod.ResolveMethod(0x06004192);
            int np = m.GetParameters().Length;
            Log("[r5] D. invoke 06004192 params=" + np);
            try {
                m.Invoke(null, np == 0 ? null : new object[np]);
                Log("[r5] D. guard1 OK (no throw)");
            } catch (Exception ex) { Log("[r5] D. guard1 THROW " + Chain(ex)); }
        } catch (Exception ex) { Log("[r5] D resolve FAIL " + ex.Message); }

        // R5.E automatedError 字段(4192 用它读资源)→ 同路径读 res5
        try {
            var diT2 = asm.GetType("CloudClient.Templating.DispatcherInitializer");
            var f2 = diT2.GetField("automatedError", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
            var v2 = f2.GetValue(null);
            Log("[r5] E. automatedError = " + (v2 == null ? "NULL" : v2.GetType().FullName));
            if (v2 is Assembly) {
                var a2 = (Assembly)v2;
                try { Log("[r5] E. location=" + a2.Location); } catch {}
                using (var s = a2.GetManifestResourceStream("ValidatorArgument.EmitterReporter")) {
                    if (s == null) Log("[r5] E. res5 via automatedError = NULL");
                    else {
                        var ms = new MemoryStream(); s.CopyTo(ms);
                        var buf = ms.ToArray();
                        File.WriteAllBytes(Path.Combine(DumpDir, "res5_via_asm.bin"), buf);
                        Log("[r5] E. res5 via asm len=" + buf.Length);
                    }
                }
            }
        } catch (Exception ex) { Log("[r5] E FAIL " + Chain(ex)); }

        // R5.F 全资源落盘 + RSA 进程内解密 res5(私钥不可导出但 Decrypt 可用)
        try {
            foreach (var n in asm.GetManifestResourceNames()) {
                var safe = n.Replace('.', '_');
                using (var s = asm.GetManifestResourceStream(n)) {
                    if (s == null) continue;
                    var ms = new MemoryStream(); s.CopyTo(ms);
                    File.WriteAllBytes(Path.Combine(DumpDir, "res_" + safe + ".bin"), ms.ToArray());
                }
            }
            Log("[r5] F. all resources dumped");
        } catch (Exception ex) { Log("[r5] F dump-all FAIL " + Chain(ex)); }
        try {
            var diT3 = asm.GetType("CloudClient.Templating.DispatcherInitializer");
            var f3 = diT3.GetField("m_ExtendedSchemaTemplate", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
            var rsa = (RSACryptoServiceProvider)f3.GetValue(null);
            var c5 = File.ReadAllBytes(Path.Combine(DumpDir, "res5_cipher.bin"));
            foreach (var fOAEP in new[] { true, false }) {
                try {
                    var pt = rsa.Decrypt(c5, fOAEP);
                    File.WriteAllBytes(Path.Combine(DumpDir, "res5_plain_oaep" + fOAEP + ".bin"), pt);
                    Log("[r5] F. Decrypt OAEP=" + fOAEP + " OK len=" + pt.Length);
                    Log("[r5] F. plain head=" + BitConverter.ToString(pt, 0, Math.Min(96, pt.Length)).Replace("-", ""));
                    try {
                        var hex = BitConverter.ToString(pt).Replace("-", "");
                        Log("[r5] F. plain full=" + hex);
                    } catch {}
                } catch (Exception ex) { Log("[r5] F. OAEP=" + fOAEP + " FAIL " + (ex.InnerException ?? ex).Message); }
            }
            try { Log("[r5] F. CspKeyContainerInfo: name=" + rsa.CspKeyContainerInfo.KeyContainerName + " exportable=" + rsa.CspKeyContainerInfo.Exportable); } catch (Exception ex) { Log("[r5] F. CspInfo FAIL " + (ex.InnerException ?? ex).Message); }
        } catch (Exception ex) { Log("[r5] F decrypt FAIL " + Chain(ex)); }

        // R5.G 4192 跑完后 DispatcherInitializer 全静态字段 dump (baseline vs a7probe 差分 → 4528 的输入)
        try {
            var diT4 = asm.GetType("CloudClient.Templating.DispatcherInitializer");
            var fs4 = diT4.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
            int gi = 0;
            foreach (var f in fs4) {
                object v = null; string vs;
                try { v = f.GetValue(null); } catch (Exception ex) { Log("[r5] G. " + f.Name + " READ-FAIL " + ex.GetType().Name); continue; }
                if (v == null) vs = "NULL";
                else if (v is string) vs = "STR(" + ((string)v).Length + ")=" + (string)v;
                else if (v is byte[]) {
                    var bb = (byte[])v;
                    vs = "BYTE[" + bb.Length + "]=" + BitConverter.ToString(bb, 0, Math.Min(256, bb.Length)).Replace("-", "");
                    try { File.WriteAllBytes(Path.Combine(DumpDir, "gstat_" + f.Name + ".bin"), bb); } catch {}
                } else if (v is Array) {
                    var arr = (Array)v;
                    var sb2 = new StringBuilder("ARR[" + arr.Length + "] ");
                    int c2 = 0;
                    foreach (var x in arr) { if (c2++ > 48) { sb2.Append("..."); break; } sb2.Append(x == null ? "null " : (x is byte ? ((byte)x).ToString("x2") + " " : x.ToString() + " ")); }
                    vs = sb2.ToString();
                } else if (v is int || v is long || v is uint || v is bool || v is short || v is byte || v is char || v is ulong || v is IntPtr) vs = "PRIM " + v.ToString();
                else vs = v.GetType().FullName;
                Log("[r5] G. " + f.Name + " = " + vs);
                gi++;
            }
            Log("[r5] G. total statics=" + gi);
        } catch (Exception ex) { Log("[r5] G FAIL " + Chain(ex)); }

        // R5.H invoke 06004528 GenerateAdaptableExtractor (二层守卫) → 抓异常 + 静态再 dump
        try {
            var m2 = (MethodInfo)mod.ResolveMethod(0x06004528);
            var ps = m2.GetParameters();
            Log("[r5] H. invoke 06004528 params=" + ps.Length + (ps.Length > 0 ? " p0=" + ps[0].ParameterType.FullName + (ps[0].ParameterType.IsByRef ? "(byref)" : "") : ""));
            object[] args2 = new object[ps.Length];
            for (int i2 = 0; i2 < ps.Length; i2++) if (ps[i2].ParameterType.IsValueType) args2[i2] = Activator.CreateInstance(ps[i2].ParameterType);
            try {
                m2.Invoke(null, args2);
                Log("[r5] H. 4528 OK (no throw)");
                if (ps.Length > 0 && ps[0].ParameterType.IsByRef) Log("[r5] H. byref p0 after=" + args2[0]);
            } catch (Exception ex) { Log("[r5] H. 4528 THROW " + Chain(ex)); }
            // 实例重试: 4528 是实例方法, Activator 建目标再调
            if (ps.Length > 0 && !ps[0].ParameterType.IsByRef) {
                try {
                    var tgt2 = Activator.CreateInstance(ps[0].ParameterType);
                    Log("[r5] H. target created " + tgt2.GetType().FullName);
                    try { m2.Invoke(tgt2, args2); Log("[r5] H. 4528(inst) OK (no throw)"); }
                    catch (Exception ex5) { Log("[r5] H. 4528(inst) THROW " + Chain(ex5)); }
                } catch (Exception ex6) { Log("[r5] H. target ctor FAIL " + Chain(ex6)); }
            }
            try {
                var diT5 = asm.GetType("CloudClient.Templating.DispatcherInitializer");
                foreach (var f in diT5.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)) {
                    object v = null;
                    try { v = f.GetValue(null); } catch { continue; }
                    if (v is string) Log("[r5] H. post " + f.Name + " = STR(" + ((string)v).Length + ")=" + (string)v);
                    else if (v is byte[]) {
                        var bb = (byte[])v;
                        try { File.WriteAllBytes(Path.Combine(DumpDir, "hstat_" + f.Name + ".bin"), bb); } catch {}
                        Log("[r5] H. post " + f.Name + " = BYTE[" + bb.Length + "] " + BitConverter.ToString(bb, 0, Math.Min(64, bb.Length)).Replace("-", ""));
                    }
                }
            } catch (Exception ex2) { Log("[r5] H post-dump FAIL " + Chain(ex2)); }
        } catch (Exception ex) { Log("[r5] H resolve FAIL " + ex.Message); }

        // R5.I full-assembly static snapshot (diff baseline vs a7c -> 4528's real input)
        try {
            int ti = 0, fi = 0;
            var sb3 = new StringBuilder();
            Type[] allT;
            try { allT = asm.GetTypes(); }
            catch (ReflectionTypeLoadException rtle) {
                int nl = 0; foreach (var t2 in rtle.Types) if (t2 == null) nl++;
                Log("[r5] I. GetTypes RTL: loaded=" + (rtle.Types.Length - nl) + " null=" + nl);
                var sb5 = new StringBuilder();
                if (rtle.LoaderExceptions != null) foreach (var le in rtle.LoaderExceptions) sb5.AppendLine(le == null ? "null" : le.GetType().Name + ": " + le.Message);
                try { File.WriteAllText(Path.Combine(DumpDir, "istat_loadex.txt"), sb5.ToString()); } catch {}
                allT = rtle.Types;
            }
            if (allT == null) allT = new Type[0];
            foreach (var t in allT) {
                if (t == null) continue;
                try {
                if (t.IsGenericType || t.IsArray) continue;
                ti++;
                System.Reflection.FieldInfo[] fs = null;
                try { fs = t.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic); } catch { continue; }
                foreach (var f in fs) {
                    object v = null;
                    try { v = f.GetValue(null); } catch (Exception) { continue; }
                    fi++;
                    string vs;
                    if (v == null) vs = "NULL";
                    else if (v is string) vs = "STR(" + ((string)v).Length + ")=" + (string)v;
                    else if (v is byte[]) {
                        var bb = (byte[])v;
                        using (var mh = System.Security.Cryptography.MD5.Create())
                            vs = "BYTE[" + bb.Length + "]md5=" + BitConverter.ToString(mh.ComputeHash(bb)).Replace("-", "");
                        try { File.WriteAllBytes(Path.Combine(DumpDir, "istat_" + t.Name + "_" + f.Name + ".bin"), bb); } catch {}
                    } else if (v is int || v is long || v is uint || v is bool || v is short || v is byte || v is char || v is ulong || v is double || v is float || v is sbyte || v is ushort) vs = "PRIM " + v.ToString();
                    else if (v is Array) {
                        var arr = (Array)v; var sb4 = new StringBuilder("ARR[" + arr.Length + "] "); int c3 = 0;
                        foreach (var x in arr) { if (c3++ > 32) { sb4.Append("..."); break; } sb4.Append(x == null ? "null " : (x is byte ? ((byte)x).ToString("x2") + " " : x.ToString() + " ")); }
                        vs = sb4.ToString();
                    } else vs = "TYP " + v.GetType().FullName;
                    sb3.Append("I. ").Append(t.FullName).Append("::").Append(f.Name).Append(" = ").Append(vs).AppendLine();
                }
                } catch (Exception) { }
            }
            File.WriteAllText(Path.Combine(DumpDir, "istat_all.txt"), sb3.ToString());
            Log("[r5] I. static snapshot: types=" + ti + " fields=" + fi + " -> istat_all.txt");
        } catch (Exception ex) { Log("[r5] I FAIL " + Chain(ex)); }
    }

    // ===================== mode=mem: 运行时提取 =====================
    static string DumpDir = "dump";

    [StructLayout(LayoutKind.Sequential)]
    struct MBI { public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; }
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualQuery(IntPtr lpAddress, ref MBI lpBuffer, IntPtr dwLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProc, IntPtr lpBase, byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    // AV-proof read (PAGE_NOACCESS / freed pages return false instead of crashing)
    static bool SafeRead(IntPtr addr, byte[] buf) {
        IntPtr got;
        try { return ReadProcessMemory(GetCurrentProcess(), addr, buf, (IntPtr)buf.Length, out got) && got.ToInt64() == buf.Length; }
        catch { return false; }
    }
    // bounded read: request count bytes into (possibly larger) buf; partial reads OK
    static bool SafeReadN(IntPtr addr, byte[] buf, int count) {
        IntPtr got;
        try { return ReadProcessMemory(GetCurrentProcess(), addr, buf, (IntPtr)count, out got); }
        catch { return false; }
    }
    static bool LooksLikeHeap(ulong pv) { return pv > 0x10000UL && pv < 0x7FFFFFFEFFFFUL; }
    static int censHits = 0, censDumps = 0;

    static ICryptoTransform _keepT;      // 自建 transform 标定引用 (布局校验)
    static void MemRun(Assembly asm) {
        try { Directory.CreateDirectory(DumpDir); } catch {}
        var mod = asm.GetModules()[0];
        var flags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;

        // ---- A. DispatcherInitializer 静态字段全 dump (Reactor 状态容器) ----
        var diT = asm.GetType("CloudClient.Templating.DispatcherInitializer");
        Log("[mem] A. DispatcherInitializer = " + (diT == null ? "NULL!" : diT.FullName + " fields=" + diT.GetFields(flags).Length));
        if (diT != null) {
            foreach (var f in diT.GetFields(flags)) DumpFieldValue(f.Name, f.GetValue(null), "stat1", 0);
        }

        // ---- B. 全方法 IL dump (内存真体 ground truth) ----
        try {
            int n = 0, okB = 0;
            using (var ix = new StreamWriter(Path.Combine(DumpDir, "il_index.tsv")))
            using (var bl = new FileStream(Path.Combine(DumpDir, "il_all.bin"), FileMode.Create)) {
                for (int rid = 1; rid <= 30912; rid++) {
                    MethodBase mb = null;
                    try { mb = mod.ResolveMethod(0x06000000 | rid); } catch {}
                    if (mb == null) continue;
                    n++;
                    try {
                        var il = mb.GetMethodBody().GetILAsByteArray();
                        if (il == null) continue;
                        long pos = bl.Position;
                        bl.Write(il, 0, il.Length);
                        ix.WriteLine("0x{0:X8}\t{1}\t{2}\t{3}\t{4}", 0x06000000 | rid, il.Length, mb.DeclaringType == null ? "" : mb.DeclaringType.FullName, mb.Name, pos);
                        okB++;
                    } catch {}
                }
            }
            Log("[mem] B. il_all: resolved=" + n + " bodies=" + okB);
        } catch (Exception ex) { Log("[mem] B il_all FAIL " + Chain(ex)); }

        // ---- C. 已知明文 sanity (内存 IL vs dump_16598) ----
        foreach (var tok in new[] { 0x0600212A, 0x06002157, 0x06002145, 0x06000CEE }) {
            try {
                var mb = mod.ResolveMethod(tok);
                var il = mb.GetMethodBody().GetILAsByteArray();
                Log("[mem] C. 0x" + tok.ToString("X8") + " len=" + il.Length + " head=" + BitConverter.ToString(il, 0, Math.Min(12, il.Length)).Replace("-", ""));
            } catch (Exception ex) { Log("[mem] C. 0x" + tok.ToString("X8") + " FAIL " + (ex.InnerException ?? ex).Message); }
        }

        // ---- D. MT 指针准备 (自建同型实例取 MethodTable*) ----
        ulong mtRMCrypt = 0, mtAesCSPCrypt = 0, mtRijndael = 0, mtAesCSP = 0;
        try { _keepT = new RijndaelManaged().CreateDecryptor(new byte[32], new byte[16]); mtRMCrypt = (ulong)_keepT.GetType().TypeHandle.Value.ToInt64(); }
        catch (Exception ex) { Log("[mem] D RMCrypt FAIL " + ex.Message); }
        try { mtAesCSPCrypt = (ulong)new AesCryptoServiceProvider().CreateDecryptor(new byte[32], new byte[16]).GetType().TypeHandle.Value.ToInt64(); } catch (Exception ex) { Log("[mem] D AesCSPCrypt FAIL " + ex.Message); }
        try { mtRijndael = (ulong)typeof(RijndaelManaged).TypeHandle.Value.ToInt64(); } catch {}
        try { mtAesCSP = (ulong)typeof(AesCryptoServiceProvider).TypeHandle.Value.ToInt64(); } catch {}
        // byte[] 真 MT: TypeHandle 对 SZ 数组返回 TypeDesc (非 8 对齐) → 用 pinned 对象头取真 MethodTable*
        ulong mtByteArr = 0;
        try {
            var arrProbe = new byte[101];
            var gh = GCHandle.Alloc(arrProbe, GCHandleType.Pinned);
            long dp = gh.AddrOfPinnedObject().ToInt64();
            mtByteArr = (ulong)Marshal.ReadIntPtr(new IntPtr(dp - 16)).ToInt64();
            gh.Free();
        } catch (Exception ex) { Log("[mem] D arrProbe FAIL " + ex.Message); }
        ulong mtByteArrTH = (ulong)typeof(byte[]).TypeHandle.Value.ToInt64();
        Log("[mem] D. MT: RMCrypt=" + mtRMCrypt.ToString("X") + " AesCSPCrypt=" + mtAesCSPCrypt.ToString("X") + " RijndaelManaged=" + mtRijndael.ToString("X") + " AesCSP=" + mtAesCSP.ToString("X") + " byte[]pinned=" + mtByteArr.ToString("X") + " byte[]TH=" + mtByteArrTH.ToString("X"));

        var algMTs = new[] { mtRijndael, mtAesCSP, mtRMCrypt, mtAesCSPCrypt };
        var algNames = new[] { "RijndaelManaged", "AesCSP", "RMCrypt", "AesCSPCrypt" };
        var scanBuf = new byte[8 << 20]; // 预分配复用: 扫描期零分配, 防止 GC 回收 ITP 残留 transform

        // ---- E. 清堆后 S1 扫描 (module cctor 残留) ----
        try { GC.Collect(); GC.WaitForPendingFinalizers(); } catch {}
        ScanHeap("s1", algMTs, algNames, mtByteArr, 60, 32 << 20, scanBuf, true);

        // ---- F. invoke 0600418C 工厂 → 读返回对象 Key/IV ----
        try {
            var mF = (MethodInfo)mod.ResolveMethod(0x0600418C);
            Log("[mem] F. invoke " + mF.DeclaringType.Name + "::" + mF.Name + " (AES factory)...");
            var alg = mF.Invoke(null, null);
            if (alg == null) Log("[mem] F. returned NULL");
            else {
                Log("[mem] F. returned " + alg.GetType().FullName);
                DumpFieldValue("factory", alg, "statF", 0);
            }
        } catch (Exception ex) { Log("[mem] F FAIL " + Chain(ex)); }

        // ---- G. invoke 0600419C 驱动器 → 立即 S2 扫描 (transform/key/明文流捕获) ----
        try {
            var mD = (MethodInfo)mod.ResolveMethod(0x0600419C);
            Log("[mem] G. invoke " + mD.DeclaringType.Name + "::" + mD.Name + " (res0 driver)...");
            try { mD.Invoke(null, null); Log("[mem] G. driver OK"); }
            catch (Exception ex) { Log("[mem] G. driver EX " + Chain(ex)); }
        } catch (Exception ex) { Log("[mem] G resolve FAIL " + ex.Message); }
        ScanHeap("s2", algMTs, algNames, mtByteArr, 60, 32 << 20, scanBuf, true);

        // ---- K2. NoGC 区: 驱动器+ITP+立即扫描 (transform/Key/IV 原址残留, 零复用) ----
        try {
            bool nogc = false;
            try { nogc = GC.TryStartNoGCRegion(256L << 20); } catch {}
            if (!nogc) { try { nogc = GC.TryStartNoGCRegion(128L << 20); } catch {} }
            Log("[mem] K2. NoGC=" + nogc);
            try {
                if (nogc) {
                    try {
                        var mD2 = (MethodInfo)mod.ResolveMethod(0x0600419C);
                        Log("[mem] K2. driver (fresh)...");
                        mD2.Invoke(null, null);
                        Log("[mem] K2. driver OK");
                    } catch (Exception ex) { Log("[mem] K2. driver EX " + Chain(ex)); }
                    ScanHeap("censD", algMTs, algNames, mtByteArr, 40, 8 << 20, scanBuf, true);
                }
                var itp0 = (MethodInfo)mod.ResolveMethod(0x06004196);
                var s0 = (string)itp0.Invoke(null, new object[] { 0 });
                Log("[mem] K2. ITP(0) len=" + (s0 == null ? -1 : s0.Length));
                ScanHeap("censI", algMTs, algNames, mtByteArr, 40, 8 << 20, scanBuf, true);
            } finally {
                if (nogc) { try { GC.EndNoGCRegion(); } catch {} }
            }
        } catch (Exception ex) { Log("[mem] K2 FAIL " + Chain(ex)); }

        // ---- I. ITP 预热 (res5 字符串池填充; 新鲜 token 收尾强制全解密路径) → stat2 ----
        try {
            var itp = (MethodInfo)mod.ResolveMethod(0x06004196);
            foreach (var id in new[] { 0, 1, 2, 100, 1000, 12345, 0x40000000, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }) {
                try { var s = (string)itp.Invoke(null, new object[] { id }); Log("[mem] I. ITP(" + id + ") len=" + (s == null ? -1 : s.Length) + " \"" + (s == null ? "" : s.Substring(0, Math.Min(60, s.Length))) + "\""); }
                catch (Exception ex) { Log("[mem] I. ITP(" + id + ") EX " + (ex.InnerException ?? ex).Message); }
            }
        } catch (Exception ex) { Log("[mem] I resolve FAIL " + ex.Message); }

        // ---- K. ITP 后立即普查 (transform/Key/IV 残留捕获; ITP→扫描间零 GC) ----
        ScanHeap("cens", algMTs, algNames, mtByteArr, 80, 32 << 20, scanBuf, true);

        // ---- J. 缺体族重试 + 驱动器静态字段 dump (payload 条目表 token→(offset,len,key) 候选) ----
        // 驱动器/ITP 已执行 (G/K2/I): Reactor JIT-hook 路径已走过; forcedump failed 名单
        // (06003909/06002BD1/0600419E-0600427F 族) 的真体可能在首次 JIT 时由运行时回填 IL 头 →
        // PrepareMethod 强制 JIT + GetMethodBody 重试 + 全量 diff + 驱动器类静态字段
        var missToks = new[] { 0x06003909, 0x06002BD1, 0x0600419C, 0x0600419E, 0x0600419F, 0x060041A3,
                               0x060041FA, 0x0600425C, 0x0600425D, 0x06004261, 0x06004264, 0x0600426B,
                               0x0600426F, 0x06004273, 0x06004277, 0x0600427B, 0x0600427F };
        var missTypes = new List<Type>();
        foreach (var tok in missToks) {
            try {
                var mb = mod.ResolveMethod(tok);
                if (mb == null) { Log("[mem] J. 0x" + tok.ToString("X8") + " resolve NULL"); continue; }
                if (mb.DeclaringType != null && !missTypes.Contains(mb.DeclaringType)) missTypes.Add(mb.DeclaringType);
                Log("[mem] J. 0x" + tok.ToString("X8") + " = " + (mb.DeclaringType == null ? "?" : mb.DeclaringType.FullName) + "::" + mb.Name);
                try { RuntimeHelpers.PrepareMethod(mb.MethodHandle); Log("[mem] J. 0x" + tok.ToString("X8") + " PrepareMethod OK"); }
                catch (Exception ex) { Log("[mem] J. 0x" + tok.ToString("X8") + " PrepareMethod FAIL " + (ex.InnerException ?? ex).Message); }
            } catch (Exception ex) { Log("[mem] J. 0x" + tok.ToString("X8") + " FAIL " + (ex.InnerException ?? ex).Message); }
        }
        // J2: 全量 diff — B 节(驱动器执行前)缺体/失败的方法此刻重试, 新真体全落盘
        int jNew = 0, jFail = 0;
        try {
            var have = new HashSet<int>();
            foreach (var ln in File.ReadAllLines(Path.Combine(DumpDir, "il_index.tsv"))) {
                if (ln.StartsWith("0x") && ln.Length > 10) {
                    int v;
                    if (int.TryParse(ln.Substring(2, 8), System.Globalization.NumberStyles.HexNumber, null, out v)) have.Add(v);
                }
            }
            var want = new HashSet<int>(missToks);
            var ix = new StreamWriter(Path.Combine(DumpDir, "il_new_index.tsv"));
            var bl = new FileStream(Path.Combine(DumpDir, "il_new.bin"), FileMode.Create);
            try {
                for (int rid = 1; rid <= 30912; rid++) {
                    int tok = 0x06000000 | rid;
                    if (have.Contains(tok)) continue;
                    MethodBase mb = null;
                    try { mb = mod.ResolveMethod(tok); } catch {}
                    if (mb == null) continue;
                    try {
                        var bd = mb.GetMethodBody();
                        var il = bd == null ? null : bd.GetILAsByteArray();
                        if (il == null || il.Length == 0) continue;
                        byte[] mf = NewMFile(tok, il, bd.MaxStackSize, bd.ExceptionHandlingClauses.Count);
                        long pos = bl.Position;
                        bl.Write(mf, 0, mf.Length);
                        ix.WriteLine("0x{0:X8}\t{1}\t{2}\t{3}\t{4}", tok, il.Length, mb.DeclaringType == null ? "" : mb.DeclaringType.FullName, mb.Name, pos);
                        if (want.Contains(tok) || jNew < 400)
                            File.WriteAllBytes(Path.Combine(DumpDir, "m_" + tok.ToString("X8") + ".bin"), mf);
                        Log("[mem] J2. NEW 0x" + tok.ToString("X8") + " len=" + il.Length + " " + (mb.DeclaringType == null ? "" : mb.DeclaringType.Name) + "::" + mb.Name + " head=" + BitConverter.ToString(il, 0, Math.Min(16, il.Length)).Replace("-", ""));
                        jNew++;
                    } catch { jFail++; }
                }
            } finally { ix.Dispose(); bl.Dispose(); }
            Log("[mem] J2. diff done: new=" + jNew + " fail=" + jFail);
        } catch (Exception ex) { Log("[mem] J2 FAIL " + Chain(ex)); }
        // J3: 驱动器类静态字段全 dump (条目表候选: Dictionary/Array/int 表)
        try {
            foreach (var t in missTypes) {
                Log("[mem] J3. statics of " + t.FullName);
                foreach (var f in t.GetFields(flags)) DumpFieldValue(f.Name, f.GetValue(null), "statJ", 0);
            }
        } catch (Exception ex) { Log("[mem] J3 FAIL " + Chain(ex)); }

        // ---- M/N. 映像负载区 dump ×2 (PrepareMethod 全扫前后) → 本地 diff 定位条目表/逐条目解密 ----
        // 依据: 4609 内存体 = call 0600419C; ret 桩 (JIT hook 标记); 唯一托管回填链 0600419C→060041FA→Marshal.WriteInt32
        // .text payload RVA 0x620000-0x920000 (file 0x61E200-0x91E200); 映像内 VA = base+RVA
        try {
            IntPtr ibase = Marshal.GetHINSTANCE(mod);
            Log("[mem] M. image base=" + ibase.ToInt64().ToString("X"));
            byte[] img = new byte[0x340000];
            var blk = new byte[0x10000];
            for (int pass = 1; pass <= 2; pass++) {
                if (pass == 2) {
                    int pOK = 0, pFail = 0;
                    for (int rid = 1; rid <= 30912; rid++) {
                        MethodBase mb = null;
                        try { mb = mod.ResolveMethod(0x06000000 | rid); } catch {}
                        if (mb == null) continue;
                        try { RuntimeHelpers.PrepareMethod(mb.MethodHandle); pOK++; } catch { pFail++; }
                    }
                    Log("[mem] N. PrepareMethod sweep: ok=" + pOK + " fail=" + pFail);
                }
                int readOK = 0;
                for (int off = 0; off < img.Length; off += 0x10000) {
                    bool ok = SafeRead(new IntPtr(ibase.ToInt64() + 0x600000 + off), blk);
                    if (ok) { Buffer.BlockCopy(blk, 0, img, off, 0x10000); readOK++; }
                }
                Log("[mem] M" + pass + ". image dump [base+0x600000,+0x340000): blocksOK=" + readOK + "/52");
                using (var md = System.Security.Cryptography.MD5.Create())
                    Log("[mem] M" + pass + ". img md5=" + BitConverter.ToString(md.ComputeHash(img)).Replace("-", ""));
                File.WriteAllBytes(Path.Combine(DumpDir, "img" + pass + ".bin"), img);
            }
        } catch (Exception ex) { Log("[mem] M FAIL " + Chain(ex)); }

        if (diT != null) {
            foreach (var f in diT.GetFields(flags)) DumpFieldValue(f.Name, f.GetValue(null), "stat2", 0);
        }
        Log("[mem] stat2 done");
    }

    // dump_official_16598 兼容 24B 头: tok/ilSize/maxStack/ehCount/preExtra/localsTok
    static byte[] NewMFile(int tok, byte[] il, int maxStack, int eh) {
        var b = new byte[24 + il.Length];
        BitConverter.GetBytes(tok).CopyTo(b, 0);
        BitConverter.GetBytes(il.Length).CopyTo(b, 4);
        BitConverter.GetBytes(maxStack).CopyTo(b, 8);
        BitConverter.GetBytes(eh).CopyTo(b, 12);
        il.CopyTo(b, 24);
        return b;
    }

    // 堆扫描 v3: ReadProcessMemory 全读; 预分配 buf 复用(扫描期零分配); MT 命中 → dump 512B + 追链;
    // byte[] MT → len≥32KB dump 数据; censSmall=true 时 len∈{16,24,32,64} 全部 hex 打印(AES Key/IV 普查)
    static void ScanHeap(string tag, ulong[] mts, string[] names, ulong mtByteArr, int maxObj, long maxBytes, byte[] buf, bool censSmall) {
        long dumped = 0; int objHits = 0;
        var mbi = new MBI();
        var sizeOfMbi = (IntPtr)Marshal.SizeOf(typeof(MBI));
        IntPtr addr = new IntPtr(0x10000);
        long regions = 0, committed = 0;
        while ((long)addr < 0x7FFFFFFEFFFF) {
            if (VirtualQuery(addr, ref mbi, sizeOfMbi) == IntPtr.Zero) break;
            long rsz = mbi.RegionSize.ToInt64();
            if (rsz <= 0) break;
            IntPtr next = (IntPtr)(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
            if (mbi.State == 0x1000 && (mbi.Protect & 0x100) == 0 && (mbi.Protect & 0xFF) != 0x01) {
                committed += rsz; regions++;
                long done = 0;
                while (done < rsz) {
                    int take = (int)Math.Min((long)buf.Length, rsz - done);
                    IntPtr src = (IntPtr)(mbi.BaseAddress.ToInt64() + done);
                    if (!SafeReadN(src, buf, take)) { done += take; continue; }
                    for (int off = 0; off + 16 <= take; off += 8) {
                        ulong v = BitConverter.ToUInt64(buf, off);
                        if (v == mtByteArr && mtByteArr != 0) {
                            // byte[] 对象: [MT][len][pad][data]
                            int alen = BitConverter.ToInt32(buf, off + 8);
                            if (alen >= 0x8000 && alen <= 0x400000 && dumped < maxBytes && objHits < maxObj) {
                                IntPtr dsrc = (IntPtr)(src.ToInt64() + off + 16);
                                var data = new byte[Math.Min(alen, 1 << 20)];
                                if (SafeRead(dsrc, data)) {
                                    File.WriteAllBytes(Path.Combine(DumpDir, tag + "_bigarr_" + (objHits + 1) + "_len" + alen + ".bin"), data);
                                    Log("[mem] " + tag + " bigarr @0x" + (src.ToInt64() + off).ToString("X") + " len=" + alen + " head=" + BitConverter.ToString(data, 0, 24).Replace("-", ""));
                                    dumped += alen; objHits++;
                                }
                            } else if (censSmall && (alen == 16 || alen == 24 || alen == 32 || alen == 64) && censHits < 4000) {
                                IntPtr osrc = (IntPtr)(src.ToInt64() + off);
                                var head = new byte[16 + alen];
                                if (SafeRead(osrc, head)) {
                                    string hex = BitConverter.ToString(head, 16, alen).Replace("-", "");
                                    Log("[mem] " + tag + " cens byte[" + alen + "] @0x" + osrc.ToInt64().ToString("X") + " = " + hex);
                                    if (censDumps < 1200) { File.WriteAllBytes(Path.Combine(DumpDir, tag + "_cens" + alen + "_" + censDumps + "_0x" + osrc.ToInt64().ToString("X") + ".bin"), head); censDumps++; }
                                    censHits++;
                                }
                            }
                            continue;
                        }
                        string nm = null;
                        for (int k = 0; k < mts.Length; k++) if (v == mts[k] && mts[k] != 0) { nm = names[k]; break; }
                        if (nm == null || objHits >= maxObj) continue;
                        objHits++;
                        Log("[mem] " + tag + " obj " + nm + " #" + objHits + " @0x" + (src.ToInt64() + off).ToString("X"));
                        var obj = new byte[512];
                        if (SafeRead((IntPtr)(src.ToInt64() + off), obj))
                            File.WriteAllBytes(Path.Combine(DumpDir, tag + "_" + nm + "_" + objHits + ".bin"), obj);
                        // 全字段指针追链 (前 0x100B)
                        for (int fo = 8; fo < 0x100; fo += 8) {
                            ulong pv = BitConverter.ToUInt64(obj, fo);
                            if (!LooksLikeHeap(pv)) continue;
                            var tgt = new byte[272];
                            if (!SafeRead((IntPtr)(long)pv, tgt)) continue;
                            ulong tmt = BitConverter.ToUInt64(tgt, 0);
                            if (tmt == mtByteArr) {
                                int tlen = BitConverter.ToInt32(tgt, 8);
                                if (tlen >= 0 && tlen <= 4096) {
                                    var td = new byte[tlen];
                                    if (SafeRead((IntPtr)(long)(pv + 16UL), td) && tlen > 0) {
                                        bool small = tlen == 16 || tlen == 24 || tlen == 32 || tlen == 64;
                                        File.WriteAllBytes(Path.Combine(DumpDir, tag + "_" + nm + "_" + objHits + "_f" + fo + "_arr" + tlen + ".bin"), td);
                                        if (small) Log("[mem] " + tag + " " + nm + "#" + objHits + " field+0x" + fo.ToString("X") + " byte[" + tlen + "] = " + BitConverter.ToString(td).Replace("-", ""));
                                    }
                                }
                            } else {
                                File.WriteAllBytes(Path.Combine(DumpDir, tag + "_" + nm + "_" + objHits + "_f" + fo + "_obj.bin"), tgt);
                            }
                        }
                    }
                    done += take;
                }
            }
            if (next.ToInt64() <= (long)addr) break;
            addr = next;
        }
        Log("[mem] scan " + tag + ": regions=" + regions + " committed=" + (committed >> 20) + "MB objHits=" + objHits + " bigarrKB=" + (dumped >> 10));
    }

    // 反射值递归 dump: 原始类型→log, string→文件+预览, byte[]→文件, IDictionary/IEnumerable→迭代, 其它对象→字段 depth1
    static void DumpFieldValue(string path, object v, string tag, int depth) {
        try {
            if (v == null) { Log("[mem] " + tag + "." + path + " = NULL"); return; }
            var t = v.GetType();
            if (t == typeof(string)) {
                string s = (string)v;
                File.WriteAllText(Path.Combine(DumpDir, tag + "_" + path + ".txt"), s);
                Log("[mem] " + tag + "." + path + " = str len=" + s.Length + " \"" + (s.Length > 100 ? s.Substring(0, 100) : s) + "\"");
            } else if (t == typeof(byte[])) {
                byte[] b = (byte[])v;
                File.WriteAllBytes(Path.Combine(DumpDir, tag + "_" + path + ".bin"), b);
                Log("[mem] " + tag + "." + path + " = byte[" + b.Length + "] head=" + BitConverter.ToString(b, 0, Math.Min(24, b.Length)).Replace("-", ""));
            } else if (t.IsPrimitive || t.IsEnum || t == typeof(decimal)) {
                Log("[mem] " + tag + "." + path + " = " + v);
            } else if (t == typeof(char[]) || t == typeof(int[]) || t == typeof(uint[]) || t == typeof(long[]) || t == typeof(ulong[]) || t == typeof(short[]) || t == typeof(ushort[])) {
                var arr = (Array)v;
                var sw = new StringWriter();
                foreach (var e in arr) sw.Write(e + " ");
                File.WriteAllText(Path.Combine(DumpDir, tag + "_" + path + ".txt"), sw.ToString());
                Log("[mem] " + tag + "." + path + " = " + t.Name + "[" + arr.Length + "]");
            } else if (v is IDictionary) {
                var d = (IDictionary)v;
                Log("[mem] " + tag + "." + path + " = " + t.Name + " Count=" + d.Count);
                int i = 0;
                foreach (DictionaryEntry e in d) {
                    if (i++ >= 200) { Log("[mem] " + tag + "." + path + " ... (truncated)"); break; }
                    DumpFieldValue(path + "[k" + i + "]", e.Key, tag, depth + 1);
                    DumpFieldValue(path + "[v" + i + "]", e.Value, tag, depth + 1);
                }
            } else if (v is IEnumerable) {
                int i = 0;
                Log("[mem] " + tag + "." + path + " = " + t.Name + " (IEnumerable)");
                foreach (var e in (IEnumerable)v) {
                    if (i++ >= 200) { Log("[mem] " + tag + "." + path + " ... (truncated)"); break; }
                    DumpFieldValue(path + "[" + i + "]", e, tag, depth + 1);
                }
            } else if (depth < 2) {
                Log("[mem] " + tag + "." + path + " = obj " + t.FullName);
                foreach (var ff in t.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)) {
                    try { DumpFieldValue(path + "." + ff.Name, ff.GetValue(v), tag, depth + 1); }
                    catch (Exception e2) { Log("[mem] " + tag + "." + path + "." + ff.Name + " EX " + e2.Message); }
                }
                // 常见属性: Key/IV/Mode
                if (depth == 0) {
                    foreach (var pn in new[] { "Key", "IV", "Mode", "BlockSize", "KeySize" }) {
                        try {
                            var pp = t.GetProperty(pn, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                            if (pp != null) Log("[mem] " + tag + "." + path + "." + pn + " = " + pp.GetValue(v, null));
                        } catch {}
                    }
                }
            } else {
                Log("[mem] " + tag + "." + path + " = obj " + t.FullName + " (depth cut)");
            }
        } catch (Exception ex) { Log("[mem] " + tag + "." + path + " DUMP-FAIL " + (ex.InnerException ?? ex).GetType().Name); }
    }

    static string Chain(Exception ex) {
        var sb = new StringBuilder();
        for (var e = ex; e != null; e = e.InnerException) {
            sb.Append(e.GetType().FullName).Append(": ").Append(e.Message);
            var st = e.StackTrace;
            if (st != null) sb.Append(" @ ").Append(st.Split('\n')[0].Trim());
            if (e.InnerException != null) sb.Append("  <--  ");
        }
        return sb.ToString();
    }

    // ==================== mtrack: 并发抓解密窗口的 transform/KEY ====================
    static volatile bool MT_stop = false;
    static volatile bool MT_hot = false;
    static int MT_round = 0;
    static ulong MT_mtRMCrypt = 0, MT_mtByteArr = 0;
    // res[0] 密文块: B[j] = res0[8+16j] (skip=8 框定基准), j=0..7 → 覆盖相邻对框定 skip∈{8,24,40,56,72}
    static byte[][] MT_B;
    // 唯一 KEY/IV 注册: 内容去重, 全部落盘 (本地可用任意框定重测)
    static HashSet<string> MT_seenKey = new HashSet<string>(300000);
    static HashSet<string> MT_seenIv = new HashSet<string>(50000);
    static int MT_uKeys = 0, MT_uIvs = 0;
    static readonly object MT_FileLock = new object();
    static int MT_nKey = 0, MT_nTf = 0, MT_nIv = 0, MT_nB32 = 0;
    static int MT_nI60 = 0, MT_nI8 = 0, MT_nI32 = 0, MT_nG4 = 0;

    static void RunMTrack(string exe) {
        MT_InitCt();
        try { Directory.CreateDirectory(DumpDir); } catch {}
        try { var t0 = new RijndaelManaged().CreateDecryptor(new byte[32], new byte[16]);
              MT_mtRMCrypt = (ulong)t0.GetType().TypeHandle.Value.ToInt64(); } catch (Exception ex) { Log("[mtrack] MT calib FAIL " + ex.Message); }
        try { var ap = new byte[101]; var gh = GCHandle.Alloc(ap, GCHandleType.Pinned);
              MT_mtByteArr = (ulong)Marshal.ReadIntPtr(new IntPtr(gh.AddrOfPinnedObject().ToInt64() - 16)).ToInt64(); gh.Free(); } catch (Exception ex) { Log("[mtrack] MT arr calib FAIL " + ex.Message); }
        Log("[mtrack] MT RMCrypt=" + MT_mtRMCrypt.ToString("X") + " byteArr=" + MT_mtByteArr.ToString("X"));

        var mts = new Thread(MT_ScanLoop); mts.IsBackground = true; mts.Priority = ThreadPriority.AboveNormal; mts.Start();

        Directory.SetCurrentDirectory(Path.GetDirectoryName(exe));
        var asm = Assembly.LoadFrom(exe);
        Log("[mtrack] loaded " + asm.FullName);
        foreach (var m in asm.GetModules()) {
            try { RuntimeHelpers.RunModuleConstructor(m.ModuleHandle); Log("[mtrack] module cctor OK"); }
            catch (Exception ex) { Log("[mtrack] module cctor FAIL: " + Chain(ex)); }
        }
        // 触发 payload 解密路径 (JIT hook 在首次 resolve/JIT 时回填)
        try {
            var mod2 = asm.GetModules()[0];
            var mb0 = mod2.ResolveMethod(0x06002133);
            Log("[mtrack] P1 = " + (mb0.DeclaringType == null ? "?" : mb0.DeclaringType.FullName) + "::" + mb0.Name);
            try { RuntimeHelpers.PrepareMethod(mb0.MethodHandle); Log("[mtrack] PrepareMethod OK"); }
            catch (Exception ex2) { Log("[mtrack] PrepareMethod FAIL " + (ex2.InnerException ?? ex2).Message); }
        } catch (Exception ex) { Log("[mtrack] resolve FAIL " + Chain(ex)); }
        Thread.Sleep(5000);              // 尾扫窗口
        MT_stop = true;
        Thread.Sleep(2500);
        Log("[mtrack] rounds=" + MT_round + " tf=" + MT_nTf + " key=" + MT_nKey + " b32=" + MT_nB32 + " iv=" + MT_nIv + " i60=" + MT_nI60 + " i8=" + MT_nI8 + " i32=" + MT_nI32 + " g4=" + MT_nG4);
        // 验证解密确实发生
        try {
            var mod2 = asm.GetModules()[0];
            var mb = mod2.ResolveMethod(0x06002133);
            var il = mb.GetMethodBody().GetILAsByteArray();
            Log("[mtrack] P1 body len=" + il.Length + " head=" + BitConverter.ToString(il, 0, Math.Min(16, il.Length)).Replace("-", ""));
        } catch (Exception ex) { Log("[mtrack] P1 body FAIL " + Chain(ex)); }
    }

    static void RunMTrack2(string exe) {
        // 与 mtrack 相同的并发扫描, 但在 cctor 后清驱动器缓存并强制重解密, 抓新鲜 transform
        MT_InitCt();
        try { Directory.CreateDirectory(DumpDir); } catch {}
        try { var t0 = new RijndaelManaged().CreateDecryptor(new byte[32], new byte[16]);
              MT_mtRMCrypt = (ulong)t0.GetType().TypeHandle.Value.ToInt64(); } catch (Exception ex) { Log("[mtrack2] MT calib FAIL " + ex.Message); }
        try { var ap = new byte[101]; var gh = GCHandle.Alloc(ap, GCHandleType.Pinned);
              MT_mtByteArr = (ulong)Marshal.ReadIntPtr(new IntPtr(gh.AddrOfPinnedObject().ToInt64() - 16)).ToInt64(); gh.Free(); } catch (Exception ex) { Log("[mtrack2] arr calib FAIL " + ex.Message); }
        Log("[mtrack2] MT RMCrypt=" + MT_mtRMCrypt.ToString("X") + " byteArr=" + MT_mtByteArr.ToString("X"));
        var mts = new Thread(MT_ScanLoop); mts.IsBackground = true; mts.Priority = ThreadPriority.AboveNormal; mts.Start();

        Directory.SetCurrentDirectory(Path.GetDirectoryName(exe));
        var asm = Assembly.LoadFrom(exe);
        Log("[mtrack2] loaded " + asm.FullName);
        foreach (var m in asm.GetModules()) {
            try { RuntimeHelpers.RunModuleConstructor(m.ModuleHandle); Log("[mtrack2] module cctor OK"); }
            catch (Exception ex) { Log("[mtrack2] module cctor FAIL: " + Chain(ex)); }
        }
        // ---- cache bust: 驱动器类静态集合清空 ----
        try {
            var diT = asm.GetType("CloudClient.Templating.DispatcherInitializer");
            var flags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
            Log("[mtrack2] DispatcherInitializer statics:");
            foreach (var f in diT.GetFields(flags)) {
                object v = null;
                try { v = f.GetValue(null); } catch {}
                string desc = "NULL";
                if (v == null) desc = "NULL";
                else if (v is string) desc = "str len=" + ((string)v).Length;
                else desc = v.GetType().Name;
                Log("[mtrack2]   ." + f.Name + " = " + desc);
                System.Collections.Hashtable ht = v as System.Collections.Hashtable;
                if (ht != null) { int n = ht.Count; ht.Clear(); Log("[mtrack2]   CLEARED Hashtable " + f.Name + " (was " + n + ")"); continue; }
                if (v is string) continue;
                System.Collections.IDictionary dc = v as System.Collections.IDictionary;
                if (dc != null) { int n = dc.Count; dc.Clear(); Log("[mtrack2]   CLEARED IDictionary " + f.Name + " (was " + n + ")"); continue; }
                System.Collections.IList il2 = v as System.Collections.IList;
                if (il2 != null) { int n = il2.Count; il2.Clear(); Log("[mtrack2]   CLEARED IList " + f.Name + " (was " + n + ")"); continue; }
                Array a2 = v as Array;
                if (a2 != null && !(v is byte[]) && a2.Length > 0 && a2.Length <= 4096) {
                    try { Array.Clear(a2, 0, a2.Length); Log("[mtrack2]   CLEARED Array " + f.Name + " len=" + a2.Length); } catch {}
                }
            }
        } catch (Exception ex) { Log("[mtrack2] cache bust FAIL " + Chain(ex)); }
        // ---- 强制重解密 (热点窗口: 扫描线程高频只扫 GC 快区) ----
        try {
            var mod2 = asm.GetModules()[0];
            var mD = (MethodInfo)mod2.ResolveMethod(0x0600419C);
            Log("[mtrack2] invoking driver (fresh decrypt, HOT scan)...");
            MT_hot = true;
            try { mD.Invoke(null, null); Log("[mtrack2] driver OK"); }
            catch (Exception ex) { Log("[mtrack2] driver EX " + Chain(ex)); }
            MT_hot = false;
            Log("[mtrack2] HOT window closed, rounds=" + MT_round);
        } catch (Exception ex) { MT_hot = false; Log("[mtrack2] resolve FAIL " + Chain(ex)); }
        Thread.Sleep(3000);
        MT_stop = true;
        Thread.Sleep(2000);
        Log("[mtrack2] rounds=" + MT_round + " tf=" + MT_nTf + " key=" + MT_nKey + " b32=" + MT_nB32 + " iv=" + MT_nIv + " i60=" + MT_nI60 + " tbls");
    }

    // 零值分: b==0 记 2 分, b<0x10 记 1 分 (适合 IL/二进制明文)
    static int MT_Zeros(byte[] p) { int s = 0; foreach (var b in p) { if (b == 0) s += 2; else if (b < 0x10) s++; } return s; }
    // 文本分: 可打印 ASCII 计数 (适合 XML/JSON/资源明文)
    static int MT_Text(byte[] p) { int s = 0; foreach (var b in p) { if ((b >= 0x20 && b <= 0x7E) || b == 9 || b == 10 || b == 13) s++; } return s; }

    static void MT_InitCt() {
        string[] bh = new string[] {
            "0465e85ae8abba16f4f90e16ce3b3dbf",
            "42e4b7f2128462e446d95f36bdbb828e",
            "074d8b9b40d50aa55049bf722183621e",
            "d9889dd684a7fd35975c3011b3d285e6",
            "14ee72328a3325e295177cbc7d68ed77",
            "35152abf256458d09a379e79cf7167a2",
            "8576a497690f4e8da9c46a66c1b2dd9d",
            "1dcd2b7db523901c9ba4119b03b59765"
        };
        MT_B = new byte[8][];
        for (int j = 0; j < 8; j++) {
            MT_B[j] = new byte[16];
            for (int i = 0; i < 16; i++) MT_B[j][i] = Convert.ToByte(bh[j].Substring(i * 2, 2), 16);
        }
    }

    // 唯一 IV 注册 → dump/ivs16.txt (内容去重)
    static void MT_RegIv(byte[] iv) {
        if (iv == null || iv.Length != 16) return;
        string hex = MT_Hex(iv);
        lock (MT_FileLock) {
            if (!MT_seenIv.Add(hex)) return;
            MT_uIvs++;
            if (MT_uIvs <= 30000) { try { File.AppendAllText(Path.Combine(DumpDir, "ivs16.txt"), hex + " #" + MT_uIvs + "\r\n"); } catch {} }
        }
    }

    // 全框定预言机: ECB 解 8 块 B[0..7], P_j = D_j ^ B[j-1] (j=1..7, 与 IV 无关);
    // 命中 = 存在相邻对 (P_j, P_{j+1}) 满足 零值分双>=20 或 文本分双>=14 → 覆盖 skip∈{8,24,40,56,72} 全部框定
    // 每个 32B KEY 内容只测一次, 全部落盘 dump/keys32.txt
    static void MT_TryAndLog(byte[] key, string tag) {
        if (key == null || key.Length != 32) return;
        bool allZero = true; foreach (var b in key) if (b != 0) { allZero = false; break; }
        if (allZero) return;
        string hex = MT_Hex(key);
        lock (MT_FileLock) {
            if (!MT_seenKey.Add(hex)) return;
            MT_uKeys++;
            if (MT_uKeys <= 200000) { try { File.AppendAllText(Path.Combine(DumpDir, "keys32.txt"), hex + " #" + MT_uKeys + " " + tag + "\r\n"); } catch {} }
        }
        if (MT_B == null) return;
        try {
            using (var rm = new RijndaelManaged()) {
                rm.Mode = CipherMode.ECB; rm.Padding = PaddingMode.None;
                rm.Key = key;
                using (var dec = rm.CreateDecryptor()) {
                    byte[][] D = new byte[8][];
                    for (int j = 0; j < 8; j++) { var d = new byte[16]; dec.TransformBlock(MT_B[j], 0, 16, d, 0); D[j] = d; }
                    byte[][] P = new byte[8][];
                    for (int j = 1; j < 8; j++) {
                        var p = new byte[16];
                        for (int i = 0; i < 16; i++) p[i] = (byte)(D[j][i] ^ MT_B[j - 1][i]);
                        P[j] = p;
                    }
                    for (int j = 1; j < 7; j++) {
                        int z1 = MT_Zeros(P[j]), z2 = MT_Zeros(P[j + 1]);
                        int t1 = MT_Text(P[j]), t2 = MT_Text(P[j + 1]);
                        if ((z1 >= 20 && z2 >= 20) || (t1 >= 14 && t2 >= 14)) {
                            MT_nKey++;
                            Log("[mtrack] *** KEYFOUND tag=" + tag + " key=" + hex + " pair j=" + j + " z=" + z1 + "/" + z2 + " t=" + t1 + "/" + t2);
                            Log("[mtrack] *** P" + j + "=" + MT_Hex(P[j]) + " P" + (j + 1) + "=" + MT_Hex(P[j + 1]));
                            try { File.WriteAllBytes(Path.Combine(DumpDir, "KEYFOUND_" + MT_nKey + "_" + tag + ".bin"), key); } catch {}
                            break;
                        }
                    }
                }
            }
        } catch {}
    }

    static byte MT_GMul(byte a, byte b) {
        int r = 0, aa = a, bb = b;
        while (bb > 0) { if ((bb & 1) != 0) r ^= aa; aa <<= 1; if ((aa & 0x100) != 0) aa ^= 0x1B; bb >>= 1; }
        return (byte)r;
    }
    // MixColumns on 16B = 4 columns (memory order); used to invert D-table mid entries
    static byte[] MT_MixCols(byte[] d) {
        var o = new byte[16];
        for (int c = 0; c < 4; c++) {
            byte s0 = d[c*4], s1 = d[c*4+1], s2 = d[c*4+2], s3 = d[c*4+3];
            o[c*4+0] = (byte)(MT_GMul(2,s0) ^ MT_GMul(3,s1) ^ s2 ^ s3);
            o[c*4+1] = (byte)(s0 ^ MT_GMul(2,s1) ^ MT_GMul(3,s2) ^ s3);
            o[c*4+2] = (byte)(s0 ^ s1 ^ MT_GMul(2,s2) ^ MT_GMul(3,s3));
            o[c*4+3] = (byte)(MT_GMul(3,s0) ^ s1 ^ s2 ^ MT_GMul(2,s3));
        }
        return o;
    }

    static string MT_Hex(byte[] b) {
        var sb = new StringBuilder(b.Length * 2);
        foreach (var x in b) sb.Append(x.ToString("X2"));
        return sb.ToString();
    }

    static void MT_Dump(string name, byte[] data) {
        try { File.WriteAllBytes(Path.Combine(DumpDir, name), data); } catch {}
    }

    static void MT_ScanLoop() {
        try { MT_ScanLoopInner(); }
        catch (Exception ex) { Log("[mtrack] SCAN-THREAD FAIL " + ex.GetType().FullName + ": " + ex.Message); }
        Log("[mtrack] scan thread exit, rounds=" + MT_round);
    }

    static void MT_ScanLoopInner() {
        var buf = new byte[4 << 20];
        var mbi = new MBI();
        var sz = (IntPtr)Marshal.SizeOf(typeof(MBI));
        var seenTf = new HashSet<long>();
        var seen32 = new HashSet<long>();
        var seen60 = new HashSet<long>();
        while (!MT_stop) {
            MT_round++;
            int r = MT_round;
            IntPtr addr = new IntPtr(0x10000);
            while ((long)addr < 0x7FFFFFFEFFFF && !MT_stop) {
                if (VirtualQuery(addr, ref mbi, sz) == IntPtr.Zero) break;
                long rsz = mbi.RegionSize.ToInt64();
                IntPtr next = (IntPtr)(mbi.BaseAddress.ToInt64() + rsz);
                if (rsz <= 0) break;
                bool inFast = mbi.BaseAddress.ToInt64() >= 0x2800000 && mbi.BaseAddress.ToInt64() < 0x3800000;
                if ((r == 1 || MT_hot) && !inFast) { if (next.ToInt64() <= (long)addr) break; addr = next; continue; }
                if (mbi.State == 0x1000 && (mbi.Protect & 0x100) == 0 && (mbi.Protect & 0xFF) != 0x01) {
                    long done = 0;
                    while (done < rsz && !MT_stop) {
                        int take = (int)Math.Min((long)buf.Length, rsz - done);
                        IntPtr src = (IntPtr)(mbi.BaseAddress.ToInt64() + done);
                        if (!SafeReadN(src, buf, take)) { done += take; continue; }
                        for (int off = 0; off + 16 <= take; off += 8) {
                            ulong v = BitConverter.ToUInt64(buf, off);
                            if (MT_mtRMCrypt != 0 && v == MT_mtRMCrypt) {
                                long oa = src.ToInt64() + off;
                                if (!seenTf.Add(oa)) continue;
                                MT_nTf++;
                                if (take - off < 512) continue;   // 跨 buf 尾: 等下一轮覆盖
                                var obj = new byte[512];
                                Array.Copy(buf, off, obj, 0, 512);   // buf 内快照, 零二次读
                                Log("[mtrack] r" + r + " RMCrypt @0x" + oa.ToString("X"));
                                MT_Dump("mtrack_tf_0x" + oa.ToString("X") + "_r" + r + ".bin", obj);
                                for (int fo = 8; fo < 0x100; fo += 8) {
                                    ulong pv = BitConverter.ToUInt64(obj, fo);
                                    if (!LooksLikeHeap(pv)) continue;
                                    // 优先 buf 内读 (同一 RPM 快照, 免 GC 竞争)
                                    long rel = (long)pv - src.ToInt64();
                                    byte[] tgt;
                                    if (rel >= 0 && rel + 272 <= take) {
                                        tgt = new byte[272];
                                        Array.Copy(buf, (int)rel, tgt, 0, 272);
                                    } else {
                                        tgt = new byte[272];
                                        if (!SafeRead((IntPtr)(long)pv, tgt)) continue;
                                    }
                                    int tlen = BitConverter.ToInt32(tgt, 8);
                                    if (tlen == 60) {
                                        var ed = new byte[240];
                                        Array.Copy(tgt, 16, ed, 0, 240);
                                        MT_Dump("mtrack_tbl_0x" + oa.ToString("X") + "_f" + fo + "_r" + r + ".bin", ed);
                                        // E 表头 32B = KEY 原文 (encrypt expansion W[0..7])
                                        var kE = new byte[32]; Array.Copy(ed, 0, kE, 0, 32);
                                        MT_TryAndLog(kE, "Ehead_0x" + oa.ToString("X") + "_f" + fo);
                                        // D 表头: D[0..3]=E[0..3]=KEY[0:16]; D[4..7]=InvMixCol(E[4..7]) → MixCols 还原
                                        var kD = new byte[32];
                                        Array.Copy(ed, 0, kD, 0, 16);
                                        var mid = new byte[16]; Array.Copy(ed, 16, mid, 0, 16);
                                        var mc = MT_MixCols(mid);
                                        Array.Copy(mc, 0, kD, 16, 16);
                                        MT_TryAndLog(kD, "Dhead_0x" + oa.ToString("X") + "_f" + fo);
                                    } else if (tlen == 4) {
                                        var iv = new byte[16];
                                        Array.Copy(tgt, 16, iv, 0, 16);
                                        MT_nIv++;
                                        Log("[mtrack] r" + r + " IV4 @0x" + pv.ToString("X") + " tf@0x" + oa.ToString("X") + " f" + fo + " = " + MT_Hex(iv));
                                        MT_RegIv(iv);
                                    }
                                }
                            } else if (MT_mtByteArr != 0 && v == MT_mtByteArr) {
                                int alen = BitConverter.ToInt32(buf, off + 8);
                                if (alen == 32) {
                                    long oa = src.ToInt64() + off;
                                    if (!seen32.Add(oa)) continue;
                                    MT_nB32++;
                                    if (MT_nB32 <= 40000) {
                                        var k = new byte[32];
                                        Array.Copy(buf, off + 16, k, 0, 32);
                                        MT_TryAndLog(k, "b32_r" + r + "_0x" + oa.ToString("X"));
                                    }
                                } else if (alen == 16) {
                                    var iv = new byte[16];
                                    Array.Copy(buf, off + 16, iv, 0, 16);
                                    MT_nIv++;
                                    MT_RegIv(iv);
                                }
                            } else if (LooksLikeHeap(v)) {
                                // 全局 int[]/uint[] 普查: KEY 组装形态 + 遗漏的 E 表 (MT 任意)
                                int alen = BitConverter.ToInt32(buf, off + 8);
                                long oa = src.ToInt64() + off;
                                if (alen == 60 && MT_nI60 < 2500 && seen60.Add(oa)) {
                                    MT_nI60++;
                                    if (off + 16 + 240 <= take) {
                                        var ed = new byte[240];
                                        Array.Copy(buf, off + 16, ed, 0, 240);
                                        var kE = new byte[32]; Array.Copy(ed, 0, kE, 0, 32);
                                        MT_TryAndLog(kE, "g60_0x" + oa.ToString("X") + "_r" + r);
                                        var kD = new byte[32];
                                        Array.Copy(ed, 0, kD, 0, 16);
                                        var mid2 = new byte[16]; Array.Copy(ed, 16, mid2, 0, 16);
                                        var mc2 = MT_MixCols(mid2);
                                        Array.Copy(mc2, 0, kD, 16, 16);
                                        MT_TryAndLog(kD, "g60D_0x" + oa.ToString("X") + "_r" + r);
                                        if (MT_nI60 <= 2500) MT_Dump("mtrack_g60_0x" + oa.ToString("X") + "_r" + r + ".bin", ed);
                                    }
                                } else if (alen == 8 && MT_nI8 < 12000 && seen60.Add(oa)) {
                                    MT_nI8++;
                                    if (off + 16 + 32 <= take) {
                                        // int[8]: 直接当 32B KEY (int LE 字节流)
                                        var k = new byte[32];
                                        Array.Copy(buf, off + 16, k, 0, 32);
                                        MT_TryAndLog(k, "gi8_0x" + oa.ToString("X") + "_r" + r);
                                    }
                                } else if (alen == 32 && MT_nI32 < 12000 && seen60.Add(oa)) {
                                    MT_nI32++;
                                    if (off + 16 + 128 <= take) {
                                        // int[32]: 每 int <=0xFF 时组装 32B KEY
                                        var k = new byte[32];
                                        bool ok = true;
                                        for (int i = 0; i < 32 && ok; i++) {
                                            int x = BitConverter.ToInt32(buf, off + 16 + 4*i);
                                            if (x < 0 || x > 255) ok = false; else k[i] = (byte)x;
                                        }
                                        if (ok) MT_TryAndLog(k, "gi32_0x" + oa.ToString("X") + "_r" + r);
                                    }
                                } else if (alen == 4 && MT_nG4 < 8000 && seen60.Add(oa)) {
                                    MT_nG4++;
                                    if (off + 16 + 16 <= take) {
                                        var iv = new byte[16];
                                        Array.Copy(buf, off + 16, iv, 0, 16);
                                        MT_nIv++;
                                        MT_RegIv(iv);
                                    }
                                }
                            }
                        }
                        done += take;
                    }
                }
                if (next.ToInt64() <= (long)addr) break;
                addr = next;
            }
            if (r % 5 == 0) Log("[mtrack] round " + r + " tf=" + MT_nTf + " key=" + MT_nKey + " b32=" + MT_nB32 + " iv=" + MT_nIv);
        }
        Log("[mtrack] scan thread exit, rounds=" + MT_round);
    }

    // ==================== mtrack3: 冻结世界扫描 ====================
    // 原理: worker 线程跑 LoadFrom/cctor/驱动器(解密链); 主线程循环
    //   SuspendThread(全部其他线程) → 冻结态做【零分配】GC 堆扫描 → ResumeThread → 处理命中 → thaw 3ms
    // 冻结窗内 transform 必然存活(其所属线程被挂起, 不可能走到 Dispose), E 表必然未清空。
    // thaw 窗(3ms) < res[0] 解密时长(~5-7ms) ⇒ 解密过程必然被冻结截断 ≥1 次 ⇒ 必然捕获活体。
    // 冻结路径审计: 仅 VirtualQuery/ReadProcessMemory/BitConverter/Array.Copy/预分配池写 — 无任何堆分配, 无 Log。
    static volatile bool MT3_stop = false;
    static int MT3_cycles = 0, MT3_susp = 0, MT3_nTfLive = 0, MT3_dropAr = 0, MT3_fulls = 0;
    static HashSet<long> MT3_seenAddr = new HashSet<long>(400000);

    const int MT3_MAXARR = 8192;
    static long[] MT3_arAddr = new long[MT3_MAXARR];
    static int[] MT3_arKind = new int[MT3_MAXARR];   // 0=g60表 1=b32 2=b16 3=big356k
    static byte[][] MT3_arSnap = new byte[MT3_MAXARR][];
    static int MT3_nAr = 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint SuspendThread(IntPtr hThread);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern int ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentThreadId();
    const uint MT3_THREAD_SUSPEND_RESUME = 0x0002;

    static void RunMTrack3Worker(string exe) {
        MT_InitCt();
        try { Directory.CreateDirectory(DumpDir); } catch {}
        Directory.SetCurrentDirectory(Path.GetDirectoryName(exe));
        Log("[mtrack3] worker: loading (freezer cycling)...");
        var asm = Assembly.LoadFrom(exe);
        Log("[mtrack3] loaded " + asm.FullName);
        foreach (var m in asm.GetModules()) {
            try { RuntimeHelpers.RunModuleConstructor(m.ModuleHandle); Log("[mtrack3] module cctor OK"); }
            catch (Exception ex) { Log("[mtrack3] module cctor FAIL: " + Chain(ex)); }
        }
        var mod2 = asm.GetModules()[0];
        for (int it = 0; it < 3; it++) {
            MT3_Bust(asm);
            try {
                var mD = (MethodInfo)mod2.ResolveMethod(0x0600419C);
                Log("[mtrack3] invoke#" + it + " (freezer live)...");
                mD.Invoke(null, null);
                Log("[mtrack3] invoke#" + it + " OK");
            } catch (Exception ex) { Log("[mtrack3] invoke#" + it + " EX " + Chain(ex)); }
            Thread.Sleep(1500);
        }
        Thread.Sleep(3000);
        MT3_stop = true;
        Log("[mtrack3] worker done");
    }

    static void MT3_Bust(Assembly asm) {
        try {
            var diT = asm.GetType("CloudClient.Templating.DispatcherInitializer");
            var flags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
            int cleared = 0;
            foreach (var f in diT.GetFields(flags)) {
                object v = null;
                try { v = f.GetValue(null); } catch {}
                if (v == null) continue;
                System.Collections.Hashtable ht = v as System.Collections.Hashtable;
                if (ht != null) { cleared += ht.Count; ht.Clear(); continue; }
                if (v is string) continue;
                System.Collections.IDictionary dc = v as System.Collections.IDictionary;
                if (dc != null) { cleared += dc.Count; dc.Clear(); continue; }
                System.Collections.IList il2 = v as System.Collections.IList;
                if (il2 != null) { cleared += il2.Count; il2.Clear(); continue; }
                Array a2 = v as Array;
                if (a2 != null && !(v is byte[]) && a2.Length > 0 && a2.Length <= 4096) {
                    try { Array.Clear(a2, 0, a2.Length); cleared += a2.Length; } catch {}
                }
            }
            Log("[mtrack3] cache bust cleared=" + cleared);
        } catch (Exception ex) { Log("[mtrack3] cache bust FAIL " + Chain(ex)); }
    }

    static void MT3_FreezerLoop(Thread w) {
        MT_InitCt();
        try { Directory.CreateDirectory(DumpDir); } catch {}
        try {
            var t0 = new RijndaelManaged().CreateDecryptor(new byte[32], new byte[16]);
            MT_mtRMCrypt = (ulong)t0.GetType().TypeHandle.Value.ToInt64();
        } catch (Exception ex) { Log("[mtrack3] calib FAIL " + ex.Message); }
        try {
            var ap = new byte[101]; var gh = GCHandle.Alloc(ap, GCHandleType.Pinned);
            MT_mtByteArr = (ulong)Marshal.ReadIntPtr(new IntPtr(gh.AddrOfPinnedObject().ToInt64() - 16)).ToInt64(); gh.Free();
        } catch (Exception ex) { Log("[mtrack3] arr calib FAIL " + ex.Message); }
        for (int i = 0; i < MT3_MAXARR; i++) MT3_arSnap[i] = new byte[272];
        Log("[mtrack3] freezer start RMCrypt=" + MT_mtRMCrypt.ToString("X") + " byteArr=" + MT_mtByteArr.ToString("X"));

        var buf = new byte[4 << 20];
        var mbi = new MBI();
        var sz = (IntPtr)Marshal.SizeOf(typeof(MBI));
        var hs = new List<IntPtr>(64);
        uint myTid = GetCurrentThreadId();
        var proc = Process.GetCurrentProcess();
        while (!MT3_stop && w.IsAlive) {
            MT3_cycles++;
            bool full = (MT3_cycles % 40) == 1;
            // ---- freeze: 挂起本线程外全部线程 ----
            hs.Clear();
            proc.Refresh();
            foreach (ProcessThread pt in proc.Threads) {
                if ((uint)pt.Id == myTid) continue;
                if (hs.Count >= 60) break;   // List 扩容会分配 — 冻结段前只有 ~15 个线程, 60 足够
                IntPtr h = OpenThread(MT3_THREAD_SUSPEND_RESUME, false, (uint)pt.Id);
                if (h == IntPtr.Zero) continue;
                if (SuspendThread(h) != 0xFFFFFFFFu) hs.Add(h); else CloseHandle(h);
            }
            MT3_susp += hs.Count;
            // ---- 冻结态扫描 (零分配) ----
            if (full) { MT3_fulls++; MT3_FrozenRange(buf, mbi, sz, 0x10000, 0x7FFFFFFEFFFF); }
            else MT3_FrozenRange(buf, mbi, sz, 0x2800000, 0x3800000);
            // ---- resume ----
            for (int i = 0; i < hs.Count; i++) { ResumeThread(hs[i]); CloseHandle(hs[i]); }
            // ---- 解冻段处理命中 (允许分配/Log) ----
            MT3_ProcessHits();
            Thread.Sleep(3);
        }
        Log("[mtrack3] freezer exit cycles=" + MT3_cycles + " fulls=" + MT3_fulls + " suspends=" + MT3_susp
            + " tfLive=" + MT3_nTfLive + " keyFound=" + MT_nKey + " uKeys=" + MT_uKeys + " uIvs=" + MT_uIvs);
    }

    static void MT3_FrozenRange(byte[] buf, MBI mbi, IntPtr sz, long lo, long hi) {
        IntPtr addr = new IntPtr(lo);
        while ((long)addr < hi) {
            if (VirtualQuery(addr, ref mbi, sz) == IntPtr.Zero) break;
            long rsz = mbi.RegionSize.ToInt64();
            IntPtr next = new IntPtr(mbi.BaseAddress.ToInt64() + rsz);
            if (rsz <= 0) break;
            if (mbi.State == 0x1000 && (mbi.Protect & 0x100) == 0 && (mbi.Protect & 0xFF) != 0x01) {
                long done = 0;
                while (done < rsz) {
                    int take = (int)Math.Min((long)buf.Length, rsz - done);
                    IntPtr src = new IntPtr(mbi.BaseAddress.ToInt64() + done);
                    if (SafeReadN(src, buf, take)) MT3_ScanChunk(buf, take, src);
                    done += take;
                }
            }
            if (next.ToInt64() <= (long)addr) break;
            addr = next;
        }
    }

    static void MT3_ScanChunk(byte[] buf, int take, IntPtr src) {
        long srcBase = src.ToInt64();
        for (int off = 0; off + 16 <= take; off += 8) {
            ulong v = BitConverter.ToUInt64(buf, off);
            if (MT_mtRMCrypt != 0 && v == MT_mtRMCrypt) {
                MT3_nTfLive++;   // 仅计数 (E/D 表由 alen==60 普查覆盖, 无需字段追踪)
            } else if (MT_mtByteArr != 0 && v == MT_mtByteArr) {
                int alen = BitConverter.ToInt32(buf, off + 8);
                if (alen == 32 || alen == 16 || (alen >= 356300 && alen <= 356400)) {
                    long oa = srcBase + off;
                    if (MT3_nAr >= MT3_MAXARR || MT3_seenAddr.Count >= 380000 || !MT3_seenAddr.Add(oa)) continue;
                    int need = alen == 32 ? 32 : (alen == 16 ? 16 : 64);
                    if (take - off - 16 < need) continue;
                    var snap = MT3_arSnap[MT3_nAr];
                    if (snap == null) { MT3_dropAr++; continue; }
                    Array.Copy(buf, off + 16, snap, 0, need);
                    MT3_arAddr[MT3_nAr] = oa;
                    MT3_arKind[MT3_nAr] = alen == 32 ? 1 : (alen == 16 ? 2 : 3);
                    if (MT3_arKind[MT3_nAr] == 3) {
                        MT4_saw356Addr = oa;
                        // res[0] CT/PT 头 8B 区分 (20efb9d7a4dc0500=CT, f5410006215b4000=PT)
                        ulong h = BitConverter.ToUInt64(buf, off + 16);
                        if (h == 0x0500dca4d7b9ef20UL) MT4_ctSeen = true;
                        else if (h == 0x00405b21060041f5UL) MT4_ptSeen = true;
                    }
                    MT3_nAr++;
                }
            } else if (LooksLikeHeap(v)) {
                int alen = BitConverter.ToInt32(buf, off + 8);
                if (alen == 60) {
                    long oa = srcBase + off;
                    if (MT3_nAr >= MT3_MAXARR || MT3_seenAddr.Count >= 380000 || !MT3_seenAddr.Add(oa)) continue;
                    if (take - off - 16 < 240) continue;
                    var snap = MT3_arSnap[MT3_nAr];
                    if (snap == null) { MT3_dropAr++; continue; }
                    Array.Copy(buf, off + 16, snap, 0, 240);
                    MT3_arAddr[MT3_nAr] = oa; MT3_arKind[MT3_nAr] = 0; MT3_nAr++;
                }
            }
        }
    }

    static void MT3_ProcessHits() {
        int nAr = MT3_nAr; MT3_nAr = 0;
        for (int i = 0; i < nAr; i++) {
            var snap = MT3_arSnap[i];
            long oa = MT3_arAddr[i];
            int kind = MT3_arKind[i];
            if (kind == 0) {
                var kE = new byte[32]; Array.Copy(snap, 0, kE, 0, 32);
                MT_TryAndLog(kE, "mt3g60_0x" + oa.ToString("X"));
                var kD = new byte[32]; Array.Copy(snap, 0, kD, 0, 16);
                var mid = new byte[16]; Array.Copy(snap, 16, mid, 0, 16);
                Array.Copy(MT_MixCols(mid), 0, kD, 16, 16);
                MT_TryAndLog(kD, "mt3g60D_0x" + oa.ToString("X"));
            } else if (kind == 1) {
                var k = new byte[32]; Array.Copy(snap, 0, k, 0, 32);
                MT_TryAndLog(k, "mt3b32_0x" + oa.ToString("X"));
            } else if (kind == 2) {
                var iv = new byte[16]; Array.Copy(snap, 0, iv, 0, 16);
                MT_RegIv(iv);
            } else {
                var h64 = new byte[64]; Array.Copy(snap, 0, h64, 0, 64);
                Log("[mtrack3] *** BIG356K @0x" + oa.ToString("X") + " head64=" + MT_Hex(h64));
            }
        }
        if (nAr > 0 && (MT3_cycles % 10 == 0))
            Log("[mtrack3] cycle " + MT3_cycles + " arr=" + nAr + " uKeys=" + MT_uKeys + " uIvs=" + MT_uIvs + " keyFound=" + MT_nKey);
    }

    // ==================== mtrack4: BIG356K 触发 → 冻结态全 MEM_PRIVATE 快照 ====================
    // 依据 mtrack3 证据: res[0] 密文缓冲 @0x147A92A0 (loader/native 堆, 快区轮不可见, 仅全堆轮命中过一次);
    // res5 已知 KEY 不在 890 唯一 b32 → KEY 非 GC 堆 byte[32] 或存活期 <thaw 窗。
    // 策略: PhaseA 快进(thaw 8ms)盯 .147 窗 16MB+快区 16MB; 首次命中 BIG356K(=资源流刚读入, 解密即将开始)
    // → 冻结态内当轮全 MEM_PRIVATE 快照落盘(预算 768MB, 低址优先) + 后续 2 轮热窗 dump; 慢动作(thaw 1ms) 40 轮。
    // 本地离线对快照逐 8B 窗口暴力 AES 试解 — KEY 不限形态/位置, 在快照里即可恢复。
    static bool MT4_armed = true;
    static volatile bool MT4_ctSeen = false, MT4_ptSeen = false;
    static int MT4_slowLeft = 0, MT4_dumpLeft = 0, MT4_nDumps = 0;
    static long MT4_saw356Addr = 0;
    static long MT4_budget = 768L << 20;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW([MarshalAs(UnmanagedType.LPWStr)] string name, uint access, uint share, IntPtr sa, uint creat, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(IntPtr h, byte[] buf, uint n, out uint written, IntPtr overlapped);
    const uint MT4_GENERIC_WRITE = 0x40000000, MT4_CREATE_ALWAYS = 2, MT4_FILE_ATTR = 0x80;

    // 段表 (冻结态收集, post-thaw 落盘)
    const int MT4_MAXSEG = 4096;
    static long[] MT4_segLo = new long[MT4_MAXSEG], MT4_segHi = new long[MT4_MAXSEG], MT4_segOff = new long[MT4_MAXSEG];
    static int MT4_nSeg = 0;

    static void MT4_RunWorker(string exe) {
        MT_InitCt();
        try { Directory.CreateDirectory(DumpDir); } catch {}
        Directory.SetCurrentDirectory(Path.GetDirectoryName(exe));
        Log("[mtrack4] worker: loading (freezer cycling)...");
        var asm = Assembly.LoadFrom(exe);
        Log("[mtrack4] loaded " + asm.FullName);
        foreach (var m in asm.GetModules()) {
            try { RuntimeHelpers.RunModuleConstructor(m.ModuleHandle); Log("[mtrack4] module cctor OK"); }
            catch (Exception ex) { Log("[mtrack4] module cctor FAIL: " + Chain(ex)); }
        }
        var mod2 = asm.GetModules()[0];
        for (int it = 0; it < 3; it++) {
            MT3_Bust(asm);
            try {
                var mD = (MethodInfo)mod2.ResolveMethod(0x0600419C);
                Log("[mtrack4] invoke#" + it + " ...");
                mD.Invoke(null, null);
                Log("[mtrack4] invoke#" + it + " OK");
            } catch (Exception ex) { Log("[mtrack4] invoke#" + it + " EX " + Chain(ex)); }
            Thread.Sleep(1500);
        }
        Thread.Sleep(3000);
        MT3_stop = true;
        Log("[mtrack4] worker done");
    }

    // 冻结态快照: 全 MEM_PRIVATE commit 段, 低址优先, 预算封顶
    static void MT4_DumpAll(byte[] buf, int cycle) {
        MT4_nSeg = 0;
        long budget = MT4_budget;
        IntPtr h = CreateFileW("dump\\snap_all_" + cycle + ".bin", MT4_GENERIC_WRITE, 0, IntPtr.Zero, MT4_CREATE_ALWAYS, MT4_FILE_ATTR, IntPtr.Zero);
        if (h == (IntPtr)(-1)) { Log("[mtrack4] snap create FAIL cycle=" + cycle); return; }
        long written = 0;
        IntPtr addr = new IntPtr(0x10000);
        MBI mbi = new MBI();
        IntPtr sz = (IntPtr)Marshal.SizeOf(typeof(MBI));
        while ((long)addr < 0x7FFFFFFEFFFF && budget > 0) {
            if (VirtualQuery(addr, ref mbi, sz) == IntPtr.Zero) break;
            long rsz = mbi.RegionSize.ToInt64();
            IntPtr next = new IntPtr(mbi.BaseAddress.ToInt64() + rsz);
            if (rsz <= 0) break;
            if (mbi.State == 0x1000 && (mbi.Protect & 0x100) == 0 && (mbi.Protect & 0xFF) != 0x01 && mbi.Type == 0x20000) {
                long lo = mbi.BaseAddress.ToInt64(), hi = lo + rsz, segStart = written;
                long a = lo;
                while (a < hi && budget > 0) {
                    int take = (int)Math.Min((long)buf.Length, Math.Min(hi - a, budget));
                    if (take <= 0) break;
                    IntPtr got;
                    if (ReadProcessMemory(GetCurrentProcess(), new IntPtr(a), buf, (IntPtr)take, out got) && got.ToInt64() == take) {
                        uint w;
                        if (!WriteFile(h, buf, (uint)take, out w, IntPtr.Zero)) break;
                        written += take; budget -= take;
                    }
                    a += take;
                }
                if (written > segStart && MT4_nSeg < MT4_MAXSEG) {
                    MT4_segLo[MT4_nSeg] = lo; MT4_segHi[MT4_nSeg] = hi; MT4_segOff[MT4_nSeg] = segStart; MT4_nSeg++;
                }
            }
            if (next.ToInt64() <= (long)addr) break;
            addr = next;
        }
        CloseHandle(h);
        MT4_nDumps++;
        Log("[mtrack4] *** SNAP cycle=" + cycle + " bytes=" + written + " segs=" + MT4_nSeg + " (budget left " + budget + ")");
    }

    // 热窗快照 (动态锚点: LOH±32MB + loaderMT±16MB + 快区)
    static void MT4_DumpHot(byte[] buf, int cycle, long lohAddr, long mtAddr) {
        long budget = 96L << 20;
        IntPtr h = CreateFileW("dump\\snap_hot_" + cycle + ".bin", MT4_GENERIC_WRITE, 0, IntPtr.Zero, MT4_CREATE_ALWAYS, MT4_FILE_ATTR, IntPtr.Zero);
        if (h == (IntPtr)(-1)) return;
        var wins = new List<long[]>();
        if (lohAddr > 0) { long lo = Math.Max(0x10000, lohAddr - (32L << 20)); wins.Add(new long[] { lo, lohAddr + (32L << 20) }); }
        if (mtAddr > 0) { long lo = Math.Max(0x10000, mtAddr - (16L << 20)); wins.Add(new long[] { lo, mtAddr + (16L << 20) }); }
        wins.Add(new long[] { 0x2800000, 0x3800000 });
        foreach (long[] wh in wins) {
            long a = wh[0];
            while (a < wh[1] && budget > 0) {
                int take = (int)Math.Min((long)buf.Length, Math.Min(wh[1] - a, budget));
                if (take <= 0) break;
                IntPtr got;
                if (ReadProcessMemory(GetCurrentProcess(), new IntPtr(a), buf, (IntPtr)take, out got) && got.ToInt64() == take) {
                    uint w;
                    WriteFile(h, buf, (uint)take, out w, IntPtr.Zero);
                    budget -= take;
                }
                a += take;
            }
        }
        CloseHandle(h);
        MT4_nDumps++;
        Log("[mtrack4] snap_hot cycle=" + cycle + " (budget left " + budget + ")");
    }

    static void MT4_FreezerLoop(Thread w) {
        MT_InitCt();
        try { Directory.CreateDirectory(DumpDir); } catch {}
        try {
            var t0 = new RijndaelManaged().CreateDecryptor(new byte[32], new byte[16]);
            MT_mtRMCrypt = (ulong)t0.GetType().TypeHandle.Value.ToInt64();
        } catch (Exception ex) { Log("[mtrack4] calib FAIL " + ex.Message); }
        try {
            var ap = new byte[101]; var gh = GCHandle.Alloc(ap, GCHandleType.Pinned);
            MT_mtByteArr = (ulong)Marshal.ReadIntPtr(new IntPtr(gh.AddrOfPinnedObject().ToInt64() - 16)).ToInt64(); gh.Free();
        } catch (Exception ex) { Log("[mtrack4] arr calib FAIL " + ex.Message); }
        // 动态锚点: LOH (pin >85KB 数组 → 大对象堆实时地址) + loader 堆 (byte[] MT 地址)
        long lohAddr = 0;
        GCHandle lohPin = new GCHandle();
        try {
            var big = new byte[1 << 20]; big[0] = 0xAA;
            lohPin = GCHandle.Alloc(big, GCHandleType.Pinned);
            lohAddr = lohPin.AddrOfPinnedObject().ToInt64() - 16;
        } catch (Exception ex) { Log("[mtrack4] LOH pin FAIL " + ex.Message); }
        long mtAddr = (long)MT_mtByteArr;
        for (int i = 0; i < MT3_MAXARR; i++) MT3_arSnap[i] = new byte[272];
        Log("[mtrack4] freezer start RMCrypt=" + MT_mtRMCrypt.ToString("X") + " byteArr=" + MT_mtByteArr.ToString("X")
            + " loh=0x" + lohAddr.ToString("X") + " mt=0x" + mtAddr.ToString("X"));

        var buf = new byte[4 << 20];
        var mbi = new MBI();
        var sz = (IntPtr)Marshal.SizeOf(typeof(MBI));
        var hs = new List<IntPtr>(64);
        uint myTid = GetCurrentThreadId();
        var proc = Process.GetCurrentProcess();
        var segSb = new StringBuilder();
        while (!MT3_stop && w.IsAlive) {
            MT3_cycles++;
            // ---- freeze ----
            hs.Clear();
            proc.Refresh();
            foreach (ProcessThread pt in proc.Threads) {
                if ((uint)pt.Id == myTid) continue;
                if (hs.Count >= 60) break;
                IntPtr h = OpenThread(MT3_THREAD_SUSPEND_RESUME, false, (uint)pt.Id);
                if (h == IntPtr.Zero) continue;
                if (SuspendThread(h) != 0xFFFFFFFFu) hs.Add(h); else CloseHandle(h);
            }
            MT3_susp += hs.Count;
            // ---- 冻结态扫描: 动态锚点窗口 (LOH±32MB + loaderMT±16MB + 快区) ----
            MT4_saw356Addr = 0; MT4_ctSeen = false; MT4_ptSeen = false;
            if (lohAddr > 0) {
                long lo = lohAddr - (32L << 20); if (lo < 0x10000) lo = 0x10000;
                MT3_FrozenRange(buf, mbi, sz, lo, lohAddr + (32L << 20));
            }
            if (mtAddr > 0) {
                long lo2 = mtAddr - (16L << 20); if (lo2 < 0x10000) lo2 = 0x10000;
                MT3_FrozenRange(buf, mbi, sz, lo2, mtAddr + (16L << 20));
            }
            MT3_FrozenRange(buf, mbi, sz, 0x2800000, 0x3800000);
            // ---- CT (res[0] 密文) 首现 → 开闸: 连续 10 轮 DumpAll 覆盖解密全程 ----
            if (MT4_ctSeen && MT4_armed) {
                MT4_armed = false;
                MT4_slowLeft = 60; MT4_dumpLeft = 10;
                Log("[mtrack4] *** CT SEEN @0x" + MT4_saw356Addr.ToString("X") + " cycle=" + MT3_cycles
                    + " pt=" + MT4_ptSeen + " → SNAP BURST (10)");
                MT4_DumpAll(buf, MT3_cycles);
                MT4_dumpLeft--;
            }
            if (MT4_dumpLeft > 0) {
                MT4_dumpLeft--;
                Log("[mtrack4] burst snap cycle=" + MT3_cycles + " ct=" + MT4_ctSeen + " pt=" + MT4_ptSeen);
                MT4_DumpAll(buf, MT3_cycles);
            } else if (MT4_dumpLeft == 0 && !MT4_armed && MT4_ptSeen && MT4_slowLeft == 0) {
                MT4_DumpHot(buf, MT3_cycles, lohAddr, mtAddr);
            }
            // ---- resume ----
            for (int i = 0; i < hs.Count; i++) { ResumeThread(hs[i]); CloseHandle(hs[i]); }
            // ---- 解冻段处理 ----
            if (MT4_nSeg > 0) {
                segSb.Length = 0;
                for (int i = 0; i < MT4_nSeg; i++)
                    segSb.AppendLine(MT4_segOff[i] + " " + MT4_segLo[i] + " " + (MT4_segHi[i] - MT4_segLo[i]));
                try { File.WriteAllText("dump\\snap_index_" + MT3_cycles + ".txt", segSb.ToString()); } catch {}
                MT4_nSeg = 0;
            }
            MT3_ProcessHits();
            Thread.Sleep(MT4_slowLeft > 0 ? 1 : 2);
            if (MT4_slowLeft > 0) MT4_slowLeft--;
        }
        if (lohPin.IsAllocated) lohPin.Free();
        Log("[mtrack4] freezer exit cycles=" + MT3_cycles + " suspends=" + MT3_susp + " dumps=" + MT4_nDumps
            + " keyFound=" + MT_nKey + " uKeys=" + MT_uKeys + " uIvs=" + MT_uIvs);
    }
}
