// probe2 — v132 反射探针 (Windows CI, net48)
// 用法: probe2 <exe> <mode> [timeoutSec]
//   mode=ag   触发 AG.cctor → 读全部 AG 静态字段 → 调 EvaluateVisibleAttribute → 抓完整异常链
//   mode=itp  触发引导 → 抽样调 ITP(id) 验证解密器语义
//   mode=mem  静态字段全dump + 全方法IL dump + 反射invoke解密链 + 自进程堆扫描(transform/key/大byte[])
// 所有调用都在独立 STA 线程 + 看门狗(默认 90s, 超时强杀进程, 防状态机死循环)
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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

        Exception runEx = null;
        var worker = new Thread(delegate() {
            try { Run(exe, mode); Log("[probe2] DONE"); }
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
        }
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
}
