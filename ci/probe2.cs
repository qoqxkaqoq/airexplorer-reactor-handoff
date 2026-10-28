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
        }
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
    static bool LooksLikeHeap(ulong pv) { return pv > 0x10000UL && pv < 0x7FFFFFFEFFFFUL; }

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
        ulong mtRMCrypt = 0, mtAesCSPCrypt = 0, mtRijndael = 0, mtAesCSP = 0, mtByteArr = (ulong)typeof(byte[]).TypeHandle.Value.ToInt64();
        try { mtRMCrypt = (ulong)new RijndaelManaged().CreateDecryptor(new byte[32], new byte[16]).GetType().TypeHandle.Value.ToInt64(); } catch (Exception ex) { Log("[mem] D RMCrypt FAIL " + ex.Message); }
        try { mtAesCSPCrypt = (ulong)new AesCryptoServiceProvider().CreateDecryptor(new byte[32], new byte[16]).GetType().TypeHandle.Value.ToInt64(); } catch (Exception ex) { Log("[mem] D AesCSPCrypt FAIL " + ex.Message); }
        try { mtRijndael = (ulong)typeof(RijndaelManaged).TypeHandle.Value.ToInt64(); } catch {}
        try { mtAesCSP = (ulong)typeof(AesCryptoServiceProvider).TypeHandle.Value.ToInt64(); } catch {}
        Log("[mem] D. MT: RMCrypt=" + mtRMCrypt.ToString("X") + " AesCSPCrypt=" + mtAesCSPCrypt.ToString("X") + " RijndaelManaged=" + mtRijndael.ToString("X") + " AesCSP=" + mtAesCSP.ToString("X") + " byte[]=" + mtByteArr.ToString("X"));

        var algMTs = new[] { mtRijndael, mtAesCSP, mtRMCrypt, mtAesCSPCrypt };
        var algNames = new[] { "RijndaelManaged", "AesCSP", "RMCrypt", "AesCSPCrypt" };

        // ---- E. 清堆后 S1 扫描 (module cctor 残留) ----
        try { GC.Collect(); GC.WaitForPendingFinalizers(); } catch {}
        ScanHeap("s1", algMTs, algNames, mtByteArr, 60, 32 << 20);

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
        ScanHeap("s2", algMTs, algNames, mtByteArr, 60, 32 << 20);

        // ---- I. ITP 预热 (res5 字符串池填充) → stat2 ----
        try {
            var itp = (MethodInfo)mod.ResolveMethod(0x06004196);
            foreach (var id in new[] { 0, 1, 2, 100, 1000, 12345, 0x40000000 }) {
                try { var s = (string)itp.Invoke(null, new object[] { id }); Log("[mem] I. ITP(" + id + ") len=" + (s == null ? -1 : s.Length) + " \"" + (s == null ? "" : s.Substring(0, Math.Min(60, s.Length))) + "\""); }
                catch (Exception ex) { Log("[mem] I. ITP(" + id + ") EX " + (ex.InnerException ?? ex).Message); }
            }
        } catch (Exception ex) { Log("[mem] I resolve FAIL " + ex.Message); }
        if (diT != null) {
            foreach (var f in diT.GetFields(flags)) DumpFieldValue(f.Name, f.GetValue(null), "stat2", 0);
        }
        Log("[mem] stat2 done");
    }

    // 堆扫描 v2: ReadProcessMemory 全读; MT 命中 → dump 512B + 全字段指针追链(byte[] MT → len∈{16,24,32,64} 直接打印 hex); byte[] MT → len≥32KB dump 数据
    static void ScanHeap(string tag, ulong[] mts, string[] names, ulong mtByteArr, int maxObj, long maxBytes) {
        long dumped = 0; int objHits = 0;
        var buf = new byte[4 << 20];
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
                    byte[] chunk = new byte[take];
                    if (!SafeRead(src, chunk)) { done += take; continue; }
                    Buffer.BlockCopy(chunk, 0, buf, 0, take);
                    for (int off = 0; off + 16 <= take; off += 8) {
                        ulong v = BitConverter.ToUInt64(buf, off);
                        if (v == mtByteArr && mtByteArr != 0) {
                            // byte[] 大数组: [MT][len][pad][data]
                            int alen = BitConverter.ToInt32(buf, off + 8);
                            if (alen >= 0x8000 && alen <= 0x400000 && dumped < maxBytes && objHits < maxObj) {
                                IntPtr dsrc = (IntPtr)(src.ToInt64() + off + 16);
                                var data = new byte[Math.Min(alen, 1 << 20)];
                                if (SafeRead(dsrc, data)) {
                                    File.WriteAllBytes(Path.Combine(DumpDir, tag + "_bigarr_" + (objHits + 1) + "_len" + alen + ".bin"), data);
                                    Log("[mem] " + tag + " bigarr @0x" + (src.ToInt64() + off).ToString("X") + " len=" + alen + " head=" + BitConverter.ToString(data, 0, 24).Replace("-", ""));
                                    dumped += alen; objHits++;
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
