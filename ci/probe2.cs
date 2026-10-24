// probe2 — v132 反射探针 (Windows CI, net48)
// 用法: probe2 <exe> <mode> [timeoutSec]
//   mode=ag   触发 AG.cctor → 读全部 AG 静态字段 → 调 EvaluateVisibleAttribute → 抓完整异常链
//   mode=itp  触发引导 → 抽样调 ITP(id) 验证解密器语义
// 所有调用都在独立 STA 线程 + 看门狗(默认 90s, 超时强杀进程, 防状态机死循环)
using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
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
                    var vsT = asm.GetType("ValidatorSchema") ?? asm.GetTypes().First(t => t.Name == "ValidatorSchema");
                    var cct = vsT.GetField("CheckCustomizableTransmitter", flagsS).GetValue(null);
                    var sBridge = vsT.GetMethod("ExecuteExplorer", flagsS);
                    var s = (string)sBridge.Invoke(null, new[] { (object)dir, label, cct });
                    Log("[probe2] CHAIN CheckCustomizableTransmitter(dir,label) = " + (s == null ? "NULL" : "\"" + s + "\" len=" + s.Length));
                    var gvT = asm.GetTypes().First(t => t.Name == "GroupedValidator");
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
        }
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
