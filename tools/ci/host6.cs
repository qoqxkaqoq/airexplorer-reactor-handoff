// host6.cs — 官方运行时状态快照抓取器 v4
// 加载官方原版正常启动(引导完整), 反射 dump 引导类全部静态状态 → snapshot.txt
// 恢复对象: int/string/bool/byte[](base64)/List/enum; 复杂对象展开一层实例字段; 不可恢复标记 SKIP
// 用法: host6.exe <exe> <out.txt> <delaySec>
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;

class Host6 {
    static string TraceFile = "fetch_trace.txt";
    static StreamWriter W;

    static void Log(string s) { W.WriteLine(s); W.Flush(); }

    // 深度遍历: 简单类型直接记, byte[] 记 base64, IEnumerable 展开元素, 自建类型展开一层实例字段
    static void DumpObject(string tag, object obj, int depth) {
        if (obj == null) { Log("NULL " + tag); return; }
        var t = obj.GetType();
        if (t == typeof(int) || t == typeof(bool) || t == typeof(long) || t.IsEnum) { Log("INT " + tag + " " + obj); return; }
        if (t == typeof(string)) { Log("STR " + tag + " " + Convert.ToBase64String(Encoding.UTF8.GetBytes((string)obj))); return; }
        if (t == typeof(byte[])) {
            var b = (byte[])obj;
            if (b.Length > 4000000) { Log("SKIP " + tag + " bytes=" + b.Length); return; }
            Log("B64 " + tag + " " + Convert.ToBase64String(b)); return;
        }
        if (depth > 0 && obj is IEnumerable && t != typeof(System.Security.Cryptography.RSACryptoServiceProvider)) {
            var it = ((IEnumerable)obj).GetEnumerator();
            var items = new List<object>();
            while (it.MoveNext()) { items.Add(it.Current); if (items.Count > 100000) break; }
            Log("LIST " + tag + " " + items.Count);
            foreach (var e in items) DumpObject(tag + "[]", e, depth - 1);
            return;
        }
        if (depth > 0 && !t.FullName.StartsWith("System.")) {
            // 自建类型: 展开一层实例字段
            Log("OBJ " + tag + " " + t.FullName);
            foreach (var f in t.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)) {
                object v = null; try { v = f.GetValue(obj); } catch { }
                DumpObject(tag + "." + f.Name, v, depth - 1);
            }
            return;
        }
        Log("SKIP " + tag + " " + t.FullName);
    }

    [STAThread]
    static int Main(string[] a) {
        var exePath = Path.GetFullPath(a[0]);
        var outFile = Path.GetFullPath(a[1]);
        int delay = a.Length > 2 ? int.Parse(a[2]) : 15;
        Directory.SetCurrentDirectory(Path.GetDirectoryName(exePath));
        W = new StreamWriter(outFile);
        File.AppendAllText(TraceFile, "=== host6 v4 snapshot start ===\n");
        try {
            var asm = Assembly.LoadFrom(exePath);
            Console.WriteLine("[h6] loaded " + asm.FullName);

            Exception entryEx = null;
            var worker = new Thread(delegate() {
                try {
                    var ep = asm.EntryPoint;
                    object[] args = ep.GetParameters().Length == 1 ? new object[] { new string[0] } : new object[0];
                    ep.Invoke(null, args);
                } catch (Exception ex) {
                    entryEx = ex;
                    var sb = new StringBuilder("=== ENTRY EX ===\n");
                    for (var e2 = ex; e2 != null; e2 = e2.InnerException) { sb.AppendLine(e2.GetType().FullName + ": " + e2.Message); }
                    try { File.AppendAllText(TraceFile, sb.ToString()); } catch {}
                }
            });
            worker.SetApartmentState(ApartmentState.STA);
            worker.Start();
            Console.WriteLine("[h6] entry launched, waiting " + delay + "s");
            Thread.Sleep(delay * 1000);
            Console.WriteLine("[h6] snapshot start");

            var flags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
            int dumped = 0;
            // 目标1: DispatcherInitializer 全部静态字段(密钥流 _ExtractorVisitors 在此)
            var di = asm.GetType("CloudClient.Templating.DispatcherInitializer");
            if (di == null) { Console.WriteLine("[h6] DI not found"); return 1; }
            foreach (var f in di.GetFields(flags)) {
                if (f.FieldType.IsPointer) continue;
                object v = null; try { v = f.GetValue(null); } catch { Log("ERR DI." + f.Name); continue; }
                DumpObject("DI." + f.Name, v, 2);
                dumped++;
            }
            // 目标2: <Module>{...} 静态字段(容器实例 → 展开实例字段)
            foreach (var t in asm.GetTypes()) {
                if (!t.FullName.Contains("<Module>{")) continue;
                foreach (var f in t.GetFields(flags)) {
                    object v = null; try { v = f.GetValue(null); } catch { continue; }
                    if (v != null && !(v is int || v is string || v is byte[] || v is bool)) {
                        Log("OBJ " + t.Name + "." + f.Name + " " + v.GetType().FullName);
                        foreach (var f2 in v.GetType().GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)) {
                            object v2 = null; try { v2 = f2.GetValue(v); } catch { }
                            DumpObject(t.Name + "." + f.Name + "." + f2.Name, v2, 1);
                        }
                    } else DumpObject(t.Name + "." + f.Name, v, 1);
                    dumped++;
                }
            }
            // 目标3: TemplateArgument 静态字段
            var ta = asm.GetType("CloudClient.Templating.TemplateArgument");
            if (ta != null) {
                foreach (var f in ta.GetFields(flags)) {
                    object v = null; try { v = f.GetValue(null); } catch { continue; }
                    DumpObject("TA." + f.Name, v, 1);
                    dumped++;
                }
            }
            // 目标4: ArgumentGateway 静态字段(cctor 解密后的明文终值 — agfix 用)
            var ag = asm.GetType("AirExplorer.Values.ArgumentGateway");
            if (ag != null) {
                foreach (var f in ag.GetFields(flags)) {
                    object v = null; try { v = f.GetValue(null); } catch { continue; }
                    DumpObject("AG." + f.Name, v, 1);
                    dumped++;
                }
            }
            // 目标5: RequestWorker 单例 m_RequestClient → 实例字段(_RequestSorter 等)
            var rw = asm.GetType("AirExplorer.Networking.RequestWorker");
            if (rw != null) {
                var mf = rw.GetField("m_RequestClient", flags);
                object inst = null; try { inst = mf.GetValue(null); } catch { }
                if (inst != null) {
                    Log("OBJ RW.m_RequestClient " + inst.GetType().FullName);
                    foreach (var f in inst.GetType().GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)) {
                        object v = null; try { v = f.GetValue(inst); } catch { continue; }
                        DumpObject("RW.m_RequestClient." + f.Name, v, 1);
                    }
                    dumped++;
                } else Log("NULL RW.m_RequestClient");
            }
            Console.WriteLine("[h6] dumped " + dumped + " static fields");
            File.AppendAllText(TraceFile, "=== snapshot done " + dumped + " fields ===\n");
            W.Close();
            Environment.Exit(0);
            return 0;
        } catch (Exception ex) {
            File.AppendAllText(TraceFile, "FATAL " + ex + "\n");
            Console.WriteLine("[h6] FATAL " + ex.Message);
            try { W.Close(); } catch {}
            return 1;
        }
    }
}
