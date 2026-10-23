// host6.cs — 字符串抓取器: 加载官方原版正常启动(引导完整, 解密器就位, _TemplateNotifierSize>=75
// 使 ITP 的 StackFrame 保护自动跳过), 然后反射批量调用 InstantiateTransferableProgram(id) 抓明文。
// 用法: host6.exe <exe> <ids.txt> <out.json> <delaySec>
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

class Host6 {
    static string TraceFile = "fetch_trace.txt";

    [STAThread]
    static int Main(string[] a) {
        var exePath = Path.GetFullPath(a[0]);
        var idsFile = Path.GetFullPath(a[1]);
        var outFile = Path.GetFullPath(a[2]);
        int delay = a.Length > 3 ? int.Parse(a[3]) : 15;
        Directory.SetCurrentDirectory(Path.GetDirectoryName(exePath));
        File.AppendAllText(TraceFile, "=== host6 start " + DateTime.Now.ToString("HH:mm:ss.fff") + " ===\n");
        try {
            var asm = Assembly.LoadFrom(exePath);
            Console.WriteLine("[h6] loaded " + asm.FullName);
            var ids = new List<long>();
            foreach (var ln in File.ReadAllLines(idsFile)) {
                long v; if (long.TryParse(ln.Trim(), out v)) ids.Add(v);
            }
            Console.WriteLine("[h6] ids=" + ids.Count);
            File.AppendAllText(TraceFile, "ids=" + ids.Count + "\n");

            Exception entryEx = null;
            var worker = new Thread(delegate() {
                try {
                    var ep = asm.EntryPoint;
                    object[] args = ep.GetParameters().Length == 1 ? new object[] { new string[0] } : new object[0];
                    ep.Invoke(null, args);
                } catch (Exception ex) {
                    entryEx = ex;
                    var sb = new System.Text.StringBuilder("=== ENTRY EX ===\n");
                    for (var e2 = ex; e2 != null; e2 = e2.InnerException) { sb.AppendLine(e2.GetType().FullName + ": " + e2.Message); sb.AppendLine(e2.StackTrace); sb.AppendLine("-- inner --"); }
                    try { File.AppendAllText(TraceFile, sb.ToString()); } catch {}
                }
            });
            worker.SetApartmentState(ApartmentState.STA);
            worker.Start();
            Console.WriteLine("[h6] entry launched, waiting " + delay + "s for runtime warmup");
            for (int wsec = 0; wsec < delay; wsec += 5) {
                Thread.Sleep(5000);
                try { File.AppendAllText(TraceFile, "warmup " + (wsec + 5) + "s entryEx=" + (entryEx == null ? "none" : entryEx.GetType().Name) + " alive=" + !worker.Join(0) + "\n"); } catch {}
            }

            var t = asm.GetType("CloudClient.Templating.DispatcherInitializer");
            if (t == null) { Console.WriteLine("[h6] type not found"); return 1; }
            var mi = t.GetMethod("InstantiateTransferableProgram", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
            if (mi == null) { Console.WriteLine("[h6] method not found"); return 1; }
            Console.WriteLine("[h6] fetch start");
            // ★ v3: 反射读 <Module>{a8c2e9b2} 的 m_0d0b145be2 实例的全部字段值 → fv.txt
            try {
                var gmt = asm.GetType("<Module>{a8c2e9b2-2ded-4e79-99b6-076d192b5696}");
                if (gmt != null) {
                    var sf = gmt.GetField("m_0d0b145be2b94a7c8e4fcaf9a9649f1f", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
                    var obj = sf == null ? null : sf.GetValue(null);
                    var fw = new StreamWriter("fv.txt");
                    fw.WriteLine("objNull=" + (obj == null));
                    fw.WriteLine("objType=" + (obj == null ? "?" : obj.GetType().FullName));
                    if (obj != null) {
                        foreach (var f in obj.GetType().GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)) {
                            object v = null; try { v = f.GetValue(obj); } catch {}
                            fw.WriteLine(f.Name + "=" + (v == null ? "null" : v.ToString()));
                        }
                    }
                    fw.Close();
                    Console.WriteLine("[h6] fv.txt written");
                } else Console.WriteLine("[h6] global type not found");
            } catch (Exception fex) { Console.WriteLine("[h6] fv-ex " + fex.Message); File.AppendAllText(TraceFile, "fv-ex " + fex + "\n"); }
            // 探针: 保护计数器当前值
            try {
                var cnt = t.GetField("_TemplateNotifierSize", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
                File.AppendAllText(TraceFile, "TemplateNotifierSize=" + (cnt == null ? "<no field>" : (cnt.GetValue(null) ?? "?").ToString()) + "\n");
            } catch (Exception pex) { File.AppendAllText(TraceFile, "probe-ex " + pex.Message + "\n"); }
            int ok = 0, fail = 0, dbg = 0;
            using (var w = new StreamWriter(outFile)) {
                w.WriteLine("{");
                bool first = true;
                foreach (var id in ids) {
                    string val = null;
                    try { val = mi.Invoke(null, new object[] { (int)id }) as string; }
                    catch (Exception iex) {
                        if (dbg < 3) {
                            dbg++;
                            var sb = new System.Text.StringBuilder("=== id " + id + " EX ===\n");
                            for (var e2 = iex; e2 != null; e2 = e2.InnerException) { sb.AppendLine(e2.GetType().FullName + ": " + e2.Message); sb.AppendLine(e2.StackTrace); sb.AppendLine("-- inner --"); }
                            File.AppendAllText(TraceFile, sb.ToString());
                        }
                    }
                    if (val == null) { fail++; continue; }
                    if (!first) w.WriteLine(",");
                    first = false;
                    w.Write("\"" + id + "\": " + NewtonsoftEscape(val));
                    ok++;
                    if (ok % 1000 == 0) { Console.WriteLine("[h6] " + ok + " fetched"); File.AppendAllText(TraceFile, "progress " + ok + "\n"); }
                }
                w.WriteLine();
                w.WriteLine("}");
            }
            Console.WriteLine("[h6] done ok=" + ok + " fail=" + fail);
            File.AppendAllText(TraceFile, "=== done ok=" + ok + " fail=" + fail + " ===\n");
            Environment.Exit(ok > 0 ? 0 : 1);
            return 0;
        } catch (Exception ex) {
            File.AppendAllText(TraceFile, "FATAL " + ex + "\n");
            Console.WriteLine("[h6] FATAL " + ex.Message);
            return 1;
        }
    }

    // 简易 JSON 字符串转义(避免引入依赖)
    static string NewtonsoftEscape(string s) {
        var sb = new System.Text.StringBuilder(s.Length + 8);
        sb.Append('"');
        foreach (char c in s) {
            switch (c) {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }
}
