// host.cs — 在受控宿主中调用目标 WinForms 程序入口, 用于抓取未处理异常的完整堆栈
// v3: invoke 放后台线程 + 超时 Thread.Abort —— Abort 异常的栈 = 死循环/卡死位置(定位 CPU 满转)
using System;
using System.Reflection;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

class Host {
    static string TraceFile = "host_trace.txt";
    static Exception _workerEx;
    static bool _returned;

    static void Dump(string tag, Exception ex) {
        var sb = new StringBuilder();
        sb.AppendLine("=== " + tag + " " + DateTime.Now.ToString("HH:mm:ss.fff") + " ===");
        for (Exception e = ex; e != null; e = e.InnerException) {
            sb.AppendLine("EX " + e.GetType().FullName + ": " + e.Message);
            if (e.Data != null)
                foreach (var k in e.Data.Keys) sb.AppendLine("   DATA[" + k + "] = " + e.Data[k]);
            sb.AppendLine(e.StackTrace);
            sb.AppendLine("-- inner --");
        }
        File.AppendAllText(TraceFile, sb.ToString());
        Console.Write(sb.ToString());
        try { Console.Out.Flush(); } catch {}
    }

    [STAThread]
    static int Main(string[] a) {
        AppDomain.CurrentDomain.UnhandledException += delegate(object s, UnhandledExceptionEventArgs e) {
            Dump("UNHANDLED", e.ExceptionObject as Exception ?? new Exception("(null exception object)"));
        };
        Application.ThreadException += delegate(object s, System.Threading.ThreadExceptionEventArgs e) {
            Dump("THREAD-EX", e.Exception);
        };
        try {
            var path = Path.GetFullPath(a[0]);
            Directory.SetCurrentDirectory(Path.GetDirectoryName(path));
            File.AppendAllText(TraceFile, "=== host v3 start " + DateTime.Now.ToString("HH:mm:ss.fff") + " ===" + Environment.NewLine);
            var asm = Assembly.LoadFrom(path);
            Console.WriteLine("[ost] loaded " + asm.FullName);
            var ep = asm.EntryPoint;
            Console.WriteLine("[ost] entry " + ep.DeclaringType + "::" + ep.Name);
            object[] args = ep.GetParameters().Length == 1 ? new object[] { new string[0] } : new object[0];

            var worker = new Thread(delegate() {
                try {
                    ep.Invoke(null, args);
                    _returned = true;
                    Console.WriteLine("[ost] entry returned");
                } catch (ThreadAbortException tab) {
                    // 超时 Abort: 栈即卡死位置
                    Dump("ABORTED-STUCK(死循环/卡点栈)", tab);
                    Thread.ResetAbort();
                } catch (Exception ex) {
                    _workerEx = ex;
                    Dump("ENTRY-INVOCATION", ex);
                }
            });
            worker.SetApartmentState(ApartmentState.STA);
            worker.Start();
            // v4: 心跳监控(每5s落盘) — 区分主线程卡点 vs worker卡点
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (worker.IsAlive && sw.Elapsed.TotalSeconds < 70) {
                Thread.Sleep(5000);
                string hb = "=== heartbeat " + (int)sw.Elapsed.TotalSeconds + "s alive=" + worker.IsAlive + " ===";
                try { File.AppendAllText(TraceFile, hb + Environment.NewLine); } catch {}
                // 不写 Console: PowerShell 管道缓冲满会阻塞主线程(stdout 塞满即死锁)
            }
            if (worker.IsAlive) {
                Console.WriteLine("[ost] TIMEOUT — aborting to capture stuck stack");
                try { File.AppendAllText(TraceFile, "=== TIMEOUT — aborting worker ===" + Environment.NewLine); } catch {}
                try { worker.Abort(); } catch {}
                worker.Join(8000);
            }
            if (_returned) {
                File.AppendAllText(TraceFile, "=== entry returned normally ===" + Environment.NewLine);
                return 0;
            }
            if (_workerEx != null) return 1;
            // 卡死后被 abort: 让 probe 继续跑剩余流程(窗口检查由外层负责)
            Console.WriteLine("[ost] worker stuck-aborted, continuing");
            return 2;
        } catch (Exception ex) {
            Dump("HOST-FATAL", ex);
            return 1;
        }
    }
}
