// host.cs — 在受控宿主中调用目标 WinForms 程序入口, 用于抓取未处理异常的完整堆栈
// v2: 异常同步落盘 host_trace.txt (崩溃时 Console 缓冲会丢) + ThreadException + 参数明细
using System;
using System.Reflection;
using System.IO;
using System.Text;
using System.Windows.Forms;

class Host {
    static string TraceFile = "host_trace.txt";

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
            File.AppendAllText(TraceFile, "=== host v2 start " + DateTime.Now.ToString("HH:mm:ss.fff") + " jitNoInline=" + Environment.GetEnvironmentVariable("COMPlus_JitNoInline") + " ===" + Environment.NewLine);
            var asm = Assembly.LoadFrom(path);
            Console.WriteLine("[ost] loaded " + asm.FullName);
            var ep = asm.EntryPoint;
            Console.WriteLine("[ost] entry " + ep.DeclaringType + "::" + ep.Name);
            object[] args = ep.GetParameters().Length == 1 ? new object[] { new string[0] } : new object[0];
            ep.Invoke(null, args);
            Console.WriteLine("[ost] entry returned");
            File.AppendAllText(TraceFile, "=== entry returned normally ===" + Environment.NewLine);
            return 0;
        } catch (Exception ex) {
            Dump("ENTRY-INVOCATION", ex);
            return 1;
        }
    }
}
