// host.cs — 在受控宿主中调用目标 WinForms 程序入口, 用于抓取未处理异常的完整堆栈
using System;
using System.Reflection;
using System.IO;

class Host {
    [STAThread]
    static int Main(string[] a) {
        AppDomain.CurrentDomain.UnhandledException += delegate(object s, UnhandledExceptionEventArgs e) {
            Console.WriteLine("=== UNHANDLED ===");
            Console.WriteLine(e.ExceptionObject == null ? "(null)" : e.ExceptionObject.ToString());
            Console.Out.Flush();
        };
        try {
            var path = Path.GetFullPath(a[0]);
            Directory.SetCurrentDirectory(Path.GetDirectoryName(path));
            var asm = Assembly.LoadFrom(path);
            Console.WriteLine("[host] loaded " + asm.FullName);
            var ep = asm.EntryPoint;
            Console.WriteLine("[host] entry " + ep.DeclaringType + "::" + ep.Name);
            object[] args = ep.GetParameters().Length == 1 ? new object[] { new string[0] } : new object[0];
            ep.Invoke(null, args);
            Console.WriteLine("[host] entry returned");
            return 0;
        } catch (Exception ex) {
            Console.WriteLine("=== EXCEPTION CHAIN ===");
            Console.WriteLine(ex.ToString());
            Console.WriteLine("=== INNER FLAT ===");
            for (Exception e = ex; e != null; e = e.InnerException) {
                Console.WriteLine("EX " + e.GetType().FullName + ": " + e.Message);
                Console.WriteLine(e.StackTrace);
            }
            Console.Out.Flush();
            return 1;
        }
    }
}
