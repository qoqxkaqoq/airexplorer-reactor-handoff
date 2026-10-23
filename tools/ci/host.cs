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
            ResolveScan(asm);
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

    // 解析诊断: 对 ITP 方法体的全部 call/callvirt/newobj/ldfld/stsfld token 做 Module.Resolve*
    // 提前暴露 CLR 解析失败的 MemberRef(Reactor 元数据在标准 binder 下的失配)
    static void ResolveScan(Assembly asm) {
        try {
            var mi = asm.GetType("CloudClient.Templating.DispatcherInitializer").GetMethod("InstantiateTransferableProgram", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
            if (mi == null) { File.AppendAllText(TraceFile, "[resolve] ITP not found" + Environment.NewLine); return; }
            var body = mi.GetMethodBody();
            byte[] il = body.GetILAsByteArray();
            var mod2 = mi.Module;
            int ok = 0, bad = 0;
            var sb = new StringBuilder();
            int i = 0;
            while (i < il.Length) {
                byte op = il[i]; int len = 1;
                bool isMember = false;
                if (op == 0x28 || op == 0x6F || op == 0x73 || op == 0x7B || op == 0x7D || op == 0x7E || op == 0x80 || op == 0x29 || op == 0x70 || op == 0x8C) isMember = true;
                if (op == 0xFE) { len = 2; i += 2; continue; }
                // 单字节 opcode 长度表(简化: 大多 1, 含 4 字节操作数的常见项)
                if (op == 0x20 || op == 0x22 || op == 0x23 || op == 0x28 || op == 0x29 || op == 0x2B || op == 0x2C || op == 0x2D || op == 0x2E || op == 0x2F || op == 0x33 || op == 0x34 || op == 0x35 || op == 0x36 || op == 0x6F || op == 0x70 || op == 0x71 || op == 0x72 || op == 0x73 || op == 0x74 || op == 0x75 || op == 0x79 || op == 0x7B || op == 0x7D || op == 0x7E || op == 0x7F || op == 0x80 || op == 0x81 || op == 0x8C || op == 0x8D || op == 0x8E || op == 0xA3 || op == 0xA5 || op == 0xDD || op == 0xDE || op == 0x1F) len = op == 0x1F ? 2 : 5;
                else if (op == 0x1E || op == 0x1F || op == 0x2A) len = op == 0x2A ? 1 : 2;
                if (isMember) {
                    uint tok = BitConverter.ToUInt32(il, i + 1);
                    try {
                        if (op == 0x7B || op == 0x7D || op == 0x7E || op == 0x80) mod2.ResolveField((int)tok);
                        else mod2.ResolveMethod((int)tok);
                        ok++;
                    } catch (Exception ex) {
                        bad++;
                        sb.AppendLine("[resolve] BAD 0x" + tok.ToString("X8") + " op=0x" + op.ToString("X2") + " " + ex.GetType().Name + ": " + ex.Message);
                    }
                }
                i += len;
            }
            sb.Insert(0, "[resolve] ITP il=" + il.Length + " ok=" + ok + " bad=" + bad + Environment.NewLine);
            File.AppendAllText(TraceFile, sb.ToString());
            Console.WriteLine("[resolve] ok=" + ok + " bad=" + bad);
        } catch (Exception ex) {
            File.AppendAllText(TraceFile, "[resolve] scan fatal " + ex + Environment.NewLine);
        }
    }
}
