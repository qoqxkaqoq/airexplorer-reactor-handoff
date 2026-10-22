// stackdump.cs — v26 挂栈抓取 (ClrMD 1.1.126102 net45, 目标: .NET Framework x86)
// 用法:
//   stackdump.exe <pid>                    现场 attach (Invasive 失败退 Passive) 打印全部托管线程栈
//   stackdump.exe --minidump <pid> <file>  dbghelp 写全内存 minidump (纯 P/Invoke, 不走 ClrMD)
//   stackdump.exe <dumpfile>               读取 minidump 打印全部托管线程栈
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Runtime;

class StackDump
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("dbghelp.dll", SetLastError = true)]
    static extern bool MiniDumpWriteDump(IntPtr hProcess, uint pid, IntPtr hFile, uint dumpType, IntPtr exp, IntPtr user, IntPtr cb);

    const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    const uint MiniDumpWithFullMemory = 0x00000200;

    static int Main(string[] args)
    {
        try
        {
            if (args.Length == 3 && args[0] == "--minidump")
                return WriteMiniDump(int.Parse(args[1]), args[2]) ? 0 : 1;
            if (args.Length == 0)
            {
                Console.WriteLine("用法: stackdump <pid> | --minidump <pid> <file> | <dumpfile>");
                return 2;
            }
            foreach (string a in args)
            {
                int pid;
                if (int.TryParse(a, out pid)) LiveAttach(pid);
                else if (File.Exists(a)) FromDump(a);
                else Console.WriteLine("[stackdump] 无法识别的参数: " + a);
            }
            return 0;
        }
        catch (Exception e)
        {
            Console.WriteLine("[stackdump] FAIL: " + e.ToString());
            return 1;
        }
    }

    static bool WriteMiniDump(int pid, string path)
    {
        IntPtr h = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)pid);
        if (h == IntPtr.Zero)
        {
            Console.WriteLine("[minidump] OpenProcess 失败 err=" + Marshal.GetLastWin32Error());
            return false;
        }
        try
        {
            using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                bool ok = MiniDumpWriteDump(h, (uint)pid, fs.SafeFileHandle.DangerousGetHandle(), MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                fs.Flush();
                if (!ok) Console.WriteLine("[minidump] MiniDumpWriteDump 失败 err=" + Marshal.GetLastWin32Error());
                else Console.WriteLine("[minidump] 已写入 " + path + " (" + new FileInfo(path).Length + " B)");
                return ok;
            }
        }
        finally { CloseHandle(h); }
    }

    static ClrRuntime GetRuntime(DataTarget dt)
    {
        if (dt.ClrVersions == null || dt.ClrVersions.Count == 0)
            throw new Exception("目标不含 CLR 运行时 (ClrVersions=0)");
        return dt.ClrVersions[0].CreateRuntime();
    }

    static void LiveAttach(int pid)
    {
        Console.WriteLine("=== 现场 attach PID " + pid + " ===");
        DataTarget dt = null;
        try
        {
            try { dt = DataTarget.AttachToProcess(pid, 20000u, AttachFlag.Invasive); }
            catch (Exception e)
            {
                Console.WriteLine("[attach] Invasive 失败, 退 Passive: " + e.Message);
                dt = DataTarget.AttachToProcess(pid, 20000u, AttachFlag.Passive);
            }
            Report(GetRuntime(dt));
        }
        finally
        {
            if (dt != null) { try { dt.Dispose(); } catch { } }
        }
    }

    static void FromDump(string path)
    {
        Console.WriteLine("=== 读取 dump " + path + " ===");
        DataTarget dt = DataTarget.LoadCrashDump(path);
        try { Report(GetRuntime(dt)); }
        finally { try { dt.Dispose(); } catch { } }
    }

    static void Report(ClrRuntime rt)
    {
        int n = 0;
        foreach (ClrThread t in rt.Threads)
        {
            n++;
            if (!t.IsAlive) continue;
            string head = "== 线程 osTid=" + t.OSThreadId + " mngTid=" + t.ManagedThreadId;
            try
            {
                ClrException ex = t.CurrentException;
                if (ex != null)
                {
                    string msg = ex.Message;
                    if (!String.IsNullOrEmpty(msg)) head += " 当前异常[" + msg + "]";
                }
            }
            catch { }
            Console.WriteLine(head);
            try
            {
                foreach (ClrStackFrame f in t.StackTrace)
                {
                    string s = f.DisplayString;
                    if (String.IsNullOrEmpty(s))
                        s = "<native ip=0x" + f.InstructionPointer.ToString("x") + " mod=" + f.ModuleName + ">";
                    Console.WriteLine("    " + s);
                }
            }
            catch (Exception e) { Console.WriteLine("    <栈遍历失败: " + e.Message + ">"); }
        }
        Console.WriteLine("=== 共 " + n + " 个线程 ===");
    }
}
