using System;
using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;

// FirstChance probe: prints every first-chance exception with ORIGINAL throw point.
// Usage: probe.exe <target exe path>
class Probe {
    static int n = 0;
    static void Main(string[] args) {
        AppDomain.CurrentDomain.FirstChanceException += new EventHandler<FirstChanceExceptionEventArgs>(OnFC);
        AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(OnResolve);
        string target = args[0];
        Console.WriteLine("[probe] loading " + target);
        var asm = Assembly.LoadFrom(target);
        Console.WriteLine("[probe] loaded " + asm.FullName);
        var ep = asm.EntryPoint;
        if (ep == null) { Console.WriteLine("[probe] no entrypoint"); return; }
        try {
            object r = ep.Invoke(null, new object[] { new string[0] });
            Console.WriteLine("[probe] main returned " + r);
        } catch (Exception ex) {
            Console.WriteLine("[probe] main threw: " + ex.GetType().FullName + ": " + ex.Message);
        }
    }
    static void OnFC(object s, FirstChanceExceptionEventArgs e) {
        n++;
        if (n > 400) return;
        var ex = e.Exception;
        string msg = ex.Message == null ? "" : ex.Message;
        if (msg.Length > 100) msg = msg.Substring(0, 100);
        Console.WriteLine("[FC#{0}] {1}: {2}", n, ex.GetType().FullName, msg);
        var st = ex.StackTrace;
        if (st != null) {
            string[] lines = st.Split('\n');
            int m = lines.Length; if (m > 10) m = 10;
            for (int i = 0; i < m; i++) Console.WriteLine("      " + lines[i].Trim());
        }
    }
    static Assembly OnResolve(object s, ResolveEventArgs e) {
        string nm = new AssemblyName(e.Name).Name;
        string p = Path.Combine(@"C:\airtest", nm + ".dll");
        if (File.Exists(p)) return Assembly.LoadFrom(p);
        p = Path.Combine(@"C:\airtest\probe", nm + ".dll");
        if (File.Exists(p)) return Assembly.LoadFrom(p);
        return null;
    }
}
