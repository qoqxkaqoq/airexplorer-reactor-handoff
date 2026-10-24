using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;

// 逐方法 JIT 校验: 不运行程序逻辑(不触发 cctor), 只看每个方法的 IL 是否合法。
// 用法: jitcheck <assembly.exe>
class JitCheck {
    static void Main(string[] a) {
        var asm = Assembly.LoadFrom(a[0]);
        Console.WriteLine("[jitcheck] " + asm.FullName);

        int ok = 0, bad = 0;
        var groups = new Dictionary<string, int>();
        var samples = new List<string>();

        Type[] allTypes;
        try { allTypes = asm.GetTypes(); }
        catch (System.Reflection.ReflectionTypeLoadException rtle) {
            allTypes = rtle.Types;
            Console.WriteLine("[jitcheck] GetTypes 部分失败: 加载失败 " + rtle.LoaderExceptions.Length + " 个类型, 明细(前10):");
            for (int i = 0; i < rtle.LoaderExceptions.Length && i < 10; i++) {
                var le = rtle.LoaderExceptions[i];
                Console.WriteLine("  [loadeex] " + le.GetType().Name + ": " + (le.Message ?? "").Split('\n')[0]);
            }
        }
        foreach (var t in allTypes) {
            if (t == null) continue;
            MethodBase[] ms;
            try {
                ms = t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance
                                  | BindingFlags.Static | BindingFlags.DeclaredOnly);
            } catch (Exception e) {
                Console.WriteLine("[type-fail] " + t.FullName + " :: " + e.GetType().Name);
                continue;
            }
            foreach (var m in ms) {
                try {
                    RuntimeHelpers.PrepareMethod(m.MethodHandle);
                    ok++;
                } catch (Exception e) {
                    bad++;
                    var msg = (e.Message ?? "").Split('\n')[0];
                    var key = e.GetType().Name + ": " + msg;
                    int c;
                    if (groups.TryGetValue(key, out c)) groups[key] = c + 1;
                    else groups[key] = 1;
                    if (samples.Count < 60) samples.Add(t.FullName + "::" + m.Name + "   <- " + key);
                }
            }
        }

        Console.WriteLine("JIT ok=" + ok + "  fail=" + bad);
        Console.WriteLine("--- 按异常分组 ---");
        foreach (var kv in groups.OrderByDescending(x => x.Value))
            Console.WriteLine("  " + kv.Value + " x  " + kv.Key);
        Console.WriteLine("--- 失败方法(前 60) ---");
        foreach (var s in samples) Console.WriteLine("  " + s);
    }
}
