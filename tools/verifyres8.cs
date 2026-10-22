using System;
using System.Collections;
using System.IO;

class VerifyRes8 {
    static int Main(string[] a) {
        string candDir = a.Length > 0 ? a[0] : ".";
        string okDir = a.Length > 1 ? a[1] : "ok";
        Directory.CreateDirectory(okDir);
        int ok = 0, fail = 0;
        foreach (var f in Directory.GetFiles(candDir, "*.resources")) {
            try {
                using (var rr = new System.Resources.ResourceReader(f)) {
                    int n = 0;
                    object first = null; string firstName = null;
                    var keys = new System.Collections.Generic.List<string>();
                    foreach (DictionaryEntry e in rr) {
                        if (n < 5) keys.Add((string)e.Key);
                        if (n == 0) { firstName = (string)e.Key; first = e.Value; }
                        n++;
                    }
                    Console.WriteLine("[keys] " + string.Join(" | ", keys));
                    var dst = Path.Combine(okDir, "res_" + Sanitize(firstName ?? Path.GetFileName(f)) + "_" + n + ".bin");
                    File.Copy(f, dst, true);
                    Console.WriteLine("[ok] " + Path.GetFileName(f) + " (" + new FileInfo(f).Length + "B) → " + n + " 条 首条=" + firstName + " 类型=" + (first == null ? "null" : first.GetType().Name));
                    ok++;
                }
            } catch (Exception ex) {
                fail++;
                Console.WriteLine("[fail] " + Path.GetFileName(f) + ": " + ex.GetType().Name);
            }
        }
        Console.WriteLine("验证: 通过 " + ok + " 失败 " + fail);
        return 0;
    }
    static string Sanitize(string s) {
        var b = s.ToCharArray();
        for (int i = 0; i < b.Length; i++) if (!char.IsLetterOrDigit(b[i]) && b[i] != '.' && b[i] != '_') b[i] = '_';
        return new string(b).TrimEnd('.').TrimEnd('_');
    }
}
