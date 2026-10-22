// verifyres.cs — ResourceReader 验证器: 候选文件逐个用 .NET ResourceReader 读通者存档
// 用法: verifyres <候选目录> <输出目录>   (net48 目标, CI windows 跑)
using System;
using System.Collections;
using System.IO;

class VerifyRes {
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
                    foreach (DictionaryEntry e in rr) {
                        if (n == 0) { firstName = (string)e.Key; first = e.Value; }
                        n++;
                    }
                    var dst = Path.Combine(okDir, "res_" + Sanitize(firstName ?? Path.GetFileName(f)) + "_" + n + ".resources");
                    File.Copy(f, dst, true);
                    Console.WriteLine("[ok] " + Path.GetFileName(f) + " → " + n + " 条 (首条: " + firstName + ", 类型: " + (first == null ? "null" : first.GetType().Name) + ") 存 " + dst);
                    ok++;
                }
            } catch (Exception ex) {
                Console.WriteLine("[fail] " + Path.GetFileName(f) + ": " + ex.GetType().Name);
                fail++;
            }
        }
        Console.WriteLine("验证完成: 通过 " + ok + " 失败 " + fail);
        return ok > 0 ? 0 : 2;
    }
    static string Sanitize(string s) {
        var b = s.ToCharArray();
        for (int i = 0; i < b.Length; i++) if (!char.IsLetterOrDigit(b[i]) && b[i] != '.' && b[i] != '_') b[i] = '_';
        return new string(b).TrimEnd('.').TrimEnd('_');
    }
}
