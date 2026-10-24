using System;
using System.IO;
using System.Text;
using dnlib.DotNet;

// locemit <official.exe> <dumpDir> <tok> — 从 bin 头 localsTok(偏移20) 解析 StandAloneSig，
// 还原 bodyswap 兼容的 .loc 文本（index|isPinned|TypeFullName）。用于 zip 缺失的方法。
class LocEmit {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        string dumpDir = a[1];
        foreach (var tok in a[2..]) {
            uint t = Convert.ToUInt32(tok, 16);
            var bin = File.ReadAllBytes(Path.Combine(dumpDir, "m_" + t.ToString("X8") + ".bin"));
            uint locTok = BitConverter.ToUInt32(bin, 20);
            Console.WriteLine("# " + tok + " localsTok=0x" + locTok.ToString("X8"));
            var sb = new StringBuilder();
            var sas = locTok == 0 ? null : mod.ResolveToken(locTok) as StandAloneSig;
            if (sas != null && sas.LocalSig != null) {
                int i = 0;
                foreach (var l in sas.LocalSig.Locals) sb.AppendLine(i++ + "|" + (l is PinnedSig ? "1" : "0") + "|" + Fmt(l));
            }
            File.WriteAllText(Path.Combine(dumpDir, "m_" + t.ToString("X8") + ".loc"), sb.ToString());
            Console.Write(sb.ToString());
        }
    }
    // 输出 bodyswap.ParseType 可解析的文本（泛型 arg 的 assembly 部分会被忽略，可省略）
    static string Fmt(TypeSig t) {
        if (t == null) return "System.Object";
        switch (t) {
            case SZArraySig z: return Fmt(z.Next) + "[]";
            case ByRefSig b: return Fmt(b.Next) + "&";
            case PtrSig p: return Fmt(p.Next) + "*";
            case PinnedSig pin: return Fmt(pin.Next);
            case GenericInstSig g: {
                var cls = g.GenericType.TypeDefOrRef;
                string head = (cls.ReflectionNamespace.Length > 0 ? cls.ReflectionNamespace + "." : "") + cls.ReflectionName;
                var sb2 = new StringBuilder(head);
                foreach (var ga in g.GenericArguments) sb2.Append("[[" + Fmt(ga) + "]]");
                return sb2.ToString();
            }
            case TypeDefOrRefSig td:
                return (td.ReflectionNamespace.Length > 0 ? td.ReflectionNamespace + "." : "") + td.ReflectionName;
            case GenericVar _: return "System.Object";
            case GenericMVar _: return "System.Object";
            default: return t.FullName;
        }
    }
}
