using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// disasm — dump-body IL disassembler + cross-reference scanner (works on m_*.bin dumps, not exe stubs)
//
// usage:
//   disasm <exe> <dumpDir> <tok> [tok...]            resolve + disassemble dump bodies
//   disasm <exe> <dumpDir> --res                     list embedded manifest resources
//   disasm <exe> <dumpDir> --pinv                    list P/Invoke methods + dump callers
//   disasm <exe> <dumpDir> --xref <name-substr>      find defs/memberrefs whose FullName contains substr, then dump callers
//   disasm <exe> <dumpDir> --str <substr>            find ldstr in dump bodies whose string contains substr
//
// dump format: 24B header (tok/ilSize/maxStack/ehCount/preExtra/localsTok) + raw IL
class Disasm {
    static ModuleDef mod;
    static Dictionary<uint, string> resNames = new Dictionary<uint, string>(); // usTok -> not used; resources listed separately

    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: disasm <exe> <dumpDir> <tok|--res|--pinv|--xref s|--str s> ..."); return; }
        mod = ModuleDefMD.Load(a[0]);
        string dumpDir = a[1];

        if (a[2] == "--res") { ListRes(); return; }
        if (a[2] == "--pinv") { Pinv(dumpDir, a.Skip(3)); return; }
        if (a[2] == "--xref") { Xref(dumpDir, a[3]); return; }
        if (a[2] == "--str") { Str(dumpDir, a[3]); return; }
        if (a[2] == "--fld") { Fld(dumpDir, a[3]); return; }

        foreach (var tok in a.Skip(2)) DisOne(dumpDir, tok);
    }

    // ---------- disassembler ----------
    static int OpSize(OpCode oc, byte[] il, int pos, out string operand) {
        operand = "";
        if (pos >= il.Length) return 0;
        switch (oc.OperandType) {
            case OperandType.InlineNone: return 0;
            case OperandType.ShortInlineBrTarget:
                sbyte d = (sbyte)il[pos];
                operand = "IL_" + (pos + 1 + d).ToString("X4"); return 1;
            case OperandType.InlineBrTarget:
                int d4 = BitConverter.ToInt32(il, pos);
                operand = "IL_" + (pos + 4 + d4).ToString("X4"); return 4;
            case OperandType.ShortInlineI: operand = il[pos].ToString(); return 1;
            case OperandType.InlineI: operand = BitConverter.ToInt32(il, pos).ToString(); return 4;
            case OperandType.InlineI8: operand = BitConverter.ToInt64(il, pos).ToString(); return 8;
            case OperandType.ShortInlineR: operand = BitConverter.ToSingle(il, pos).ToString(); return 4;
            case OperandType.InlineR: operand = BitConverter.ToDouble(il, pos).ToString(); return 8;
            case OperandType.ShortInlineVar: operand = "v" + il[pos]; return 1;
            case OperandType.InlineVar: operand = "v" + BitConverter.ToUInt16(il, pos); return 2;
            case OperandType.InlineString: {
                uint t = BitConverter.ToUInt32(il, pos);
                operand = "\"" + UsStr(t) + "\""; return 4;
            }
            case OperandType.InlineSwitch: {
                int n = BitConverter.ToInt32(il, pos);
                var sb = new System.Text.StringBuilder("(");
                for (int k = 0; k < n && pos + 4 + k * 4 + 4 <= il.Length; k++) {
                    int dd = BitConverter.ToInt32(il, pos + 4 + k * 4);
                    sb.Append((k != 0 ? ", " : "") + "IL_" + (pos + 4 + n * 4 + dd).ToString("X4"));
                }
                operand = sb.ToString() + ")"; return 4 + n * 4;
            }
            case OperandType.InlineMethod:
            case OperandType.InlineField:
            case OperandType.InlineTok:
            case OperandType.InlineType:
            case OperandType.InlineSig: {
                uint t = BitConverter.ToUInt32(il, pos);
                operand = ResolveTok(t); return 4;
            }
            default: return 0;
        }
    }

    static string UsStr(uint tok) {
        try { var s = ((ModuleDefMD)mod).ReadUserString(tok & 0x00FFFFFF); return s == null ? "<us?" + tok.ToString("X8") + ">" : s; }
        catch { return "<us?" + tok.ToString("X8") + ">"; }
    }

    static string ResolveTok(uint tok) {
        string hex = tok.ToString("X8");
        try {
            var o = mod.ResolveToken(tok);
            if (o is MethodDef md) return hex + " " + md.FullName;
            if (o is FieldDef fd) return hex + " " + fd.FullName;
            if (o is TypeDef td) return hex + " " + td.FullName;
            if (o is MemberRef mr) return hex + " " + mr.FullName;
            if (o is MethodSpec ms) return hex + " " + ms.FullName;
            if (o is TypeSpec ts) return hex + " " + TypePrinter(ts);
            return hex + " <?" + o?.GetType().Name + ">";
        } catch (Exception e) { return hex + " <ERR " + e.Message.Substring(0, Math.Min(40, e.Message.Length)) + ">"; }
    }

    static string TypePrinter(TypeSpec ts) {
        try { return ts.TypeSig?.FullName ?? "typespec"; } catch { return "typespec"; }
    }

    static void DisOne(string dumpDir, string tok) {
        string f = Path.Combine(dumpDir, "m_" + tok + ".bin");
        if (!File.Exists(f)) { Console.WriteLine("[" + tok + "] MISSING from dump"); return; }
        var d = File.ReadAllBytes(f);
        uint t = BitConverter.ToUInt32(d, 0);
        int ilSize = (int)BitConverter.ToUInt32(d, 4);
        int maxStack = (int)BitConverter.ToUInt32(d, 8);
        int ehCount = (int)BitConverter.ToUInt32(d, 12);
        Console.WriteLine($"===== {tok} ilSize={ilSize} maxStack={maxStack} eh={ehCount} =====");
        // name it if resolvable
        try { var md = mod.ResolveToken(t) as MethodDef; if (md != null) Console.WriteLine("  name: " + md.FullName); } catch { }
        var il = new byte[ilSize]; Array.Copy(d, 24, il, 0, ilSize);
        int i = 0;
        while (i < il.Length) {
            int off = i; string operand; int sz = 1;
            byte b = il[i];
            try {
                if (b == 0xFE) {
                    var oc = OpCodes.TwoByteOpCodes[il[i + 1]];
                    if (oc == null) { Console.WriteLine($"IL_{off:X4}: <unknown FE {il[i + 1]:X2}>"); i += 2; continue; }
                    sz = 2 + OpSize(oc, il, i + 2, out operand);
                    Console.WriteLine($"IL_{off:X4}: {oc.Name} {operand}");
                } else {
                    var oc = OpCodes.OneByteOpCodes[b];
                    if (oc == null) { Console.WriteLine($"IL_{off:X4}: <unknown {b:X2}>"); i += 1; continue; }
                    sz = 1 + OpSize(oc, il, i + 1, out operand);
                    Console.WriteLine($"IL_{off:X4}: {oc.Name} {operand}");
                }
            } catch (Exception e) {
                Console.WriteLine($"IL_{off:X4}: <disasm err {e.Message} @ {b:X2}>"); i += 1;
            }
            i += Math.Max(1, sz == 0 ? 1 : sz);
        }
    }

    // ---------- resource list ----------
    static void ListRes() {
        foreach (var r in mod.Resources) {
            var er = r as EmbeddedResource;
            long len = -1; try { if (er != null) len = er.Length; } catch { }
            Console.WriteLine($"RES {(er == null ? r.ResourceType.ToString() : "Embedded")} len={len} name=\"{r.Name}\"");
        }
    }

    // ---------- dump body iteration ----------
    static IEnumerable<Tuple<string, byte[]>> Bodies(string dumpDir) {
        foreach (var f in Directory.GetFiles(dumpDir, "m_*.bin")) {
            var d = File.ReadAllBytes(f);
            int ilSize = (int)BitConverter.ToUInt32(d, 4);
            if (ilSize <= 0 || ilSize > d.Length - 24) continue;
            var il = new byte[ilSize]; Array.Copy(d, 24, il, 0, ilSize);
            yield return Tuple.Create(Path.GetFileNameWithoutExtension(f).Substring(2), il);
        }
    }

    // collect (token) operands for call/callvirt/newobj/ldftn/ldvirtftn in a body
    static IEnumerable<Tuple<int, uint>> CallSites(byte[] il) {
        int i = 0;
        while (i < il.Length) {
            byte b = il[i]; OpCode oc; int hdr; int pos;
            if (b == 0xFE) {
                if (i + 1 >= il.Length) break;
                oc = OpCodes.TwoByteOpCodes[il[i + 1]]; hdr = 2; pos = i + 2;
            } else { oc = OpCodes.OneByteOpCodes[b]; hdr = 1; pos = i + 1; }
            if (oc == null) { i += hdr; continue; }
            bool isCall = b == 0x28 || b == 0x6F || b == 0x73 || (b == 0xFE && (il[i + 1] == 0x06 || il[i + 1] == 0x07));
            if (isCall && pos + 4 <= il.Length)
                yield return Tuple.Create(i, BitConverter.ToUInt32(il, pos));
            // advance by operand size
            string op;
            int osz = OpSize(oc, il, pos, out op);
            i = pos + osz;
            if (osz == 0) i = pos;
        }
    }

    static Dictionary<uint, string> NameIndex(string substr) {
        var ix = new Dictionary<uint, string>();
        foreach (var t in mod.GetTypes()) {
            try {
                if (Match(t.FullName, substr)) ix[(uint)t.MDToken.Raw] = t.FullName;
                foreach (var m in t.Methods) if (Match(m.FullName, substr)) ix[(uint)m.MDToken.Raw] = m.FullName;
                foreach (var fl in t.Fields) if (Match(fl.FullName, substr)) ix[(uint)fl.MDToken.Raw] = fl.FullName;
            } catch { }
        }
        foreach (var mr in mod.GetMemberRefs()) if (Match(mr.FullName, substr)) ix[(uint)mr.MDToken.Raw] = mr.FullName;
        foreach (var ts in mod.GetTypeRefs()) { try { if (Match(ts.FullName, substr)) ix[(uint)ts.MDToken.Raw] = ts.FullName; } catch { } }
        return ix;
    }

    static bool Match(string s, string substr) {
        return s != null && s.IndexOf(substr, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    static void Xref(string dumpDir, string substr) {
        var ix = NameIndex(substr);
        Console.WriteLine($"[xref] {ix.Count} tokens match \"{substr}\"");
        foreach (var kv in ix) Console.WriteLine($"  {kv.Key.ToString("X8")} {kv.Value}");
        var want = new HashSet<uint>(ix.Keys);
        foreach (var body in Bodies(dumpDir)) {
            foreach (var cs in CallSites(body.Item2)) {
                if (want.Contains(cs.Item2))
                    Console.WriteLine($"CALLER {body.Item1} @IL_{cs.Item1:X4} -> {cs.Item2.ToString("X8")} {ix[cs.Item2]}");
            }
        }
    }

    static void Pinv(string dumpDir, IEnumerable<string> filter) {
        var pinvs = new List<MethodDef>();
        foreach (var t in mod.GetTypes()) foreach (var m in t.Methods)
                if (m.ImplMap != null) pinvs.Add(m);
        Console.WriteLine($"[pinv] {pinvs.Count} P/Invoke methods");
        var want = new HashSet<uint>();
        foreach (var m in pinvs) {
            string mn = m.ImplMap.Module.Name.String;
            string en = m.ImplMap.Name.String;
            if (filter.Any() && !filter.Any(f => Match(en, f) || Match(mn, f))) continue;
            Console.WriteLine($"  {(uint)m.MDToken.Raw:X8} {mn} :: {en}");
            want.Add((uint)m.MDToken.Raw);
        }
        foreach (var body in Bodies(dumpDir)) {
            foreach (var cs in CallSites(body.Item2)) {
                if (want.Contains(cs.Item2)) {
                    var pm = mod.ResolveToken(cs.Item2) as MethodDef;
                    Console.WriteLine($"CALLER {body.Item1} @IL_{cs.Item1:X4} -> {(pm?.ImplMap.Module.Name.String ?? "?")}::{pm?.ImplMap.Name.String}");
                }
            }
        }
    }

    static void Str(string dumpDir, string substr) {
        foreach (var body in Bodies(dumpDir)) {
            var il = body.Item2;
            int i = 0;
            while (i < il.Length) {
                byte b = il[i]; OpCode oc; int hdr; int pos;
                if (b == 0xFE) { if (i + 1 >= il.Length) break; oc = OpCodes.TwoByteOpCodes[il[i + 1]]; hdr = 2; pos = i + 2; }
                else { oc = OpCodes.OneByteOpCodes[b]; hdr = 1; pos = i + 1; }
                if (oc == null) { i += hdr; continue; }
                if (b == 0x72 && pos + 4 <= il.Length) {
                    uint t = BitConverter.ToUInt32(il, pos);
                    string s = UsStr(t);
                    if (Match(s, substr)) Console.WriteLine($"STR {body.Item1} @IL_{i:X4} us={t:X8} \"{Trunc(s, 120)}\"");
                }
                string op; int osz = OpSize(oc, il, pos, out op);
                i = pos + osz; if (osz == 0) i = pos;
            }
        }
    }

    // --fld <tok> : scan dumps for any instruction referencing field token (ldfld/ldflda/stfld/ldsfld/ldsflda/stsfld/ldtoken)
    static void Fld(string dumpDir, string fsubstr) {
        uint want = uint.Parse(fsubstr, System.Globalization.NumberStyles.HexNumber);
        foreach (var body in Bodies(dumpDir)) {
            var il = body.Item2;
            int i = 0;
            while (i < il.Length) {
                byte b = il[i]; int hdr = 1; int pos = i + 1;
                bool isFld = b == 0x7B || b == 0x7C || b == 0x7D || b == 0x7E || b == 0x7F || b == 0x80 || b == 0xD0;
                if (b == 0xFE) { hdr = 2; pos = i + 2; }
                if (isFld && pos + 4 <= il.Length && BitConverter.ToUInt32(il, pos) == want) {
                    string ctx = "";
                    try { var fd = mod.ResolveToken(want) as FieldDef; if (fd != null) ctx = fd.FullName; } catch { }
                    Console.WriteLine($"FLD {body.Item1} @IL_{i:X4} op={b:X2} {want:X8} {ctx}");
                }
                OpCode oc = b == 0xFE ? OpCodes.TwoByteOpCodes[il[i + 1]] : OpCodes.OneByteOpCodes[b];
                if (oc == null) { i += hdr; continue; }
                string op; int osz = OpSize(oc, il, pos, out op);
                i = pos + osz; if (osz == 0) i = pos;
            }
        }
    }

    static string Trunc(string s, int n) { s = s.Replace("\r", "\\r").Replace("\n", "\\n"); return s.Length <= n ? s : s.Substring(0, n) + "..."; }
}
