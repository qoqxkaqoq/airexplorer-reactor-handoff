using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;

namespace AirExplorerUnpacker;

/// <summary>
/// scanrva — 全方法头/足迹扫描：验证 dnlib 写出的方法体区是否存在
/// 越界(超出 section)、错位(RVA=0 但有体)、对齐(fat 未 4 对齐)。
/// epinfo  — PE 级信息：EP 指向、section 布局、import 表、COR20 头。
/// 用法: scanrva &lt;exe&gt; [--max N]   epinfo &lt;exe&gt; [baseline.exe]
/// </summary>
public static class CmdScanRva
{
    sealed class Sec { public string Name = ""; public uint VA, VSize, RawPtr, RawSize; public bool HasData; }

    public static int RunScanRva(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: scanrva <exe> [--max N]"); return 2; }
        string path = args[1];
        int maxBad = 40;
        for (int i = 2; i < args.Length; i++)
            if (args[i] == "--max") maxBad = int.Parse(args[++i]);

        var (pe, secs, epRva) = OpenPe(path);
        var mod = ModuleDefMD.Load(path);
        // COR20 资源目录
        uint resLo = 0, resHi = 0;
        {
            int opt = FindPEHeader(pe);
            uint corRva = BitConverter.ToUInt32(pe, opt + 0x60 + 14 * 8);
            uint co = RvaToOffset(corRva, secs);
            resLo = BitConverter.ToUInt32(pe, (int)co + 0x18);
            resHi = resLo + BitConverter.ToUInt32(pe, (int)co + 0x1C);
        }
        var spans = new HashSet<long>();
        var overlaps = new List<string>();
        var spanList = new List<(uint lo, uint hi, string who)>();

        int tiny = 0, fat = 0, noBody = 0, rvaZeroWithBody = 0;
        var bad = new List<string>();
        var (baseRva, baseOff, fileSize) = (0u, 0u, new FileInfo(path).Length);

        foreach (var t in mod.GetTypes())
        {
            foreach (var m in t.Methods)
            {
                uint rva = (uint)m.RVA;
                bool declaredBody = !m.IsAbstract && !m.HasAttr(MethodAttributes.PinvokeImpl);
                if (rva == 0)
                {
                    if (declaredBody && m.HasBody) { rvaZeroWithBody++; if (bad.Count < maxBad) bad.Add($"RVA0-with-body {t.FullName}::{m.Name} (0x{m.MDToken.Raw:X8})"); }
                    else noBody++;
                    continue;
                }
                uint off = RvaToOffset(rva, secs);
                if (off == uint.MaxValue)
                {
                    bad.Add($"RVA-not-in-section 0x{rva:X8} {t.FullName}::{m.Name}");
                    continue;
                }
                byte[] buf = pe;
                int o = (int)off;
                byte b0 = buf[o];
                int headSize; uint codeSize; bool isFat;
                if ((b0 & 3) == 2) { tiny++; isFat = false; headSize = 1; codeSize = (uint)(b0 >> 2); }
                else if ((b0 & 3) == 3)
                {
                    fat++; isFat = true;
                    ushort flags = (ushort)(b0 | (buf[o + 1] << 8));
                    headSize = (flags >> 12) * 4;
                    codeSize = BitConverter.ToUInt32(buf, o + 4);
                    if ((rva & 3) != 0) bad.Add($"fat-not-aligned rva=0x{rva:X8} {t.FullName}::{m.Name}");
                }
                else { bad.Add($"bad-header 0x{b0:X2} rva=0x{rva:X8} {t.FullName}::{m.Name}"); continue; }

                uint end = rva + (uint)headSize + codeSize;
                // EH 段足迹
                if (isFat && (buf[o + 1] & 0x08) != 0)
                {
                    uint ehOff = rva + (uint)headSize + codeSize;
                    ehOff = (ehOff + 3u) & ~3u;
                    uint eo = RvaToOffset(ehOff, secs);
                    if (eo == uint.MaxValue) bad.Add($"EH-RVA-out 0x{ehOff:X8} {t.FullName}::{m.Name}");
                    else
                    {
                        byte sb = buf[(int)eo];
                        uint dsize;
                        if (sb == 0x41) dsize = (BitConverter.ToUInt32(buf, (int)eo) >> 8) & 0xFFFFFF;
                        else dsize = (uint)(sb & 0x3F) * 4;
                        end = ehOff + dsize + 4;
                    }
                }
                var sec = SecOf(rva, secs);
                if (sec != null && end > sec.VA + Math.Max(sec.VSize, sec.RawSize))
                    bad.Add($"FOOTPRINT-OVERFLOW end=0x{end:X8} sec={sec.Name} secEnd=0x{sec.VA + Math.Max(sec.VSize, sec.RawSize):X8} {t.FullName}::{m.Name}");
                // COR20 托管资源区重叠（CLR 对此报 Bad IL range）
                if (resLo != 0 && end > resLo && rva < resHi)
                    bad.Add($"RES-OVERLAP [0x{rva:X8}-0x{end:X8}) ∩ res[0x{resLo:X8},0x{resHi:X8}) {t.FullName}::{m.Name}");
                // 方法间重叠
                var key = ((long)rva << 20) | (long)((end - rva) & 0xFFFFF);
                if (!spans.Add(key) ) overlaps.Add($"{t.FullName}::{m.Name} rva=0x{rva:X8} end=0x{end:X8}");
                else spans.Add(key);
                spanList.Add((rva, end, $"{t.FullName}::{m.Name}"));
            }
        }
        Console.WriteLine($"[scanrva] {Path.GetFileName(path)}: tiny={tiny} fat={fat} noBody={noBody} rva0WithBody={rvaZeroWithBody} bad={bad.Count} dupRva={overlaps.Count} res=[0x{resLo:X},0x{resHi:X})");
        foreach (var b in bad.Take(maxBad)) Console.WriteLine("  " + b);
        // 方法间重叠: 按 lo 排序后线性扫
        var sorted = spanList.OrderBy(x => x.lo).ToList();
        int ovl = 0;
        for (int i = 1; i < sorted.Count && ovl < maxBad; i++)
        {
            if (sorted[i].lo < sorted[i - 1].hi)
            {
                ovl++;
                Console.WriteLine($"  OVL {sorted[i - 1].who} [0x{sorted[i - 1].lo:X8}-0x{sorted[i - 1].hi:X8}) vs {sorted[i].who} [0x{sorted[i].lo:X8}-0x{sorted[i].hi:X8})");
            }
        }
        if (ovl >= maxBad) Console.WriteLine($"  ... (>{maxBad} more)");
        return 0;
    }

    public static int RunEpInfo(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("usage: epinfo <exe> [baseline]"); return 2; }
        DumpEp(args[1]);
        if (args.Length >= 3) { Console.WriteLine("--- baseline ---"); DumpEp(args[2]); }
        return 0;
    }

    static void DumpEp(string path)
    {
        var (pe, secs, epRva) = OpenPe(path);
        var sec = SecOf(epRva, secs);
        Console.WriteLine($"[epinfo] {Path.GetFileName(path)}: fileSize={new FileInfo(path).Length}");
        Console.WriteLine($"  EP RVA=0x{epRva:X8} -> {(sec == null ? "<NOT IN ANY SECTION>" : sec.Name + " (off 0x" + RvaToOffset(epRva, secs).ToString("X") + ")")}");
        foreach (var s in secs)
            Console.WriteLine($"  sec {s.Name,-9} VA=0x{s.VA:X8} VSize=0x{s.VSize:X} Raw=0x{s.RawPtr:X8}/0x{s.RawSize:X}");
        // COR20
        int cor20Idx = FindPEHeader(pe);
        if (cor20Idx >= 0)
        {
            uint cor20Rva = BitConverter.ToUInt32(pe, cor20Idx + 0x60 + 14 * 8);
            uint corOff = RvaToOffset(cor20Rva, secs);
            if (corOff != uint.MaxValue)
            {
                uint flags = BitConverter.ToUInt32(pe, (int)corOff + 0x10);
                uint epTokOrRva = BitConverter.ToUInt32(pe, (int)corOff + 0x14);
                uint resDir = BitConverter.ToUInt32(pe, (int)corOff + 0x18);
                uint resSize = BitConverter.ToUInt32(pe, (int)corOff + 0x1C);
                Console.WriteLine($"  COR20 flags=0x{flags:X8} EntryPointTokOrRVA=0x{epTokOrRva:X8} Resources=0x{resDir:X8}+0x{resSize:X}");
            }
        }
        // import 表（手写 PE 解析: DataDirectory[1]）
        try
        {
            int opt = FindPEHeader(pe);
            uint impRva = BitConverter.ToUInt32(pe, opt + 0x60 + 1 * 8);
            if (impRva != 0)
            {
                uint off = RvaToOffset(impRva, secs);
                for (int i = 0; i < 16; i++, off += 20)
                {
                    uint nameRva = BitConverter.ToUInt32(pe, (int)off + 12);
                    if (nameRva == 0) break;
                    uint no = RvaToOffset(nameRva, secs);
                    int len = 0; while (no + (uint)len < (uint)pe.Length && pe[no + len] != 0 && len < 64) len++;
                    Console.WriteLine($"  import: {Encoding.ASCII.GetString(pe, (int)no, len)}");
                }
            }
        }
        catch (Exception e) { Console.WriteLine("  (import 读失败: " + e.Message + ")"); }
    }

    static int FindPEHeader(byte[] pe)
    {
        // dos e_lfanew @0x3C -> "PE\0\0" -> COFF 20B -> optional header; DataDirectory[14]=COR20
        int e = BitConverter.ToInt32(pe, 0x3C);
        if (e + 4 + 20 + 0x60 > pe.Length || pe[e] != 'P') return -1;
        return e + 4 + 20; // optional header start
    }

    static (byte[] pe, List<Sec> secs, uint ep) OpenPe(string path)
    {
        var pe = File.ReadAllBytes(path);
        int opt = FindPEHeader(pe);
        uint ep = BitConverter.ToUInt32(pe, opt + 0x10);
        int numSec = BitConverter.ToUInt16(pe, opt - 20 + 2);
        int optSize = BitConverter.ToUInt16(pe, opt - 20 + 16);
        int secStart = opt + optSize;
        var secs = new List<Sec>();
        for (int i = 0; i < numSec; i++)
        {
            int o = secStart + i * 40;
            var s = new Sec
            {
                Name = Encoding.ASCII.GetString(pe, o, 8).TrimEnd('\0'),
                VSize = BitConverter.ToUInt32(pe, o + 8),
                VA = BitConverter.ToUInt32(pe, o + 12),
                RawSize = BitConverter.ToUInt32(pe, o + 16),
                RawPtr = BitConverter.ToUInt32(pe, o + 20),
                HasData = BitConverter.ToUInt32(pe, o + 16) > 0
            };
            secs.Add(s);
        }
        return (pe, secs, ep);
    }

    static uint RvaToOffset(uint rva, List<Sec> secs)
    {
        foreach (var s in secs)
        {
            if (rva >= s.VA && rva < s.VA + Math.Max(s.VSize, s.RawSize))
                return s.RawPtr == 0 ? uint.MaxValue : rva - s.VA + s.RawPtr;
        }
        return uint.MaxValue;
    }

    static Sec? SecOf(uint rva, List<Sec> secs)
    {
        foreach (var s in secs) if (rva >= s.VA && rva < s.VA + Math.Max(s.VSize, s.RawSize)) return s;
        return null;
    }

    static bool HasAttr(this MethodDef m, MethodAttributes a) => (m.Attributes & a) != 0;
}
