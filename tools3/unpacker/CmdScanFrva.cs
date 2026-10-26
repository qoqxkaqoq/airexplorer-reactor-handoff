using dnlib.DotNet;
using dnlib.PE;

namespace AirExplorerUnpacker;

/// <summary>scanfrva &lt;exeA&gt; &lt;exeB&gt; — 对比两 exe 的 FieldRVA 表（行数/RVA/字段映射）与 PE 段覆盖。</summary>
public static class CmdScanFrva
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: scanfrva <exeA> <exeB>"); return 2; }
        foreach (var (path, tag) in new[] { (args[1], "A"), (args[2], "B") })
        {
            var mod = (ModuleDefMD)ModuleDefMD.Load(path);
            var img = mod.Metadata.PEImage;
            foreach (var sec in img.ImageSectionHeaders)
                Console.WriteLine("    sect {0}: va={1:X8} vsize={2:X8} rawsize={3:X8}",
                    sec.DisplayName ?? "?", (uint)sec.VirtualAddress, (uint)sec.VirtualSize, (uint)sec.SizeOfRawData);
            int rows = 0, outOfSect = 0;
            foreach (var t in mod.GetTypes())
                foreach (var f in t.Fields)
                {
                    if (f.RVA == 0) continue;
                    rows++;
                    bool inSect = false;
                    foreach (var sec in img.ImageSectionHeaders)
                        if ((uint)sec.VirtualAddress <= (uint)f.RVA && (uint)f.RVA < (uint)sec.VirtualAddress + Math.Max(sec.VirtualSize, sec.SizeOfRawData)) { inSect = true; break; }
                    if (!inSect)
                    {
                        outOfSect++;
                        if (outOfSect <= 5)
                            Console.WriteLine("    [OUT!] {0}::{1} tok={2:X8} rva={3:X8}", t.FullName, f.Name, f.MDToken.Raw, (uint)f.RVA);
                    }
                }
            Console.WriteLine("[{0}] {1}: FieldRVA rows={2} outOfSection={3} file={4}B", tag, mod.Name, rows, outOfSect, new FileInfo(path).Length);
        }
        return 0;
    }
}
