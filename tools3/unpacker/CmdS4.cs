using dnlib.DotNet;

namespace AirExplorerUnpacker;

/// <summary>S4 — 资源重嵌：用解密后的明文资源替换产物中的 NRS 密文资源（同大小）。</summary>
public static class CmdS4
{
    // 资源名 → 解密文件
    static readonly Dictionary<string, string> Map = new()
    {
        ["ErrorReceiver.ValidatorViewer"] = "../../work_a1_pack/dec_Viewer.bin",
        ["ValidatorGenerator.DefinitionError"] = "../../work/c2_pack/dec/dec_mainlib_stream.bin",
        ["GlobalValidator.FactoryValidator"] = "../../work/c2_pack/dec/dec_Factory.bin",
        ["ValidatorAllocator.ValidatorProc"] = "../../work/c2_pack/dec/dec_Proc.bin",
        ["CollectorTransaction.ValidatorProject"] = "../../work/c2_pack/dec/dec_Project.bin",
        ["ValidatorArgument.EmitterReporter"] = "../../work/c2_pack/dec/dec_Emitter.bin",
    };

    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: s4 <in.exe> <out.exe> [only-add|only-name]"); return 2; }
        var mod = ModuleDefMD.Load(args[1]);
        string? onlyName = args.Length > 3 && args[3] != "only-add" ? args[3] : null;
        bool onlyAdd = args.Length > 3 && args[3] == "only-add";
        int replaced = 0, added = 0, mismatch = 0;
        var existing = new HashSet<string>();
        foreach (var r in mod.Resources.OfType<EmbeddedResource>().ToList())
        {
            if (!Map.TryGetValue(r.Name.String, out var decFile)) { existing.Add(r.Name.String); continue; }
            if (onlyName != null && r.Name.String != onlyName) { existing.Add(r.Name.String); continue; }
            if (onlyAdd) { existing.Add(r.Name.String); continue; }
            if (!File.Exists(decFile)) { Console.WriteLine("[s4] dec file missing: " + decFile); continue; }
            var plain = File.ReadAllBytes(decFile);
            var origLen = r.CreateReader().Length;
            if (origLen != plain.Length)
            {
                Console.WriteLine("[s4] SIZE MISMATCH {0}: orig={1} plain={2}", r.Name, origLen, plain.Length);
                mismatch++;
            }
            // 同大小替换: EmbeddedResource 直接重建
            var newEr = new EmbeddedResource(r.Name, plain, r.Attributes);
            mod.Resources.Remove(r);
            mod.Resources.Add(newEr);
            replaced++;
        }
        // 添加缺失的 FactoryValidator
        if (!string.IsNullOrEmpty(onlyName) && onlyName != "GlobalValidator.FactoryValidator") { }
        else if (!existing.Contains("GlobalValidator.FactoryValidator") && Map.TryGetValue("GlobalValidator.FactoryValidator", out var fv) && File.Exists(fv))
        {
            mod.Resources.Add(new EmbeddedResource("GlobalValidator.FactoryValidator", File.ReadAllBytes(fv), ManifestResourceAttributes.Private));
            added++;
        }
        Console.WriteLine("[s4] replaced={0} added={1} mismatch={2}", replaced, added, mismatch);
        var opts = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(args[2], opts);
        Console.WriteLine("[s4] written: " + args[2]);
        return 0;
    }
}
