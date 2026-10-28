// m1r — pure dnlib rewrite of baseline with ZERO changes (relocation discriminator)
// PreserveAll + KeepOldMaxStack per AGENTS.md hard constraint #2.
using System;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

class M1R {
    static int Main(string[] args) {
        string inp = args[0], outp = args[1];
        var mod = ModuleDefMD.Load(inp);
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll |
            MetadataFlags.KeepOldMaxStack | MetadataFlags.PreserveTypeRefRids |
            MetadataFlags.PreserveTypeDefRids | MetadataFlags.PreserveFieldRids |
            MetadataFlags.PreserveMethodRids | MetadataFlags.PreserveMemberRefRids |
            MetadataFlags.PreserveStandAloneSigRids | MetadataFlags.PreserveUSOffsets |
            MetadataFlags.PreserveBlobOffsets | MetadataFlags.PreserveExtraSignatureData;
        opts.Logger = null;
        mod.Write(outp, opts);
        Console.WriteLine("m1r written: " + outp);
        return 0;
    }
}
