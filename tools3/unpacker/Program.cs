using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace AirExplorerUnpacker;

/// <summary>
/// CLI 入口。子命令:
///   inspect  &lt;exe&gt; [manifest.tsv]  — 检查模块现状: 方法体形态/token 对齐/资源布局
///   s1       &lt;in.exe&gt; &lt;out.exe&gt; &lt;bodiesDir&gt; &lt;manifest.tsv&gt; [only:token,token,...]
///   s2       …
/// </summary>
public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("usage: AirExplorerUnpacker <inspect|s1|s2|s3|s4|s5|pipeline> [args...]");
            return 2;
        }
        try
        {
            switch (args[0])
            {
                case "inspect": return CmdInspect.Run(args);
                case "s1": return CmdS1.Run(args);
                case "ehprobe": return CmdEhProbe.Run(args);
                case "checksig": return CmdCheckSig.Run(args);
                case "scanil": return CmdScanIl.Run(args);
                case "tokinfo": return CmdTokInfo.Run(args);
                case "dumptype": return CmdDumpType.Run(args);
                case "scansem": return CmdScanSemantics.Run(args);
                case "bodyhex": return CmdBodyHex.Run(args);
                case "rawbody": return CmdRawBody.Run(args);
                default:
                    Console.WriteLine("unknown command: " + args[0]);
                    return 2;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[FATAL] " + ex);
            return 1;
        }
    }
}
