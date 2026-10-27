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
                case "scanmi": return CmdScanMethodImpl.Run(args);
                case "checkgp": return CmdCheckGP.Run(args);
                case "dummyaudit": return CmdDummyAudit.Run(args);
                case "tokalign": return CmdTokAlign.Run(args);
                case "scanloc": return CmdScanLoc.Run(args);
                case "scaneh": return CmdScanEh.Run(args);
                case "scanfrva": return CmdScanFrva.Run(args);
                case "frvadetail": return CmdFrvaDetail.Run(args);
                case "fixdummy": return CmdFixDummy.Run(args);
                case "deepdummy": return CmdDeepDummy.Run(args);
                case "reuse": return CmdReuse.Run(args);
                case "disasm": return CmdDisasm.Run(args);
                case "bodytest": return CmdBodyTest.Run(args);
                case "finddup": return CmdFindDup.Run(args);
                case "findcctor": return CmdFindCctor.Run(args);
                case "audittoks": return CmdAuditToks.Run(args);
                case "tok2": return CmdTok2.Run(args);
                case "noinline": return CmdNoInline.Run(args);
                case "ehaudit": return CmdEhAudit.Run(args);
                case "fulldiff": return CmdFullDiff.Run(args);
                case "bodyvariant": return CmdBodyVariant.Run(args);
                case "pinvoke": return CmdScanPinvoke.Run(args);
                case "findmethod": return CmdFindMethod.Run(args);
                case "typetoks": return CmdTypeToks.Run(args);
				case "scanrva": return CmdScanRva.RunScanRva(args);
				case "dumpall": return CmdScanRva.RunDumpAll(args);
				case "s3": return CmdS3.Run(args);
					case "findwr": return CmdFindWriters.Run(args);
					case "findpinv": return CmdFindPinv.Run(args);
					case "scans2": return CmdScanS2.Run(args);
					case "resinfo": return CmdRes.Run(args);
					case "s4": return CmdS4.Run(args);
					case "findthread": return CmdFindThread.Run(args);
					case "dumpgap": return CmdDumpGap.Run(args);
					case "dumpfields": return CmdDumpFields.Run(args);
					case "scanstubs": return CmdScanStubs.Run(args);
					case "finddel": return CmdFindDel.Run(args);
					case "uehook": return CmdUeHook.Run(args);
				case "epinfo": return CmdScanRva.RunEpInfo(args);
				case "scanres": return CmdScanRes.Run(args);
				case "patchstub": return CmdPatchStub.Run(args);
				case "sigdiff": return CmdSigDiff.Run(args);
				case "diagsig": return CmdSigDiff.RunDiag(args);
				case "tokmap": return CmdTokMap.Run(args);
				case "tsmap": return CmdTsMap.Run(args);
				case "attrcmp": return CmdAttrCmp.Run(args);
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
