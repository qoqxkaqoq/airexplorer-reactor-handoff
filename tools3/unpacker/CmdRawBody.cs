using dnlib.DotNet;
using dnlib.PE;

namespace AirExplorerUnpacker;

/// <summary>rawbody &lt;exe&gt; &lt;tok&gt; — 从产物文件直接抽原始方法体字节（非重线性化）。</summary>
public static class CmdRawBody
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: rawbody <exe> <tok>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var r = mod.ResolveToken(Convert.ToUInt32(args[2], 16));
        if (r is not MethodDef m || m.RVA == 0) { Console.WriteLine("no rva"); return 1; }
        var img = mod.Metadata.PEImage;
        uint rva = (uint)m.RVA;
        var fo = img.ToFileOffset(new RVA(rva));
        using var stream = img.CreateStream();
        stream.Position = fo;
        var head = new byte[16];
        stream.Read(head, 0, 16);
        int hsz, cs;
        byte b0 = head[0];
        if ((b0 & 3) == 2) { hsz = 1; cs = b0 >> 2; }
        else
        {
            hsz = ((head[1] >> 4) & 0xF) * 4;
            cs = BitConverter.ToInt32(head, 4);
            // 读更多
            stream.Position = fo;
            var buf = new byte[hsz + cs + 4 + 256];
            if (cs + hsz + 260 > buf.Length) Array.Resize(ref buf, hsz + cs + 260);
            stream.Read(buf, 0, buf.Length);
            Console.WriteLine("fat hsz={0} codesize={1} maxstack={2} b0={3:X2} locals={4:X8}",
                hsz, cs, BitConverter.ToUInt16(head, 2), b0, BitConverter.ToUInt32(head, 8));
            int sect = (hsz + cs + 3) & ~3;
            if (b0 >> 0 != 0 && (buf.Length > sect + 4))
            {
                uint ehHdr = BitConverter.ToUInt32(buf, sect);
                Console.WriteLine("EH sect hdr: {0:X8} (flagsByte={1:X2} dsize={2})",
                    ehHdr, ehHdr & 0xFF, (ehHdr >> 8) & 0xFFFFFF);
            }
            for (int i = 0; i < Math.Min(hsz + cs, buf.Length); i += 64)
                Console.WriteLine("{0:X5} {1}", i, Convert.ToHexString(buf, i, Math.Min(64, buf.Length - i)));
            return 0;
        }
        Console.WriteLine("tiny cs={0}", cs);
        return 0;
    }
}
