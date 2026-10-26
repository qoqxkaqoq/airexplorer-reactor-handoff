using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.IO;

namespace AirExplorerUnpacker;

/// <summary>
/// ehprobe — 实验命令: 给定 module_text 快照与 manifest, 用 dnlib MethodBodyReader
/// 解析运行时方法体字节 (head+IL+EH 一体), 验证 EH 段能否被 dnlib 正确理解。
/// 用法: ehprobe &lt;slayed.exe&gt; &lt;module_text.bin&gt; &lt;manifest.tsv&gt; [sampleN]
/// </summary>
public static class CmdEhProbe
{
    const int MT_SHIFT = 0x2000;

    public static int Run(string[] args)
    {
        if (args.Length < 4) { Console.WriteLine("usage: ehprobe <exe> <module_text.bin> <manifest.tsv> [N]"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var mt = File.ReadAllBytes(args[2]);
        var manifest = File.ReadLines(args[3]).Skip(1)
            .Select(l => l.Split('\t'))
            .Where(p => p.Length >= 4)
            .ToDictionary(p => p[1], p => p[0]);
        int n = args.Length > 4 ? int.Parse(args[4]) : 8;

        int done = 0, ok = 0, fail = 0;
        foreach (var kv in manifest)
        {
            if (done >= n) break;
            var tok = kv.Key;
            var rva = Convert.ToInt32(kv.Value, 16);
            int off = rva - MT_SHIFT;
            if (off < 0 || off + 12 > mt.Length) continue;
            byte b0 = mt[off];
            int kind = b0 & 3;
            int hsz, codesize;
            if (kind == 3)
            {
                hsz = ((mt[off + 1] >> 4) & 0xF) * 4;
                codesize = BitConverter.ToInt32(mt, off + 4);
            }
            else { hsz = 1; codesize = b0 >> 2; }
            if (codesize <= 0 || codesize > 0x100000) { Console.WriteLine("[skip] " + tok + " bad codesize"); continue; }
            int hasEh = (kind == 3 && (b0 & 8) != 0) ? 1 : 0;

            // 体大小: 头+IL (+EH 若有). EH 尾长度估算: 扫描到下一个方法头/按 datasize
            int end = off + hsz + codesize;
            int padLen = 0;
            int ehLen = 0;
            if (hasEh == 1)
            {
                int sect = (end + 3) & ~3;
                padLen = sect - end;
                if (sect + 4 <= mt.Length)
                {
                    uint hdr = BitConverter.ToUInt32(mt, sect);
                    int fl = (int)(hdr & 0xFF);
                    int dsize = (int)(hdr >> 8) & 0xFFFFFF;
                    Console.WriteLine("[eh] {0} sectFlags=0x{1:X2} dsize={2}", tok, fl, dsize);
                    ehLen = dsize; // 含头
                }
            }
            int total = hsz + codesize + padLen + ehLen;
            var codeBytes = new byte[codesize];
            Array.Copy(mt, off + hsz, codeBytes, 0, codesize);
            byte[] ehBytes = null;
            if (ehLen > 0)
            {
                ehBytes = new byte[ehLen];
                Array.Copy(mt, (end + 3) & ~3, ehBytes, 0, ehLen);
            }
            try
            {
                var md = mod.ResolveToken(uint.Parse(tok, System.Globalization.NumberStyles.HexNumber)) as MethodDef;
                var gp = new dnlib.DotNet.GenericParamContext();
                var body = MethodBodyReader.CreateCilBody(mod, codeBytes, ehBytes, md.Parameters, gp);
                if (body == null) throw new Exception("CreateCilBody returned null");
                var ilLen = body.Instructions.Count;
                var ehCount = body.ExceptionHandlers.Count;
                Console.WriteLine("[ok] {0} kind={1} hsz={2} codesize={3} instrs={4} eh={5} maxstack={6} locals={7} initLocals={8}",
                    tok, kind, hsz, codesize, ilLen, ehCount, body.MaxStack, body.Variables.Count, body.InitLocals);
                foreach (var eh in body.ExceptionHandlers.Take(3))
                    Console.WriteLine("     eh: {0} try[{1:X}..{2:X}) handler[{3:X}..{4:X}) catch={5}",
                        eh.HandlerType,
                        eh.TryStart?.Offset ?? uint.MaxValue, eh.TryEnd?.Offset ?? uint.MaxValue,
                        eh.HandlerStart?.Offset ?? uint.MaxValue, eh.HandlerEnd?.Offset ?? uint.MaxValue,
                        eh.CatchType?.FullName ?? "-");
                ok++;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[fail] {0}: {1}", tok, ex.Message);
                fail++;
            }
            done++;
        }
        Console.WriteLine("[ehprobe] ok={0} fail={1}", ok, fail);
        return 0;
    }
}
