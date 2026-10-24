// peekil <exe> <tok-hex>...  print MethodDef RVA / header / first IL bytes from the exe in place
using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;

class PeekIL {
    static void Main(string[] args) {
        var mod = ModuleDefMD.Load(args[0]);
        foreach (var a in args.Skip(1)) {
            uint tok = Convert.ToUInt32(a, 16);
            var m = mod.ResolveToken(tok) as MethodDef;
            if (m == null) { Console.WriteLine($"{a}: not a MethodDef"); continue; }
            Console.WriteLine($"=== {a} {m.FullName}");
            Console.WriteLine($"  rva=0x{(uint)m.RVA:X8}");
            if (m.Body == null) { Console.WriteLine("  no body (abstract/pinvoke)"); continue; }
            uint rva = (uint)m.RVA;
            var fs = new FileStream(args[0], FileMode.Open, FileAccess.Read);
            var br = new BinaryReader(fs);
            fs.Seek(0x3C, SeekOrigin.Begin); int peOff = br.ReadInt32();
            fs.Seek(peOff + 6, SeekOrigin.Begin); ushort nsec = br.ReadUInt16();
            fs.Seek(peOff + 20, SeekOrigin.Begin); ushort optSize = br.ReadUInt16();
            int secOff = peOff + 24 + optSize;
            uint fileOff = 0;
            for (int i = 0; i < nsec; i++) {
                fs.Seek(secOff + i * 40, SeekOrigin.Begin);
                br.ReadBytes(8);
                uint vsz = br.ReadUInt32(), vaddr = br.ReadUInt32();
                if (rva >= vaddr && rva < vaddr + vsz) {
                    uint rawsz = br.ReadUInt32(); br.ReadUInt32();
                    fs.Seek(secOff + i * 40 + 20, SeekOrigin.Begin);
                    uint rawptr = br.ReadUInt32();
                    fileOff = rawptr + (rva - vaddr); break;
                }
            }
            fs.Seek(fileOff, SeekOrigin.Begin);
            var hdr = br.ReadByte();
            if ((hdr & 3) == 2) {
                int ilSize = hdr >> 2;
                Console.WriteLine($"  header=tiny codesize={ilSize}");
                fs.Seek(fileOff + 1, SeekOrigin.Begin);
                var il = br.ReadBytes(Math.Min(ilSize, 64));
                Console.WriteLine("  il: " + BitConverter.ToString(il).Replace('-', ' '));
            } else {
                fs.Seek(fileOff, SeekOrigin.Begin);
                var fb = br.ReadBytes(12);
                int hsize = (fb[1] >> 4) * 4;
                int ilSize = (int)BitConverter.ToUInt32(fb, 4);
                ushort mstk = BitConverter.ToUInt16(fb, 2);
                uint ltok = BitConverter.ToUInt32(fb, 8);
                Console.WriteLine($"  header=fat hsize={hsize} codesize={ilSize} maxstack={mstk} localstok=0x{ltok:X8}");
                fs.Seek(fileOff + hsize, SeekOrigin.Begin);
                var il = br.ReadBytes(Math.Min(ilSize, 64));
                Console.WriteLine("  il: " + BitConverter.ToString(il).Replace('-', ' '));
            }
            fs.Close();
        }
    }
}
