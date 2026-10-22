using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using dnlib.IO;

// fixlocals2: 从**官方 exe** 的 MethodDef 表读 LocalVarSigTok（行内偏移 14），
// 再用 StandAloneSig.Signature 手工解析 LocalVarSig —— 官方 NecroBit 方法 RVA=0,
// 但 locals 签名在元数据里是完好的。这是最权威的 locals 来源
// (cilantro 有 161 个方法被改名/删除, 正是剩下 AV 的来源)。
//
// 用法: fixlocals2 <official.exe> <in.exe> <out.exe> [--all] [--dump]
class FixLocals2 {
    static void Main(string[] a) {
        if (a.Length < 3) { Console.WriteLine("usage: fixlocals2 <official> <in> <out> [--all] [--dump]"); return; }
        var src = ModuleDefMD.Load(a[0]);
        var dst = ModuleDefMD.Load(a[1]);
        bool all = a.Any(x => x == "--all");
        bool dump = a.Any(x => x == "--dump");
        var importer = new Importer(dst, ImporterOptions.TryToUseDefs);
        var tab = src.TablesStream.MethodTable;
        var rdr = src.Metadata.PEImage.CreateReader();
        Console.WriteLine("[official] methodTable off=0x" + tab.StartOffset.ToString("X") + " rowSize=" + tab.RowSize + " rows=" + tab.Rows);

        int n = 0, miss = 0, skipped = 0, nv = 0;
        foreach (var t in dst.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody || m.Body.Variables.Count == 0) continue;
                if (!all && !m.Body.Variables.All(v => v.Type.FullName == "System.Object")) { skipped++; continue; }
                uint rid = m.Rid;
                if (rid == 0 || rid > tab.Rows) { miss++; continue; }
                uint lvTok;
                rdr.Position = (uint)((long)tab.StartOffset + (long)(rid - 1) * tab.RowSize + 14);
                lvTok = rdr.ReadUInt32();
                if (lvTok == 0) { miss++; continue; }
                var list = ParseLocalSig(src, lvTok);
                if (list == null || list.Count == 0) { miss++; continue; }
                int k = Math.Min(list.Count, m.Body.Variables.Count);
                for (int i = 0; i < k; i++) {
                    try { m.Body.Variables[i].Type = importer.Import(list[i]); nv++; } catch { }
                }
                n++;
                if (dump) Console.WriteLine("[fix] " + t.FullName + "::" + m.Name + "  " + m.Body.Variables.Count + " <- " + list.Count);
            }
        }
        Console.WriteLine("[fixlocals2] fixed=" + n + " locals=" + nv + " miss=" + miss + " skipped=" + skipped);
        var wopt = new ModuleWriterOptions(dst);
        wopt.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        dst.Write(a[2], wopt);
        Console.WriteLine("[out] " + a[2]);
    }

    static List<TypeSig> ParseLocalSig(ModuleDef mod, uint tok) {
        try {
            var sa = mod.ResolveToken(tok) as StandAloneSig;
            if (sa == null) return null;
            var ls = sa.Signature as LocalSig;
            if (ls == null) return null;
            return ls.Locals.ToList();
        } catch { return null; }
    }

    static TypeSig ReadType(DataReader r, ModuleDef mod) {
        byte et = r.ReadByte();
        switch (et) {
            case 0x01: return mod.CorLibTypes.Void;
            case 0x02: return mod.CorLibTypes.Boolean;
            case 0x03: return mod.CorLibTypes.Char;
            case 0x04: return mod.CorLibTypes.SByte;
            case 0x05: return mod.CorLibTypes.Byte;
            case 0x06: return mod.CorLibTypes.Int16;
            case 0x07: return mod.CorLibTypes.UInt16;
            case 0x08: return mod.CorLibTypes.Int32;
            case 0x09: return mod.CorLibTypes.UInt32;
            case 0x0A: return mod.CorLibTypes.Int64;
            case 0x0B: return mod.CorLibTypes.UInt64;
            case 0x0C: return mod.CorLibTypes.Single;
            case 0x0D: return mod.CorLibTypes.Double;
            case 0x0E: return mod.CorLibTypes.String;
            case 0x11: return ReadTdor(r, mod).ToTypeSig(true);
            case 0x12: return ReadTdor(r, mod).ToTypeSig(false);
            case 0x13: return new GenericVar(r.ReadCompressedUInt32());
            case 0x1C: return mod.CorLibTypes.Object;
            case 0x1D: return new SZArraySig(ReadType(r, mod));
            case 0x10: return new ByRefSig(ReadType(r, mod));
            case 0x0F: return new PtrSig(ReadType(r, mod));
            case 0x1E: return new GenericMVar(r.ReadCompressedUInt32());
            case 0x15: {
                var gt = ReadType(r, mod) as ClassOrValueTypeSig;
                uint c = r.ReadCompressedUInt32();
                var args = new List<TypeSig>();
                for (uint i = 0; i < c; i++) args.Add(ReadType(r, mod));
                if (gt == null) return mod.CorLibTypes.Object;
                return new GenericInstSig(gt, args);
            }
            case 0x14: {
                var elem = ReadType(r, mod);
                uint rank = r.ReadCompressedUInt32();
                uint sizes = r.ReadCompressedUInt32();
                for (uint i = 0; i < sizes; i++) r.ReadCompressedUInt32();
                uint lob = r.ReadCompressedUInt32();
                for (uint i = 0; i < lob; i++) r.ReadCompressedUInt32();
                return new ArraySig(elem, rank);
            }
            default: return mod.CorLibTypes.Object;
        }
    }

    static ITypeDefOrRef ReadTdor(DataReader r, ModuleDef mod) {
        uint coded = r.ReadCompressedUInt32();
        uint rid = coded >> 2;
        uint tag = coded & 3;
        uint table = tag == 0 ? 0x02u : (tag == 1 ? 0x01u : 0x1Bu);
        var t = mod.ResolveToken((table << 24) | rid) as ITypeDefOrRef;
        return t;
    }
}
