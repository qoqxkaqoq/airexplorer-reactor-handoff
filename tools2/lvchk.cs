using System;
using System.Linq;
using dnlib.DotNet;
class LVChk {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var tab = mod.TablesStream.MethodTable;
        var rdr = mod.Metadata.PEImage.CreateReader();
        Console.WriteLine("table off=0x" + tab.StartOffset.ToString("X") + " rowSize=" + tab.RowSize + " rows=" + tab.Rows);
        foreach (var t in mod.GetTypes()) {
            if (t.FullName.IndexOf(a[1], StringComparison.Ordinal) < 0) continue;
            foreach (var m in t.Methods) {
                if (a.Length > 2 && m.Name.IndexOf(a[2], StringComparison.Ordinal) < 0) continue;
                if (m.Rid == 0 || m.Rid > tab.Rows) continue;
                rdr.Position = (uint)((long)tab.StartOffset + (long)(m.Rid - 1) * tab.RowSize + 14);
                uint lv = rdr.ReadUInt32();
                Console.WriteLine(t.FullName + "::" + m.Name + "  rid=" + m.Rid + " rva=0x" + m.RVA.ToString("X") + " lvTok=0x" + lv.ToString("X"));
            }
        }
    }
}
