using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.MD;
using dnlib.PE;

class Inspect {
    static int Main(string[] a) {
        string path = a[0];
        var mod = ModuleDefMD.Load(path, new ModuleContext());
        var pe = (IPEImage)mod.Metadata.PEImage;
        Console.WriteLine("File: " + path + "  size=" + new FileInfo(path).Length);
        Console.WriteLine("Machine=" + pe.ImageNTHeaders.FileHeader.Machine + "  CorFlags=" + mod.Metadata.ImageCor20Header.Flags);
        Console.WriteLine("EP RVA=" + ((uint)pe.ImageNTHeaders.OptionalHeader.AddressOfEntryPoint).ToString("X8"));
        foreach (var s in pe.ImageSectionHeaders)
            Console.WriteLine(string.Format("SEC {0,-8} VA={1:X8} VSize={2:X8} Ptr={3:X8} RSize={4:X8} Char={5:X8}",
                s.Name, (uint)s.VirtualAddress, (uint)s.VirtualSize, (uint)s.PointerToRawData, (uint)s.SizeOfRawData, (uint)s.Characteristics));
        
        Console.WriteLine("Types=" + mod.Types.Count + " GlobalMeth=" + mod.GlobalType.Methods.Count);
        var gt = mod.GlobalType;
        Console.WriteLine("--- <Module> methods ---");
        foreach (var m in gt.Methods)
            Console.WriteLine("  " + m.Name + " RVA=" + ((uint)m.RVA).ToString("X8") + " impl=" + m.ImplAttributes + " attrs=" + m.Attributes + " body=" + m.HasBody);
        Console.WriteLine("--- <Module> fields ---");
        foreach (var f in gt.Fields)
            Console.WriteLine("  " + f.Name + " : " + f.FieldType + " attrs=" + f.Attributes + " rva=" + f.RVA);
        Console.WriteLine("--- <Module>::.cctor IL ---");
        var cc = gt.FindStaticConstructor();
        if (cc != null && cc.HasBody)
            foreach (var i in cc.Body.Instructions)
                Console.WriteLine(string.Format("  {0:X4} {1} {2}", i.Offset, i.OpCode, i.Operand));
        Console.WriteLine("--- DispatcherInitializer ---");
        var t = mod.GetTypes().FirstOrDefault(x => x.Name == "DispatcherInitializer");
        if (t == null) { Console.WriteLine("  NOT FOUND"); }
        else {
            Console.WriteLine("  Type flags=" + t.Attributes + " ns=" + t.Namespace + " base=" + t.BaseType);
            foreach (var f in t.Fields)
                Console.WriteLine("  F " + f.Name + " : " + f.FieldType + " " + f.Attributes + " rva=" + ((uint)f.RVA).ToString("X8") + (f.HasConstant ? " const=" + f.Constant.Value : ""));
            foreach (var m in t.Methods)
                Console.WriteLine("  M " + m.Name + " RVA=" + ((uint)m.RVA).ToString("X8") + " impl=" + m.ImplAttributes + " attrs=" + m.Attributes +
                    " body=" + m.HasBody + " pinvoke=" + m.IsPinvokeImpl + " params=" + string.Join(",", m.Parameters.Select(p => p.Type.ToString())));
        }
        Console.WriteLine("--- resources ---");
        foreach (var r in mod.Resources) {
            string extra = "";
            if (r is EmbeddedResource er) {
                var data = er.CreateReader().ToArray();
                extra = " len=" + data.Length + " head=" + BitConverter.ToString(data.Take(32).ToArray());
            }
            Console.WriteLine("  " + r.Name + " " + r.ResourceType + extra);
        }
        // assembly-level
        Console.WriteLine("--- assembly ---");
        Console.WriteLine("  " + (mod.Assembly == null ? "<none>" : mod.Assembly.FullName));
        foreach (var ca in mod.Assembly.CustomAttributes)
            Console.WriteLine("  CA " + ca.TypeFullName);
        Console.WriteLine("--- refs ---");
        foreach (var r in mod.GetAssemblyRefs())
            Console.WriteLine("  REF " + r.Name + " " + r.Version);
        // count methods with RVA=0 and their impl flags
        int rva0 = 0, rva0il = 0, rva0native = 0, rva0noimpl = 0;
        var byFlags = new Dictionary<string, int>();
        foreach (var ty in mod.GetTypes())
            foreach (var m in ty.Methods) {
                if (m.RVA == 0) {
                    rva0++;
                    if ((m.ImplAttributes & MethodImplAttributes.IL) != 0) rva0il++;
                    if ((m.ImplAttributes & MethodImplAttributes.Native) != 0) rva0native++;
                    if ((m.ImplAttributes & MethodImplAttributes.CodeTypeMask) == MethodImplAttributes.Runtime) rva0noimpl++;
                    string k = m.ImplAttributes.ToString();
                    byFlags[k] = byFlags.TryGetValue(k, out var c) ? c + 1 : 1;
                }
            }
        Console.WriteLine("RVA0 total=" + rva0 + " il=" + rva0il + " native=" + rva0native + " runtime=" + rva0noimpl);
        foreach (var kv in byFlags.OrderByDescending(x => x.Value).Take(10))
            Console.WriteLine("   " + kv.Key + " -> " + kv.Value);
        return 0;
    }
}
