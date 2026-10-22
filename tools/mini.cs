using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class Mini {
    static int Main() {
        var mod = new ModuleDefUser("mini", Guid.NewGuid());
        mod.Kind = ModuleKind.Windows;
        var corlib = mod.CorLibTypes.AssemblyRef;
        var vtRef = new TypeRefUser(mod, "System", "ValueType", corlib);
        var objRef = new TypeRefUser(mod, "System", "Object", corlib);
        var parent = new TypeDefUser("<PrivateImplementationDetails>{A53A4920-CC0A-4240-8495-9E102308B05D}", objRef);
        var sait = new TypeDefUser("<PrivateImplementationDetails>{A53A4920-CC0A-4240-8495-9E102308B05D}", "__StaticArrayInitTypeSize=40", vtRef);
        sait.ClassLayout = new ClassLayoutUser(1, 40);
        // 不嵌套, 放顶层
        var f = new FieldDefUser("0E448EF5", new FieldSig(new ValueTypeSig(sait)), FieldAttributes.Static | FieldAttributes.Public | FieldAttributes.InitOnly | FieldAttributes.HasFieldRVA);
        f.InitialValue = new byte[40];
        parent.Fields.Add(f);
        mod.Types.Add(parent); mod.Types.Add(sait);
        Console.WriteLine("ClassLayout=" + (sait.ClassLayout != null ? sait.ClassLayout.ClassSize.ToString() : "null") + " pack=" + sait.ClassLayout.PackingSize);
        Console.WriteLine("ClassLayout=" + (sait.ClassLayout != null ? sait.ClassLayout.ClassSize.ToString() : "null"));
        Console.WriteLine("IsValueType=" + sait.IsValueType);
        mod.Write("/tmp/mini_sa.exe");
        Console.WriteLine("写出 OK");
        return 0;
    }
}
