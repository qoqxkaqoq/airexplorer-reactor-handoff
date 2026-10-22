using System;
using dnlib.DotNet;

class FldVer {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        foreach (var t in mod.GetTypes()) {
            if (!t.Name.String.StartsWith("<PrivateImplementationDetails>")) continue;
            Console.WriteLine("类型: " + t.FullName);
            Console.WriteLine("  attrs=" + t.Attributes + " layout=" + (t.IsAutoLayout ? "Auto" : t.IsSequentialLayout ? "Sequential" : "Explicit") + " CL=" + (t.ClassLayout != null ? t.ClassLayout.PackingSize + "/" + t.ClassLayout.ClassSize : "无"));
            foreach (var f in t.Fields) {
                var ts = f.FieldSig.Type;
                bool ok = false;
                string why = "";
                try {
                    var td = ts.TryGetTypeDef();
                    if (td == null) { var tr = ts.TryGetTypeRef(); td = tr == null ? null : tr.Resolve(); why = tr == null ? "非TypeRef" : (td == null ? "TypeRef解析失败!" : "经Resolve"); }
                    if (td != null) {
                        ok = td.IsValueType;
                        if (!ok) why = "非值类型:" + td.FullName;
                        else why = "CL=" + (td.ClassLayout != null ? td.ClassLayout.ClassSize.ToString() : "null") + " layout=" + (td.IsAutoLayout ? "Auto" : "Seq") + " fields=" + td.Fields.Count + " sealed=" + td.IsSealed + " attrs=" + td.Attributes;
                    }
                } catch (Exception ex) { why = "异常:" + ex.Message; }
                Console.WriteLine("  字段 " + f.Name.String.Substring(0, Math.Min(20, f.Name.String.Length)) + " [" + ts.GetType().Name + "] ok=" + ok + " " + why);
            }
            foreach (var nt in t.NestedTypes) {
                Console.WriteLine("  嵌套 " + nt.Name.String + " CL=" + (nt.ClassLayout != null ? nt.ClassLayout.PackingSize + "/" + nt.ClassLayout.ClassSize : "无") + " attrs=" + nt.Attributes + " fields=" + nt.Fields.Count + " sealed=" + nt.IsSealed + " base=" + (nt.BaseType == null ? "null" : nt.BaseType.FullName) + " baseScope=" + (nt.BaseType is TypeRef btr ? (btr.ResolutionScope == null ? "null" : btr.ResolutionScope.GetType().Name) : "TypeDef"));
            }
        }
        return 0;
    }
}
