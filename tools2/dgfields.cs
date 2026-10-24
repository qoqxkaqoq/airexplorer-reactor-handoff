using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;

// dgfields — enumerate static nonpublic fields of a TypeDef (GetFields(BindingFlags 1064) semantics),
// to build known-plaintext for the delegate table (06004193 TrackCompiler).
// usage: dgfields <exe> <typedef-token-hex>
class DgFields {
    static ModuleDef mod;
    static void Main(string[] a) {
        mod = ModuleDefMD.Load(a[0]);
        uint tok = Convert.ToUInt32(a[1], 16);
        var td = mod.ResolveToken(tok) as TypeDef;
        if (td == null) { Console.WriteLine("type not found"); return; }
        Console.WriteLine($"TYPE {tok:X8} {td.FullName} fields={td.Fields.Count}");
        int nonpubStatic = 0;
        foreach (var f in td.Fields) {
            bool isStatic = f.IsStatic;
            bool nonPublic = !f.IsPublic;
            string sig = f.FieldType?.FullName ?? "?";
            bool del = IsDelegate(f.FieldType);
            if (isStatic && nonPublic) nonpubStatic++;
            Console.WriteLine($"{f.MDToken.Raw:X8}\tstatic={isStatic}\tnonpub={nonPublic}\tdel={del}\t{sig}\t{f.Name}");
        }
        Console.WriteLine($"# nonpub+static = {nonpubStatic}");
    }
    // resolve field type to a TypeDef and walk base chain looking for MulticastDelegate
    static bool IsDelegate(TypeSig s) {
        s = s.RemovePinnedAndModifiers();
        if (s is GenericInstSig gis) s = gis.GenericType;
        var tdr = s as TypeDefOrRefSig;
        if (tdr == null) return false;
        ITypeDefOrRef t = tdr.TypeDefOrRef;
        for (int depth = 0; depth < 12 && t != null; depth++) {
            var td2 = t.ResolveTypeDef();
            if (td2 == null) return false;
            if (td2.FullName == "System.MulticastDelegate") return true;
            t = td2.BaseType;
        }
        return false;
    }
}
