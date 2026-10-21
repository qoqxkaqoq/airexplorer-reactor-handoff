using System; using System.Collections.Generic; using System.Linq; using dnlib.DotNet; using dnlib.DotNet.Emit;
class P { static void Main(string[] a) {
  var m = ModuleDefMD.Load(a[0]);
  var cat = new Dictionary<string,int>();
  foreach (var t in m.GetTypes()) foreach (var mm in t.Methods) {
    if (!mm.HasBody) continue;
    var ins = mm.Body.Instructions;
    if (ins.Count > 4 || !ins.All(i=>i.OpCode.Code==Code.Nop||i.OpCode.Code==Code.Ret)) continue;
    string k = mm.Name.StartsWith("add_") ? "add_" : mm.Name.StartsWith("remove_") ? "remove_" :
               mm.Name.StartsWith("get_") ? "get_" : mm.Name.StartsWith("set_") ? "set_" :
               mm.Name == ".ctor" ? ".ctor" : mm.Name == ".cctor" ? ".cctor" : (mm.ReturnType.FullName=="System.Void"?"other-void":"other");
    cat[k] = cat.TryGetValue(k, out var c) ? c+1 : 1;
  }
  foreach (var kv in cat.OrderByDescending(x=>x.Value)) Console.WriteLine(kv.Value + "\t" + kv.Key);
}}
