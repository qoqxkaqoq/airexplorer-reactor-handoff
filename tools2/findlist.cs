using System; using System.Linq; using dnlib.DotNet;
class F {
  static void Main(string[] a) {
    var mod = ModuleDefMD.Load(a[0]);
    foreach (var mr in mod.GetMemberRefs()) {
      if (mr.IsMethodRef && mr.Name == ".ctor" && mr.Class != null && mr.Class.FullName.Contains("List`1<CloudClient.Networking.AdvancedClient>"))
        Console.WriteLine("0x" + mr.MDToken.Raw.ToString("X8") + "  " + mr.FullName);
    }
  }
}
