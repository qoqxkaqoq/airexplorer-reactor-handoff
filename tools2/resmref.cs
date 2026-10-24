using System; using dnlib.DotNet;
class R {
  static void Main(string[] a) {
    var mod = ModuleDefMD.Load(a[0]);
    for (int i = 1; i < a.Length; i++) {
      uint raw = Convert.ToUInt32(a[i].Replace("0x",""), 16);
      var t = mod.ResolveToken(raw);
      Console.WriteLine("0x" + raw.ToString("X8") + " = " + (t == null ? "NULL" : t.ToString()));
    }
  }
}
