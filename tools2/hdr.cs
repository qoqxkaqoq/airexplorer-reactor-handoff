using System;
using System.Linq;
using dnlib.DotNet;
class H { static void Main(string[] a) {
  var mod = ModuleDefMD.Load(a[0]);
  int withLocals = 0, stubWithSigTok = 0, stub = 0;
  foreach (var t in mod.GetTypes()) foreach (var m in t.Methods) {
    if (!m.HasBody) continue;
    var b = m.Body;
    bool isStub = b.Instructions.Count <= 4;
    if (isStub) {
      stub++;
      if (b.LocalVarSigTok != 0) { stubWithSigTok++; if (stubWithSigTok <= 5) Console.WriteLine("stub with sigtok: " + t.FullName + "::" + m.Name + " tok=0x" + b.LocalVarSigTok.ToString("X8") + " vars=" + b.Variables.Count); }
    }
    if (b.Variables.Count > 0) withLocals++;
  }
  Console.WriteLine("stubs=" + stub + " stubsWithLocalVarSigTok=" + stubWithSigTok + " methodsWithLocals=" + withLocals);
} }
