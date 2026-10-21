using System;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
class P { static int Main(string[] a) {
  var m = ModuleDefMD.Load(a[0]);
  var o = new ModuleWriterOptions(m); o.Logger = DummyLogger.NoThrowInstance;
  m.Write(a[1], o);
  Console.WriteLine("resaved -> " + a[1]);
  return 0;
}}
