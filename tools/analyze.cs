// analyze.cs — 修复链产物静态体检: 方法体覆盖率/全局成员/资源表/关键方法状态
using System;
using System.Linq;
using dnlib.DotNet;

class Analyze {
    static int Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        int withBody = 0, noBody = 0;
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                if (m.HasBody) withBody++; else noBody++;
            }
        Console.WriteLine("[stat] 类型: " + mod.Types.Count + " | 方法有体: " + withBody + " 无体: " + noBody);
        var g = mod.GlobalType;
        if (g != null)
            Console.WriteLine("[stat] 全局: 方法 " + g.Methods.Count + " 字段 " + g.Fields.Count);
        foreach (var r in mod.Resources)
            Console.WriteLine("[res] " + r.ResourceType + " " + r.Name + " (" + ((r is dnlib.DotNet.EmbeddedResource er) ? er.CreateReader().Length : 0) + "B)");
        string[] keys = new string[] {
            "CloudClient.Models.StatelessModel::SearchAdapter",
            "AirExplorer.Wrapping.WrapperProvider::ValidateAccessibleResponderManager",
            "CloudClient.Templating.DispatcherInitializer::InstantiateTransferableProgram"
        };
        foreach (var t in mod.GetTypes())
            foreach (var m in t.Methods) {
                var fn = t.FullName + "::" + m.Name.String;
                if (keys.Contains(fn))
                    Console.WriteLine("[key] " + fn + " 体=" + m.HasBody + " 指令=" + (m.HasBody ? m.Body.Instructions.Count : 0));
            }
        return 0;
    }
}
