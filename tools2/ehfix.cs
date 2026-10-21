// ehfix.cs — 修 "Bad IL range": 异常表的排序/嵌套问题
//
// CLR 对 EH 表的要求:
//   1) 嵌套的 handler 必须排在它所嵌套的那个之前(内层在前)
//   2) try 区间不能为空, handler 区间不能为空
//   3) handler 区间不能与自己的 try 区间重叠
// 违反会直接抛 BadImageFormatException: Bad IL range。
// Krypton 重写 + 我们回填体之后 EH 表顺序可能被打乱, 本工具把它规范化。
//
// 用法: ehfix <in.exe> <out.exe>
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class EhFix {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        int sorted = 0, dropped = 0;

        foreach (var t in mod.GetTypes()) {
            foreach (var m in t.Methods) {
                if (!m.HasBody) continue;
                var body = m.Body;
                if (body.ExceptionHandlers.Count == 0) continue;
                var instrs = body.Instructions;
                int last = instrs.Count == 0 ? 0 : (int)instrs[instrs.Count - 1].Offset + 1;

                var keep = new List<ExceptionHandler>();
                foreach (var eh in body.ExceptionHandlers) {
                    // 丢弃区间非法的项: 空区间 / 起止颠倒 / 越界 / handler 与 try 重叠
                    if (eh.TryStart == null || eh.TryEnd == null || eh.HandlerStart == null || eh.HandlerEnd == null) { dropped++; continue; }
                    int ts = (int)eh.TryStart.Offset, te = (int)eh.TryEnd.Offset;
                    int hs = (int)eh.HandlerStart.Offset, he = (int)eh.HandlerEnd.Offset;
                    if (ts >= te || hs >= he) { dropped++; continue; }
                    if (ts < 0 || te > last || hs < 0 || he > last) { dropped++; continue; }
                    bool overlap = !(he <= ts || te <= hs);
                    if (overlap) { dropped++; continue; }
                    keep.Add(eh);
                }

                // 内层在前: try 起点越靠后越内层; 同起点则 try 越短越内层
                var ordered = keep
                    .OrderByDescending(e => (int)e.TryStart.Offset)
                    .ThenBy(e => (int)e.TryEnd.Offset)
                    .ToList();

                bool changed = ordered.Count != body.ExceptionHandlers.Count;
                if (!changed)
                    for (int i = 0; i < ordered.Count; i++)
                        if (!ReferenceEquals(ordered[i], body.ExceptionHandlers[i])) { changed = true; break; }

                if (changed) {
                    body.ExceptionHandlers.Clear();
                    foreach (var eh in ordered) body.ExceptionHandlers.Add(eh);
                    sorted++;
                }
            }
        }

        Console.WriteLine("[ehfix] 规范化 EH 表的方法 " + sorted + " / 丢弃非法 EH 项 " + dropped);
        if (sorted == 0 && dropped == 0) { Console.WriteLine("[ehfix] 无需改动"); return; }
        var wopt = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
        wopt.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
        mod.Write(a[1], wopt);
        Console.WriteLine("[ehfix] 写出: " + a[1]);
    }
}
