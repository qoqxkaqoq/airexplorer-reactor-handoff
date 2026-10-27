using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace AirExplorerUnpacker;

/// <summary>
/// patchstub — 给产物中指定 token 的方法造独立 ret 桩体（因果实验用）。
/// 用法: patchstub &lt;in.exe&gt; &lt;out.exe&gt; &lt;tok1,tok2,...|all-shared&gt; &lt;slayed.exe&gt;
///   all-shared: 读 slayed，Body=null 且 RVA!=0 的方法在产物里全部独立 ret 桩化
/// </summary>
public static class CmdPatchStub
{
    public static int Run(string[] args)
    {
        if (args.Length < 4) { Console.WriteLine("usage: patchstub <in.exe> <out.exe> <toks|all-shared> <slayed.exe>"); return 2; }
        string inP = args[1], outP = args[2], mode = args[3], slayedP = args[4];
        var mod = ModuleDefMD.Load(inP);

        var targets = new HashSet<uint>();
        if (mode == "all-shared")
        {
            // 判据: 产物里 MethodDef RVA 相同的方法组 (共享桩) -> 全部独立化
            var byRva = new Dictionary<uint, List<MethodDef>>();
            foreach (var t in mod.GetTypes())
                foreach (var m in t.Methods)
                {
                    uint r = (uint)m.RVA;
                    if (r == 0 || m.IsAbstract || (m.Attributes & MethodAttributes.PinvokeImpl) != 0) continue;
                    if (!byRva.TryGetValue(r, out var l)) byRva[r] = l = new List<MethodDef>();
                    l.Add(m);
                }
            foreach (var kv in byRva)
                if (kv.Value.Count > 1)
                    foreach (var m in kv.Value) targets.Add((uint)m.MDToken.Raw);
            Console.WriteLine($"[patchstub] shared-RVA methods -> {targets.Count}");
        }
        else if (mode != "impl" && mode != "noeh" && mode != "copybody" && mode != "copybatch" && mode != "stubfile" && mode != "prune")
        {
            foreach (var s in mode.Split(','))
                targets.Add(Convert.ToUInt32(s.Trim().Replace("0x", ""), 16));
        }

        int n = 0;
        if (mode == "copybatch")
        {
            // args[4] = tok 清单文件, args[5] = src exe
            var src = ModuleDefMD.Load(args[5]);
            var srcMap = new Dictionary<uint, MethodDef>();
            foreach (var t in src.GetTypes())
                foreach (var m in t.Methods)
                    if (m.HasBody) srcMap[(uint)m.MDToken.Raw] = m;
            var dstMap = new Dictionary<uint, MethodDef>();
            foreach (var t in mod.GetTypes())
                foreach (var m in t.Methods)
                    dstMap[(uint)m.MDToken.Raw] = m;
            int cnt = 0;
            foreach (var line in File.ReadLines(args[4]))
            {
                var tkS = line.Trim().Replace("0x", "");
                if (tkS.Length == 0) continue;
                uint tk = Convert.ToUInt32(tkS, 16);
                if (!srcMap.TryGetValue(tk, out var sm) || !dstMap.TryGetValue(tk, out var dm)) continue;
                var nb = new CilBody();
                var map = new Dictionary<Instruction, Instruction>();
                foreach (var i2 in sm.Body.Instructions)
                {
                    var ni = new Instruction(i2.OpCode);
                    object? opnd = i2.Operand;
                    switch (opnd)
                    {
                        case Instruction ti: opnd = null; break;
                        case Instruction[] ta: opnd = new Instruction[ta.Length]; break;
                        case ITokenOperand to: opnd = mod.ResolveToken(to.MDToken.Raw); break;
                        case int iv: case long lv: case double dv: case float fv: case string sv: break;
                        default: break;
                    }
                    ni.Operand = opnd; map[i2] = ni; nb.Instructions.Add(ni);
                }
                foreach (var i2 in sm.Body.Instructions)
                {
                    if (i2.Operand is Instruction ti && map.ContainsKey(ti)) map[i2].Operand = map[ti];
                    if (i2.Operand is Instruction[] ta)
                        map[i2].Operand = ta.Select(t2 => map.TryGetValue(t2, out var x) ? x : map.TryGetValue(t2, out var y) ? y : map.Values.First()).ToArray();
                }
                nb.MaxStack = sm.Body.MaxStack;
                foreach (var eh in sm.Body.ExceptionHandlers)
                {
                    var ne = new ExceptionHandler(eh.HandlerType);
                    if (!map.TryGetValue(eh.TryStart, out var ts2) || !map.TryGetValue(eh.TryEnd, out var te2) ||
                        !map.TryGetValue(eh.HandlerStart, out var hs2)) continue;
                    ne.TryStart = ts2; ne.TryEnd = te2; ne.HandlerStart = hs2;
                    if (eh.HandlerEnd != null && map.TryGetValue(eh.HandlerEnd, out var he2)) ne.HandlerEnd = he2;
                    if (eh.FilterStart != null && map.TryGetValue(eh.FilterStart, out var fs2)) ne.FilterStart = fs2;
                    if (eh.CatchType != null)
                    {
                        var ct = mod.ResolveToken(eh.CatchType.MDToken.Raw) as ITypeDefOrRef;
                        if (ct == null) continue;
                        ne.CatchType = ct;
                    }
                    nb.ExceptionHandlers.Add(ne);
                }
                dm.Body = nb;
                cnt++;
            }
            var optsB = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
            optsB.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
            mod.Write(args[2], optsB);
            Console.WriteLine($"[copybatch] copied {cnt} bodies -> {args[2]}");
            return 0;
        }
        if (mode == "copybody")
        {
            // args[4] = src exe; tok = 目标方法
            uint tk = Convert.ToUInt32(args[4].Trim().Replace("0x", ""), 16);
            var src = ModuleDefMD.Load(args[5]);
            MethodDef? sm = null, dm = null;
            foreach (var t in src.GetTypes()) foreach (var m in t.Methods) if ((uint)m.MDToken.Raw == tk && m.HasBody) { sm = m; break; }
            foreach (var t in mod.GetTypes()) foreach (var m in t.Methods) if ((uint)m.MDToken.Raw == tk) { dm = m; break; }
            if (sm == null || dm == null) { Console.WriteLine("[copybody] method missing"); return 1; }
            var nb = new CilBody();
            var map = new Dictionary<Instruction, Instruction>();
            foreach (var i2 in sm.Body.Instructions)
            {
                var ni = new Instruction(i2.OpCode);
                object? opnd = i2.Operand;
                switch (opnd)
                {
                    case Instruction ti: opnd = null; break; // 目标后补
                    case Instruction[] ta: opnd = new Instruction[ta.Length]; break;
                    case ITokenOperand to: opnd = mod.ResolveToken(to.MDToken.Raw); break;
                    case int iv: opnd = iv; break;
                    case long lv: opnd = lv; break;
                    case double dv: opnd = dv; break;
                    case float fv: opnd = fv; break;
                    case string sv: opnd = sv; break;
                    default: opnd = opnd; break;
                }
                ni.Operand = opnd;
                map[i2] = ni;
                nb.Instructions.Add(ni);
            }
            foreach (var i2 in sm.Body.Instructions)
            {
                if (i2.Operand is Instruction ti && map.ContainsKey(ti)) map[i2].Operand = map[ti];
                if (i2.Operand is Instruction[] ta)
                    map[i2].Operand = ta.Select(t2 => map.TryGetValue(t2, out var x) ? x : null).ToArray();
            }
            nb.MaxStack = sm.Body.MaxStack;
            dm.Body = nb;
            var optsC = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
            optsC.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
            mod.Write(args[2], optsC);
            Console.WriteLine($"[copybody] tok=0x{tk:X8} instrs={nb.Instructions.Count} maxstack={nb.MaxStack} -> {args[2]}");
            return 0;
        }
        if (mode == "prune")
        {
            // args[4]=tok, args[5]=保留指令数 N
            // 保留 [0,N): dangling 分支→栈平衡等价(nop/pop), 尾部按模拟栈深补 pop*+ret, EH 全删
            uint tk = Convert.ToUInt32(args[4].Trim().Replace("0x", ""), 16);
            int keepN = int.Parse(args[5]);
            foreach (var t in mod.GetTypes())
                foreach (var m in t.Methods)
                {
                    if ((uint)m.MDToken.Raw != tk || !m.HasBody) continue;
                    var ins = m.Body.Instructions;
                    int total = ins.Count;
                    var kept = ins.Take(Math.Min(keepN, total)).ToList();
                    var keptSet = new HashSet<Instruction>(kept);
                    var nb = new CilBody();
                    foreach (var i2 in kept) nb.Instructions.Add(i2);
                    // 尾部: 模拟保留前缀结束时的栈深 d, 补 pop*d + ret
                    int d = 0;
                    foreach (var i2 in kept)
                    {
                        var o = i2.OpCode;
                        int pops = 0, push = 0;
                        if (o.StackBehaviourPop == StackBehaviour.Pop1 || o.StackBehaviourPop == StackBehaviour.Popi || o.StackBehaviourPop == StackBehaviour.Popref) pops = 1;
                        else if (o.StackBehaviourPop == StackBehaviour.Pop1_pop1 || o.StackBehaviourPop == StackBehaviour.Popi_pop1) pops = 2;
                        else if (o.StackBehaviourPop == StackBehaviour.Popi_popi) pops = 2;
                        else if (o.StackBehaviourPop == StackBehaviour.Popi_popi8) pops = 2;
                        else if (o.StackBehaviourPop == StackBehaviour.Popref_pop1) pops = 2;
                        else if (o.StackBehaviourPop == StackBehaviour.Popref_popi) pops = 2;
                        else if (o.StackBehaviourPop == StackBehaviour.Popi_popi_popi) pops = 3;
                        else if (o.StackBehaviourPop == StackBehaviour.Popref_popi_popi) pops = 3;
                        else if (o.StackBehaviourPop == StackBehaviour.PopAll) pops = d;
                        if (o.StackBehaviourPush == StackBehaviour.Push1 || o.StackBehaviourPush == StackBehaviour.Pushi || o.StackBehaviourPush == StackBehaviour.Pushref || o.StackBehaviourPush == StackBehaviour.Pushi8 || o.StackBehaviourPush == StackBehaviour.Pushr4 || o.StackBehaviourPush == StackBehaviour.Pushr8) push = 1;
                        else if (o.StackBehaviourPush == StackBehaviour.Push1_push1) push = 2;
                        d = Math.Max(0, d - pops + push);
                    }
                    for (int p = 0; p < d; p++) nb.Instructions.Add(Instruction.Create(OpCodes.Pop));
                    nb.Instructions.Add(Instruction.Create(OpCodes.Ret));
                    // dangling 分支 → 栈平衡等价指令
                    int fixedB = 0;
                    foreach (var i2 in nb.Instructions.ToList())
                    {
                        object opnd = i2.Operand;
                        bool dangling = (opnd is Instruction ti && !keptSet.Contains(ti)) ||
                                        (opnd is Instruction[] ta && ta.Any(t2 => !keptSet.Contains(t2)));
                        if (!dangling) continue;
                        var c = i2.OpCode.Code;
                        if (c == Code.Brtrue || c == Code.Brtrue_S || c == Code.Brfalse || c == Code.Brfalse_S || c == Code.Switch)
                        {
                            i2.Operand = null; i2.OpCode = OpCodes.Pop;  // 弹1
                        }
                        else if (c == Code.Br || c == Code.Br_S || c == Code.Leave || c == Code.Leave_S)
                        {
                            i2.OpCode = OpCodes.Nop;  // 无栈操作
                        }
                        fixedB++;
                    }
                    nb.MaxStack = (ushort)Math.Max((int)m.Body.MaxStack, 8);
                    m.Body = nb;
                    Console.WriteLine($"[prune] 0x{tk:X8} total={total} kept={kept.Count} endDepth={d} fixedBranches={fixedB}");
                }
            var optsP = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
            optsP.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
            mod.Write(args[2], optsP);
            return 0;
        }
        if (mode == "stubfile")
        {
            foreach (var line in File.ReadLines(args[4]))
            {
                var t2 = line.Trim().Replace("0x", "");
                if (t2.Length == 0) continue;
                targets.Add(Convert.ToUInt32(t2, 16));
            }
            Console.WriteLine($"[dbg] targets={targets.Count}");
            foreach (var t in mod.GetTypes())
                foreach (var m in t.Methods)
                {
                    if (!targets.Contains((uint)m.MDToken.Raw)) continue;
                    var body = new CilBody();
                    var ret = m.MethodSig?.RetType;
                    if (ret != null && ret.FullName != "System.Void")
                    {
                        switch (ret.ElementType)
                        {
                            case ElementType.Boolean: case ElementType.Char:
                            case ElementType.I1: case ElementType.U1: case ElementType.I2: case ElementType.U2:
                            case ElementType.I4: case ElementType.U4: case ElementType.I8: case ElementType.U8:
                            case ElementType.R4: case ElementType.R8: case ElementType.I: case ElementType.U:
                                body.Instructions.Add(Instruction.CreateLdcI4(0)); break;
                            default: body.Instructions.Add(Instruction.Create(OpCodes.Ldnull)); break;
                        }
                    }
                    body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                    m.Body = body; m.Body.MaxStack = 8;
                    n++;
                }
            var optsS = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
            optsS.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
            mod.Write(args[2], optsS);
            Console.WriteLine($"[patchstub] stubfile stubbed {n} -> {args[2]}");
            return 0;
        }
        if (mode == "noeh")
        {
            targets.Add(Convert.ToUInt32(args[4].Trim().Replace("0x", ""), 16));  // tok
            foreach (var t in mod.GetTypes())
                foreach (var m in t.Methods)
                    if (targets.Contains((uint)m.MDToken.Raw) && m.HasBody)
                    {
                        Console.WriteLine($"[noeh] {m.Name}: eh={m.Body.ExceptionHandlers.Count}");
                        m.Body.ExceptionHandlers.Clear();
                        foreach (var ins in m.Body.Instructions.ToList())
                        {
                            if (ins.OpCode.Code == Code.Leave) ins.OpCode = OpCodes.Br;
                            else if (ins.OpCode.Code == Code.Leave_S) ins.OpCode = OpCodes.Br_S;
                        }
                        n++;
                    }
            var optsN = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
            optsN.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
            mod.Write(args[2], optsN);
            Console.WriteLine($"[patchstub] noeh on {n} -> {args[2]}");
            return 0;
        }
        if (mode == "impl")
        {
            targets.Add(Convert.ToUInt32(args[4].Trim().Replace("0x", ""), 16));
            foreach (var t in mod.GetTypes())
                foreach (var m in t.Methods)
                    if (targets.Contains((uint)m.MDToken.Raw))
                    { m.ImplAttributes = MethodImplAttributes.NoInlining; n++; }
            var optsI = new dnlib.DotNet.Writer.ModuleWriterOptions(mod);
            optsI.MetadataOptions.Flags |= dnlib.DotNet.Writer.MetadataFlags.PreserveAll | dnlib.DotNet.Writer.MetadataFlags.KeepOldMaxStack;
            mod.Write(args[2], optsI);
            Console.WriteLine($"[patchstub] impl set on {n} -> {args[2]}");
            return 0;
        }
        foreach (var t in mod.GetTypes())
        {
            foreach (var m in t.Methods)
            {
                if (!targets.Contains((uint)m.MDToken.Raw)) continue;
                var body = new CilBody();
                var ret = m.MethodSig?.RetType;
                if (ret != null && ret.FullName != "System.Void")
                {
                    switch (ret.ElementType)
                    {
                        case ElementType.Boolean: case ElementType.Char:
                        case ElementType.I1: case ElementType.U1: case ElementType.I2: case ElementType.U2:
                        case ElementType.I4: case ElementType.U4: case ElementType.I8: case ElementType.U8:
                        case ElementType.R4: case ElementType.R8: case ElementType.I: case ElementType.U:
                            body.Instructions.Add(Instruction.CreateLdcI4(0)); break;
                        default: body.Instructions.Add(Instruction.Create(OpCodes.Ldnull)); break;
                    }
                }
                body.Instructions.Add(Instruction.Create(OpCodes.Nop));
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                m.Body = body;
                m.Body.MaxStack = 8;
                n++;
            }
        }
        var opts = new ModuleWriterOptions(mod);
        opts.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        mod.Write(outP, opts);
        Console.WriteLine($"[patchstub] stubbed {n}/{targets.Count} -> {outP}");
        return 0;
    }
}
