using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>bodyhex &lt;exe&gt; &lt;tok&gt; — 输出方法体的 IL 字节流 hex（含 EH 概要），用于与注入源 diff。</summary>
public static class CmdBodyHex
{
    public static int Run(string[] args)
    {
        if (args.Length < 3) { Console.WriteLine("usage: bodyhex <exe> <tok>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        var r = mod.ResolveToken(Convert.ToUInt32(args[2], 16));
        if (r is not MethodDef m || !m.HasBody) { Console.WriteLine("no body"); return 1; }
        // 重新线性化为字节流（dnlib 写出语义近似）
        var ms = new MemoryStream();
        foreach (var ins in m.Body.Instructions)
        {
            ms.WriteByte(ins.OpCode.Size > 1 ? (byte)(ins.OpCode.Value >> 8) : (byte)ins.OpCode.Value);
            if (ins.OpCode.Size > 1) ms.WriteByte((byte)ins.OpCode.Value);
            switch (ins.OpCode.OperandType)
            {
                case OperandType.InlineNone: break;
                case OperandType.ShortInlineI: ms.WriteByte((byte)(sbyte)ins.Operand); break;
                case OperandType.InlineI: ms.Write(BitConverter.GetBytes((int)ins.Operand)); break;
                case OperandType.InlineI8: ms.Write(BitConverter.GetBytes((long)ins.Operand)); break;
                case OperandType.ShortInlineR: ms.Write(BitConverter.GetBytes((float)ins.Operand)); break;
                case OperandType.InlineR: ms.Write(BitConverter.GetBytes((double)ins.Operand)); break;
                case OperandType.ShortInlineVar:
                case OperandType.ShortInlineBrTarget: ms.WriteByte((byte)(ins.Operand is Parameter p ? p.Index : ((Local)ins.Operand).Index)); break;
                case OperandType.InlineVar:
                    ms.Write(BitConverter.GetBytes((ushort)(ins.Operand is Parameter p2 ? p2.Index : ((Local)ins.Operand).Index))); break;
                case OperandType.InlineBrTarget:
                case OperandType.InlineSwitch: break; // 跳过（offset 由 dnlib 重算）
                case OperandType.InlineString: ms.Write(BitConverter.GetBytes((uint)0)); break; // token 会变, 占位
                case OperandType.InlineMethod:
                case OperandType.InlineField:
                case OperandType.InlineType:
                case OperandType.InlineTok:
                case OperandType.InlineSig:
                    ms.Write(BitConverter.GetBytes((ins.Operand as ITokenOperand)?.MDToken.Raw ?? 0)); break;
            }
        }
        var bytes = ms.ToArray();
        Console.WriteLine("instrs={0} maxstack={1} locals={2} eh={3}", m.Body.Instructions.Count, m.Body.MaxStack, m.Body.Variables.Count, m.Body.ExceptionHandlers.Count);
        for (int i = 0; i < bytes.Length; i += 64)
            Console.WriteLine("{0:X5} {1}", i, Convert.ToHexString(bytes, i, Math.Min(64, bytes.Length - i)));
        foreach (var eh in m.Body.ExceptionHandlers)
            Console.WriteLine("EH {0} try[{1:X4}..{2:X4}) h[{3:X4}..{4:X4}) cls={5}",
                eh.HandlerType, eh.TryStart?.Offset ?? 0xFFFFFFFF, eh.TryEnd?.Offset ?? 0xFFFFFFFF,
                eh.HandlerStart?.Offset ?? 0xFFFFFFFF, eh.HandlerEnd?.Offset ?? 0xFFFFFFFF,
                eh.CatchType?.MDToken.Raw.ToString("X8") ?? "-");
        return 0;
    }
}
