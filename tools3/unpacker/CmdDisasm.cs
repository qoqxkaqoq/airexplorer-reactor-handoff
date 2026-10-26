using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>disasm &lt;exe&gt; &lt;tok&gt; &lt;fromHex&gt; &lt;toHex&gt; — 打印产物方法指定 offset 窗口的指令（真实边界）。</summary>
public static class CmdDisasm
{
    public static int Run(string[] args)
    {
        if (args.Length < 5) { Console.WriteLine("usage: disasm <exe> <tok> <from> <to>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        if (mod.ResolveToken(Convert.ToUInt32(args[2], 16)) is not MethodDef m || !m.HasBody) { Console.WriteLine("no body"); return 1; }
        uint from = Convert.ToUInt32(args[3], 16), to = Convert.ToUInt32(args[4], 16);
        foreach (var ins in m.Body.Instructions)
        {
            if (ins.Offset < from) continue;
            if (ins.Offset > to) break;
            string op = ins.Operand switch
            {
                ITokenOperand t => t.MDToken.Raw.ToString("X8"),
                Instruction i2 => "IL_" + i2.Offset.ToString("X4"),
                Parameter p => "arg" + p.Index,
                Local l => "loc" + l.Index,
                null => "",
                _ => ins.Operand.ToString() ?? ""
            };
            // 解析 token 目标身份
            string extra = "";
            if (ins.Operand is ITokenOperand t2 && (ins.OpCode.Code == Code.Call || ins.OpCode.Code == Code.Callvirt || ins.OpCode.Code == Code.Newobj || ins.OpCode.Code == Code.Ldftn || ins.OpCode.Code == Code.Box || ins.OpCode.Code == Code.Castclass || ins.OpCode.Code == Code.Ldtoken || ins.OpCode.Code == Code.Isinst || ins.OpCode.Code == Code.Ldsfld || ins.OpCode.Code == Code.Ldsflda || ins.OpCode.Code == Code.Stsfld || ins.OpCode.Code == Code.Ldfld || ins.OpCode.Code == Code.Ldflda || ins.OpCode.Code == Code.Stfld))
            {
                try
                {
                    var r = mod.ResolveToken(t2.MDToken.Raw);
                    extra = r switch
                    {
                        MethodDef md => " -> " + md.DeclaringType?.Name + "::" + md.Name + " " + md.MethodSig,
                        MemberRef mr => " -> " + mr.Class?.Name + "::" + mr.Name + " " + (mr.MethodSig != null ? mr.MethodSig : (CallingConventionSig)mr.FieldSig),
                        TypeDef td => " -> type " + td.FullName,
                        TypeRef tr => " -> typeref " + tr.FullName,
                        TypeSpec ts => " -> typespec " + ts.FullName,
                        FieldDef fd => " -> field " + fd.DeclaringType?.Name + "::" + fd.Name,
                        _ => ""
                    };
                }
                catch (Exception ex) { extra = " -> RESOLVE-FAIL " + ex.Message; }
            }
            Console.WriteLine("IL_{0:X4}  {1} {2}{3}", ins.Offset, ins.OpCode, op, extra);
        }
        return 0;
    }
}
