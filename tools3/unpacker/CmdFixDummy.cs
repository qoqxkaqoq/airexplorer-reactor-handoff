using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace AirExplorerUnpacker;

/// <summary>fixdummy &lt;exe&gt; &lt;out&gt; &lt;variant&gt; — 减法实验: 逐项修改 dummy 类型找拒载原因。
/// variants: 1=清类型Abstract 2=全部方法补stub体+清abstract 3=删129字段 4=改名 5=全做</summary>
public static class CmdFixDummy
{
    public static int Run(string[] args)
    {
        if (args.Length < 4) { Console.WriteLine("usage: fixdummy <exe> <out> <variant 1-5>"); return 2; }
        var mod = (ModuleDefMD)ModuleDefMD.Load(args[1]);
        int variant = int.Parse(args[3]);

        foreach (var t in mod.GetTypes())
        {
            if (!t.FullName.Contains("dummy_ptr")) continue;
            Console.WriteLine("[fixdummy] target: {0} variant={1}", t.FullName, variant);

            if (variant == 1 || variant == 5)
            {
                t.Attributes &= ~TypeAttributes.Abstract;
                t.Attributes &= ~TypeAttributes.Sealed;
            }
            if (variant == 2 || variant == 5)
            {
                foreach (var m in t.Methods)
                {
                    bool mAbs = (m.Attributes & MethodAttributes.Abstract) != 0;
                    if (!m.HasBody || mAbs)
                    {
                        m.Attributes &= ~MethodAttributes.Abstract;
                        if (!m.HasBody)
                        {
                            // 按签名返回类型补体
                            var ret = m.MethodSig?.RetType;
                            var body = new CilBody();
                            if (ret != null && ret.FullName == "System.Boolean") { body.Instructions.Add(Instruction.CreateLdcI4(0)); }
                            else if (ret != null && ret.FullName != "System.Void")
                            {
                                body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
                                body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                                m.Body = body;
                                m.Body.MaxStack = 1;
                                continue;
                            }
                            body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                            m.Body = body;
                            m.Body.MaxStack = 8;
                        }
                    }
                }
            }
            if (variant == 3)
            {
                for (int i = t.Fields.Count - 1; i >= 0; i--) t.Fields.RemoveAt(i);
            }
            if (variant == 4)
            {
                t.Name = "dummyXX_" + Guid.NewGuid().ToString("N")[..8];
            }
        }
        mod.Write(args[2]);
        Console.WriteLine("[fixdummy] written: " + args[2]);
        return 0;
    }
}
