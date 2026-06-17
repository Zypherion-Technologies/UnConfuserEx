using dnlib.DotNet.Emit;
using System;

namespace MSILEmulator.Instructions.Branch
{
    internal static class BranchCompare
    {
        public static int Emulate(Context ctx, Instruction instr, Func<int, int, bool> compareInt, Func<long, long, bool> compareLong)
        {
            object val2 = ctx.Stack.Pop();
            object val1 = ctx.Stack.Pop();

            if (val1.GetType() != val2.GetType())
            {
                throw new EmulatorException($"Attempted to compare different types {val1.GetType()} != {val2.GetType()}");
            }

            bool branch = val1 switch
            {
                int leftInt => compareInt(leftInt, (int)val2),
                long leftLong => compareLong(leftLong, (long)val2),
                _ => throw new NotImplementedException($"Comparison of {val1.GetType().Name} not handled")
            };

            return branch
                ? ctx.Offsets[((Instruction)instr.Operand).Offset]
                : ctx.Offsets[instr.Offset] + 1;
        }
    }
}
