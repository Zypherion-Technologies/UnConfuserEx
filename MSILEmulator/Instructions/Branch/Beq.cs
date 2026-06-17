using dnlib.DotNet.Emit;

namespace MSILEmulator.Instructions.Branch
{
    internal class Beq
    {
        public static int Emulate(Context ctx, Instruction instr)
        {
            return BranchCompare.Emulate(ctx, instr, static (left, right) => left == right, static (left, right) => left == right);
        }
    }
}
