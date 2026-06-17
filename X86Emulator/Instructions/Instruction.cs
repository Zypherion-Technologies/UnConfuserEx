using System.Collections.Generic;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace X86Emulator.Instructions
{
    internal abstract class Instruction
    {
        public abstract void Emulate(Stack<int> stack, Registers registers);

        protected static int ReadOperand(Operand operand, Registers registers)
        {
            return operand.Type == ud_type.UD_OP_REG
                ? registers.GetValue(operand.Base)
                : operand.LvalSDWord;
        }
    }
}
