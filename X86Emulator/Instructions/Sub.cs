using SharpDisasm;
using System.Collections.Generic;

namespace X86Emulator.Instructions
{
    internal class Sub : Instruction
    {
        private Operand[] Operands;

        public Sub(Operand[] operands)
        {
            Operands = operands;
        }

        public override void Emulate(Stack<int> stack, Registers registers)
        {
            int src = ReadOperand(Operands[1], registers);
            int dst = ReadOperand(Operands[0], registers);

            int result = dst - src;
            registers.SetValue(Operands[0].Base, result);
        }
    }
}
