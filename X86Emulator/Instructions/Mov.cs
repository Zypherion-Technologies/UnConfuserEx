using SharpDisasm;
using System.Collections.Generic;

namespace X86Emulator.Instructions
{
    internal class Mov : Instruction
    {
        private Operand[] Operands;

        public Mov(Operand[] operands)
        {
            Operands = operands;
        }

        public override void Emulate(Stack<int> stack, Registers registers)
        {
            Operand to = Operands[0];
            int val = ReadOperand(Operands[1], registers);

            registers.SetValue(to.Base, val);
        }
    }
}
