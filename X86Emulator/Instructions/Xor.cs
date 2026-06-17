using SharpDisasm;
using System.Collections.Generic;

namespace X86Emulator.Instructions
{
    internal class Xor : Instruction
    {
        private Operand[] Operands;

        public Xor(Operand[] operands)
        {
            Operands = operands;
        }

        public override void Emulate(Stack<int> stack, Registers registers)
        {
            int dst = registers.GetValue(Operands[0].Base);
            int src = ReadOperand(Operands[1], registers);

            int result = src ^ dst;
            registers.SetValue(Operands[0].Base, result);
        }
    }
}
