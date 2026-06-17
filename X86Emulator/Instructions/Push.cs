using SharpDisasm;
using System.Collections.Generic;

namespace X86Emulator.Instructions
{
    internal class Push : Instruction
    {
        private Operand Operand;

        public Push(Operand operand)
        {
            Operand = operand;
        }

        public override void Emulate(Stack<int> stack, Registers registers)
        {
            stack.Push(ReadOperand(Operand, registers));
        }
    }
}
