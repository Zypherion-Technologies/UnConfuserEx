using SharpDisasm;
using System.Collections.Generic;

namespace X86Emulator.Instructions
{
    internal class IMul : Instruction
    {
        private Operand[] Operands;

        public IMul(Operand[] operands)
        {
            Operands = operands;
        }

        public override void Emulate(Stack<int> stack, Registers registers)
        {
            if (Operands.Length == 1)
            {
                long eax = registers.GetValue(Registers.Register.EAX);
                long val = ReadOperand(Operands[0], registers);

                long result = eax * val;

                registers.SetValue(SharpDisasm.Udis86.ud_type.UD_R_EDX, (int)(result >> 32));
                registers.SetValue(SharpDisasm.Udis86.ud_type.UD_R_EAX, (int)result);
            }
            else if (Operands.Length == 2)
            {
                int dst = registers.GetValue(Operands[0].Base);
                int src = ReadOperand(Operands[1], registers);

                int result = dst * src;
                registers.SetValue(Operands[0].Base, result);
            }
            else
            {
                int val0 = ReadOperand(Operands[1], registers);
                int val1 = ReadOperand(Operands[2], registers);

                int result = val0 * val1;
                registers.SetValue(Operands[0].Base, result);
            }
        }
    }
}
