using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Collections.Generic;

namespace MSILEmulator
{
    public class Context
    {
        public Dictionary<int, object> Args = new();
        public Dictionary<IField, object> Fields = new();
        public Dictionary<int, object> Locals = new();
        public Dictionary<uint, int> Offsets = new();
        public Stack<object> Stack = new();

        public Context(IList<Instruction> instructions)
        {
            for (int i = 0; i < instructions.Count; i++)
            {
                Offsets[instructions[i].Offset] = i;
            }
        }
    }
}
