using dnlib.DotNet.Emit;
using MSILEmulator;
using System;
using System.Collections.Generic;
using System.Linq;

namespace UnConfuserEx.Protections.Resources
{
    internal class DynamicDecryptor : IDecryptor
    {
        private IList<Instruction> DecryptInstructions;
        private ILMethod DecryptMethod;
        private int[] ArrayIndices;

        public DynamicDecryptor(IList<Instruction> decryptInstructions)
        {
            DecryptInstructions = decryptInstructions;

            SortedSet<int> arrays = new();
            for (int i = 0; i < DecryptInstructions.Count - 2; i++)
            {
                if (DecryptInstructions[i + 2].OpCode == OpCodes.Ldelem_U4
                    && DecryptInstructions[i].IsLdloc())
                {
                    arrays.Add(Utils.GetLoadLocalIndex(DecryptInstructions[i]));
                }
            }
            ArrayIndices = arrays.ToArray();
            if (ArrayIndices.Length != 2)
            {
                throw new Exception("Resources dynamic decryptor expects exactly two arrays");
            }

            DecryptMethod = new ILMethod(DecryptInstructions);
        }

        public byte[] Decrypt(uint[] key, uint[] data)
        {
            uint[] temp = new uint[key.Length];
            byte[] ret = new byte[data.Length << 2];
            int s = 0, d = 0;

            DecryptMethod.SetLocal(ArrayIndices[0], key);
            DecryptMethod.SetLocal(ArrayIndices[1], temp);

            while (s < data.Length)
            {
                for (int j = 0; j < 16; j++)
                {
                    temp[j] = data[s + j];
                }

                DecryptMethod.Emulate();

                for (int j = 0; j < 16; j++)
                {
                    uint t = temp[j];
                    ret[d++] = (byte)t;
                    ret[d++] = (byte)(t >> 8);
                    ret[d++] = (byte)(t >> 16);
                    ret[d++] = (byte)(t >> 24);
                    key[j] ^= t;
                }
                s += 16;
            }

            return ret;
        }
    }
}
