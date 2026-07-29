using dnlib.DotNet;
using dnlib.DotNet.Emit;
using log4net;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace UnConfuserEx
{
    internal class Utils
    {
        private static ILog Logger = LogManager.GetLogger("Utils");

        private const int MaxLzmaDictionarySize = 0x10000000;
        private const int MaxLzmaUncompressedSize = 0x10000000;

        public static byte[] DecompressLZMA(byte[] data, MethodDef initMethod)
        {
            int sizeBytes = GetUncompressedSizeBytes(initMethod);

            MemoryStream inStream = new MemoryStream(data);
            MemoryStream outStream = new MemoryStream();
            var decoder = new SevenZip.Compression.LZMA.Decoder();

            var props = new byte[5];
            if (inStream.Read(props, 0, 5) != 5)
            {
                throw new Exception("Failed to read LZMA properties");
            }
            Logger.Debug($"LZMA properties => {props[0]:X} {props[1]:X} {props[2]:X} {props[3]:X} {props[4]:X}");

            if (!AreLzmaPropertiesValid(props))
            {
                throw new Exception($"Invalid LZMA properties byte 0x{props[0]:X} or unreasonable dictionary size");
            }

            decoder.SetDecoderProperties(props);

            var size = new byte[8];
            if (inStream.Read(size, 0, sizeBytes) != sizeBytes)
            {
                throw new Exception("Failed to read uncompressed size");
            }
            long uncompressedSize = BitConverter.ToInt64(size);
            long compressedSize = inStream.Length - inStream.Position;

            Logger.Debug($"Compressed bytes: 0x{compressedSize:X} -> Uncompressed bytes: 0x{uncompressedSize:X}");

            if (uncompressedSize < 0 || uncompressedSize > MaxLzmaUncompressedSize)
            {
                throw new Exception($"Unreasonable uncompressed size 0x{uncompressedSize:X} — payload is likely not raw LZMA");
            }

            decoder.Code(inStream, outStream, compressedSize, uncompressedSize, null);
            return outStream.ToArray();
        }

        private static bool AreLzmaPropertiesValid(byte[] props)
        {
            if (props[0] >= (9 * 5 * 5)) return false;
            uint dict = (uint)(props[1] | (props[2] << 8) | (props[3] << 16) | (props[4] << 24));
            if (dict == 0) return true;
            return dict <= MaxLzmaDictionarySize;
        }

        private static int GetUncompressedSizeBytes(MethodDef initMethod)
        {
            // Iterate through all instructions to find the call to the decompress method
            foreach (var instr in initMethod.Body.Instructions)
            {
                if (instr.OpCode != OpCodes.Call || instr.Operand is not MethodDef callee)
                {
                    continue;
                }

                if (callee.Signature.ToString() != "System.Byte[] (System.Byte[])")
                {
                    continue;
                }

                // Attempt to find the number of bytes representing the uncompressed size
                var instrs = callee.Body.Instructions;
                for (int i = 0; i < instrs.Count - 1; i++)
                {
                    if (instrs[i].IsLdcI4() && instrs[i+1].OpCode == OpCodes.Blt_S && instrs[i].GetLdcI4Value() != 5)
                    {
                        Logger.Debug($"Using {instrs[i].GetLdcI4Value()} bytes for the uncompressed size");
                        return instrs[i].GetLdcI4Value();
                    }
                }

            }
            Logger.Warn("Failed to find number of bytes used by the uncompressed size. Defaulting to 4");
            return 4;
        }

        private static char[] InvalidChars = "!@#$%^&*()-=+\\,<>".ToArray();

        public static bool IsInvalidName(string name)
        {
            return Encoding.UTF8.GetByteCount(name) != name.Length
                    || (name.Any(c => InvalidChars.Contains(c)));
        }

        /// <summary>
        /// True for the short all-letter identifiers a renamer emits when it is
        /// configured for ASCII/letters output — "a", "A", "aB" and so on.
        /// These are perfectly legal identifiers, so <see cref="IsInvalidName"/>
        /// (correctly) ignores them; this is the opt-in test used when the user
        /// would rather have unique generated names than case-only collisions.
        /// </summary>
        public static bool IsMeaninglessName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length > 2)
                return false;

            foreach (var c in name)
            {
                if (!char.IsAsciiLetter(c))
                    return false;
            }

            return true;
        }

        public static int GetStoreLocalIndex(Instruction instr)
        {
            if (instr.OpCode == OpCodes.Stloc_S || instr.OpCode == OpCodes.Stloc)
            {
                return ((Local)instr.Operand).Index;
            }
            else
            {
                return instr.OpCode.Code - Code.Stloc_0;
            }
        }

        public static int GetLoadLocalIndex(Instruction instr)
        {
            if (instr.OpCode == OpCodes.Ldloc_S || instr.OpCode == OpCodes.Ldloc)
            {
                return ((Local)instr.Operand).Index;
            }
            else
            {
                return instr.OpCode.Code - Code.Ldloc_0;
            }
        }
    }
}
