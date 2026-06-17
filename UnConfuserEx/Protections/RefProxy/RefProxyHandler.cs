using dnlib.DotNet;
using dnlib.DotNet.Emit;
using MSILEmulator;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using X86Emulator;

namespace UnConfuserEx.Protections.Delegates
{
    internal class RefProxyHandler
    {
        private MethodDef Handler;
        private X86Method? X86Method;
        private IList<Instruction>? PrefixInstructions;
        private IList<Instruction>? SuffixInstructions;
        private int[] NameChars = new int[5];
        private int[] Shifts = new int[4];

        public RefProxyHandler(ModuleDefMD module, MethodDef handler)
        {
            Handler = handler;

            var instrs = handler.Body.Instructions;
            var nameCharsFound = 0;
            var shiftsFound = 0;
            for (int i = 0; i < instrs.Count - 2; i++)
            {
                if (nameCharsFound == 5)
                {
                    break;
                }

                if (instrs[i].OpCode == OpCodes.Callvirt &&
                    instrs[i].Operand is IMethodDefOrRef md &&
                    md.Name.Contains("get_Name") &&
                    instrs[i + 1].IsLdcI4())
                {
                    NameChars[nameCharsFound++] = instrs[i + 1].GetLdcI4Value();
                }
                else if (shiftsFound < 4 &&
                    instrs[i].IsLdcI4() &&
                    instrs[i].GetLdcI4Value() == 0x1f &&
                    i > 0 && instrs[i - 1].IsLdcI4())
                {
                    Shifts[shiftsFound++] = instrs[i - 1].GetLdcI4Value();
                }
                else if (shiftsFound < 4 &&
                    instrs[i].OpCode == OpCodes.Xor &&
                    i + 3 < instrs.Count &&
                    instrs[i + 1].IsLdcI4() &&
                    instrs[i + 2].OpCode == OpCodes.Shl &&
                    instrs[i + 3].OpCode == OpCodes.Add)
                {
                    Shifts[shiftsFound++] = instrs[i + 1].GetLdcI4Value();
                }
            }

            if (!TryResolvePredicate(module, instrs))
            {
                throw new Exception("RefProxy handler predicate could not be located");
            }
        }

        private bool TryResolvePredicate(ModuleDefMD module, IList<Instruction> instrs)
        {
            int tokenStloc = FindTokenStloc(instrs);
            if (tokenStloc < 0) return false;

            int argStart = FindArgStart(instrs);
            if (argStart < 0) return false;

            int argEnd = FindArgEnd(instrs, argStart);
            if (argEnd < 0 || argEnd >= tokenStloc) return false;

            int prefixStart = argStart;
            while (prefixStart > 0 && IsArithmeticOp(instrs[prefixStart - 1]))
                prefixStart--;

            var prefix = new List<Instruction>();
            for (int i = prefixStart; i < argStart; i++)
                prefix.Add(instrs[i]);

            var suffix = new List<Instruction>();
            for (int i = argEnd + 1; i < tokenStloc; i++)
                suffix.Add(instrs[i]);

            foreach (var instr in suffix)
            {
                if (instr.OpCode == OpCodes.Call &&
                    instr.Operand is MethodDef nativeCandidate &&
                    nativeCandidate.IsNative)
                {
                    X86Method = new X86Method(module, nativeCandidate);
                    return true;
                }
            }

            foreach (var instr in prefix.Concat(suffix))
            {
                if (!IsArithmeticOp(instr)) return false;
            }

            PrefixInstructions = prefix;
            SuffixInstructions = suffix;
            return true;
        }

        private static int FindTokenStloc(IList<Instruction> instrs)
        {
            for (int i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode == OpCodes.Callvirt &&
                    instrs[i].Operand is IMethodDefOrRef m &&
                    m.Name.String.Contains("GetCustomAttributes"))
                {
                    for (int j = i - 1; j >= 0; j--)
                    {
                        if (instrs[j].IsStloc())
                            return j;
                    }
                    return -1;
                }
            }
            return -1;
        }

        private static int FindArgStart(IList<Instruction> instrs)
        {
            for (int i = 1; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode == OpCodes.Callvirt &&
                    instrs[i].Operand is IMethodDefOrRef m &&
                    m.Name.String.Contains("GetOptionalCustomModifiers"))
                {
                    return i - 1;
                }
            }
            return -1;
        }

        private static int FindArgEnd(IList<Instruction> instrs, int argStart)
        {
            int shiftCount = 0;
            int lastAdd = -1;
            for (int i = argStart + 1; i < instrs.Count - 3; i++)
            {
                if (instrs[i].IsLdcI4() && instrs[i].GetLdcI4Value() == 0x1f
                    && instrs[i + 1].OpCode == OpCodes.And
                    && instrs[i + 2].OpCode == OpCodes.Shl
                    && instrs[i + 3].OpCode == OpCodes.Add)
                {
                    shiftCount++;
                    lastAdd = i + 3;
                    if (shiftCount == 4) return lastAdd;
                }
                else if (instrs[i].OpCode == OpCodes.Xor
                    && i + 3 < instrs.Count
                    && instrs[i + 1].IsLdcI4()
                    && instrs[i + 2].OpCode == OpCodes.Shl
                    && instrs[i + 3].OpCode == OpCodes.Add)
                {
                    shiftCount++;
                    lastAdd = i + 3;
                    if (shiftCount == 4) return lastAdd;
                }
            }
            return lastAdd;
        }

        private static bool IsArithmeticOp(Instruction instr)
        {
            if (instr.IsLdcI4()) return true;
            switch (instr.OpCode.Code)
            {
                case Code.Add:
                case Code.Sub:
                case Code.Mul:
                case Code.Div:
                case Code.Div_Un:
                case Code.Rem:
                case Code.Rem_Un:
                case Code.Xor:
                case Code.And:
                case Code.Or:
                case Code.Shl:
                case Code.Shr:
                case Code.Shr_Un:
                case Code.Not:
                case Code.Neg:
                case Code.Nop:
                case Code.Conv_I4:
                case Code.Conv_U4:
                    return true;
                default:
                    return false;
            }
        }

        public MDToken GetMethodMDToken(FieldDef field)
        {
            var fieldSig = field.FieldSig.ExtraData;

            int key;
            if (field.FieldType is CModOptSig optSig)
            {
                key = (int)optSig.Modifier.MDToken.Raw;
            }
            else
            {
                throw new Exception("First field type wasn't an optional modifier - need to iterate");
            }

            key += ((field.Name.String[NameChars[0]] ^ (char)fieldSig[^1]) << Shifts[0]) +
                ((field.Name.String[NameChars[1]] ^ (char)fieldSig[^2]) << Shifts[1]) +
                ((field.Name.String[NameChars[2]] ^ (char)fieldSig[^3]) << Shifts[2]) +
                ((field.Name.String[NameChars[3]] ^ (char)fieldSig[^5]) << Shifts[3]);

            if (X86Method != null)
            {
                key = X86Method.Emulate(new int[] { key });
            }
            else if (SuffixInstructions != null)
            {
                var synthetic = new List<Instruction>();
                if (PrefixInstructions != null) synthetic.AddRange(PrefixInstructions);
                synthetic.Add(Instruction.CreateLdcI4(key));
                synthetic.AddRange(SuffixInstructions);
                var il = new ILMethod(synthetic);
                key = (int)il.Emulate().Stack.Pop();
            }
            else
            {
                throw new NotImplementedException("RefProxy predicate type not recognised");
            }

            key *= GetFieldHash(field);

            return new MDToken(key);
        }

        public OpCode GetOpCode(FieldDef field, byte opKey)
        {
            var opCode = (Code)(field.Name.String[NameChars[4]] ^ opKey);
            return opCode.ToOpCode();
        }

        private int GetFieldHash(FieldDef field)
        {
            if (field.CustomAttributes.Count == 0)
            {
                throw new Exception($"RefProxy field {field.Name} has no custom attribute to derive its hash from");
            }
            var customAttribute = field.CustomAttributes[0];

            if (customAttribute.Constructor is not MethodDef ctor)
            {
                throw new Exception($"RefProxy field {field.Name} attribute ctor is not a MethodDef");
            }
            if (customAttribute.ConstructorArguments.Count == 0)
            {
                throw new Exception($"RefProxy field {field.Name} attribute had no constructor args");
            }
            var arg = (int)customAttribute.ConstructorArguments[0].Value;

            int stfldIndex = -1;
            for (int i = 0; i < ctor.Body.Instructions.Count; i++)
            {
                if (ctor.Body.Instructions[i].OpCode == OpCodes.Stfld)
                {
                    stfldIndex = i;
                    break;
                }
            }
            if (stfldIndex < 0)
            {
                throw new Exception($"RefProxy field hash constructor for {field.Name} had no stfld");
            }

            var ilMethod = new ILMethod(ctor, 3, stfldIndex);

            ilMethod.SetArg(1, arg);

            Context ctx = ilMethod.Emulate();

            if (ctx.Stack.Count > 0)
            {
                return (int)ctx.Stack.Pop();
            }

            foreach (var value in ctx.Fields.Values)
            {
                if (value is int intValue)
                {
                    return intValue;
                }
            }

            throw new Exception($"RefProxy field hash constructor for {field.Name} produced no stack or field result");
        }
    }
}
