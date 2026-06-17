using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using de4dot.blocks;
using MSILEmulator;

namespace UnConfuserEx.Protections.Constants
{
    internal abstract class IResolver
    {
        protected byte[]? data;

        public abstract void Resolve(MethodDef method, IList<MethodDef> instances);

        protected (int stringId, int numId, int objectId) GetIdsFromGetter(MethodDef getter)
        {
            var blocks = new Blocks(getter);
            blocks.RemoveDeadBlocks();

            int blocksFound = 0;
            foreach (var block in blocks.MethodBlocks.GetAllBlocks())
            {
                // Replace each decode block with a known ldc.i4 for each decode type
                foreach (var instr in block!.Instructions)
                {
                    if (instr.OpCode == OpCodes.Newarr)
                    {
                        block.Instructions.Clear();
                        block.Instructions.Add(new Instr(Instruction.CreateLdcI4(0xAA)));
                        block.Instructions.Add(new Instr(Instruction.Create(OpCodes.Ret)));
                        blocksFound++;
                        break;
                    }
                    else if (instr.OpCode == OpCodes.Ldtoken)
                    {
                        block.Instructions.Clear();
                        block.Instructions.Add(new Instr(Instruction.CreateLdcI4(0xBB)));
                        block.Instructions.Add(new Instr(Instruction.Create(OpCodes.Ret)));
                        blocksFound++;
                        break;
                    }
                    else if (instr.OpCode == OpCodes.Call && instr.Operand is IMethodDefOrRef callee && callee.Name.Contains("get_UTF8"))
                    {
                        block.Instructions.Clear();
                        block.Instructions.Add(new Instr(Instruction.CreateLdcI4(0xCC)));
                        block.Instructions.Add(new Instr(Instruction.Create(OpCodes.Ret)));
                        blocksFound++;
                        break;
                    }
                }

                // Replace every instruction that isn't a ldloc, ldc.i4, ret, or a branch with a nop
                for (int i = 0; i < block.Instructions.Count; i++)
                {
                    var instr = block.Instructions[i];
                    if (instr.IsLdloc() ||
                        instr.IsLdcI4() ||
                        instr.OpCode == OpCodes.Ldc_I8 ||
                        instr.OpCode == OpCodes.Conv_U8 ||
                        instr.OpCode == OpCodes.Ret ||
                        instr.IsConditionalBranch() || instr.IsBr())
                    {
                        continue;
                    }
                    block.Instructions[i] = new Instr(Instruction.Create(OpCodes.Nop));
                }
            }

            if (blocksFound != 3)
            {
                throw new Exception("Failed to get constant getter ids");
            }

            IList<Instruction> instructions;
            IList<ExceptionHandler> exceptionHandlers;
            blocks.GetCode(out instructions, out exceptionHandlers);

            // Delete instructions up until the first ldloc.0
            while (instructions.Count > 0 && !instructions[0].IsLdloc())
            {
                instructions.RemoveAt(0);
            }

            // Emulate the branching to find the correct IDs
            int? stringId = null, numId = null, objectId = null;
            for (int i = 0; i < 4; i++)
            {
                var ilMethod = new ILMethod(instructions);
                ilMethod.SetLocal(0, i);
                ilMethod.SetLocal(1, 0xDD);

                var ctx = ilMethod.Emulate();
                switch (ctx.Stack.Peek())
                {
                    case 0xAA:
                        numId = i;
                        break;
                    case 0xBB:
                        objectId = i;
                        break;
                    case 0xCC:
                        stringId = i;
                        break;
                    case 0xDD:
                        // Default constants
                        break;
                    default:
                        throw new Exception("asdasdasd");
                }
            }

            return ((int)stringId!, (int)numId!, (int)objectId!);
        }

        protected static int ComputeIntValueBefore(IList<Instruction> instrs, int endInclusive)
        {
            if (instrs[endInclusive].IsLdcI4())
                return instrs[endInclusive].GetLdcI4Value();

            int start = FindArithmeticStart(instrs, endInclusive);

            var sub = new List<Instruction>();
            for (int k = start; k <= endInclusive; k++)
                sub.Add(instrs[k]);

            var il = new ILMethod(sub);
            var ctx = il.Emulate();
            return (int)ctx.Stack.Pop();
        }

        protected static int CollapseToLdcI4(IList<Instruction> instrs, int endInclusive)
        {
            if (instrs[endInclusive].IsLdcI4())
                return endInclusive;

            int start = FindArithmeticStart(instrs, endInclusive);
            int value = ComputeIntValueBefore(instrs, endInclusive);

            var replacement = Instruction.CreateLdcI4(value);
            instrs[start] = replacement;
            for (int k = endInclusive; k > start; k--)
                instrs.RemoveAt(k);

            return start;
        }

        private static int FindArithmeticStart(IList<Instruction> instrs, int endInclusive)
        {
            int start = endInclusive;
            while (start > 0 && IsStackArithmeticOp(instrs[start - 1]))
                start--;
            return start;
        }

        private static bool IsStackArithmeticOp(Instruction instr)
        {
            if (instr.IsLdcI4()) return true;
            switch (instr.OpCode.Code)
            {
                case Code.Add:
                case Code.Sub:
                case Code.Mul:
                case Code.Xor:
                case Code.And:
                case Code.Or:
                case Code.Shl:
                case Code.Shr:
                case Code.Shr_Un:
                case Code.Neg:
                case Code.Not:
                case Code.Nop:
                    return true;
                default:
                    return false;
            }
        }

        protected int GetNextInstanceInMethod(MethodDef getter, MethodDef method, out TypeSig? genericType)
        {
            var instrs = method.Body.Instructions;

            for (int i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode == OpCodes.Call &&
                    instrs[i].Operand is MethodSpec ms &&
                    ms.Method.ResolveMethodDef() is MethodDef md &&
                    md.Equals(getter))
                {
                    genericType = ms.GenericInstMethodSig.GenericArguments[0];

                    if (instrs[i - 1].IsBr() &&
                        instrs[i - 1].Operand is Instruction target &&
                        target == instrs[i])
                    {
                        method.Body.Instructions.RemoveAt(i - 1);
                        i--;
                    }

                    return i - 1;
                }
            }
            genericType = null;
            return -1;
        }

        protected void FixStringConstant(MethodDef method, int instrOffset, int id)
        {
            uint count = (uint)(data![id] | (data[id + 1] << 8) | (data[id + 2] << 16) | (data[id + 3] << 24));
            if (count > data.Length)
            {
                count = (count << 4) | (count >> 0x1C);
            }
            string result = string.Intern(Encoding.UTF8.GetString(data, id + 4, (int)count));

            method.Body.Instructions[instrOffset].OpCode = OpCodes.Ldstr;
            method.Body.Instructions[instrOffset].Operand = result;
            method.Body.Instructions.RemoveAt(instrOffset + 1);
        }

        protected void FixNumberConstant(MethodDef method, int instrOffset, int id, TypeSig type)
        {
            switch (type.ElementType)
            {
                case ElementType.I4:
                    FixNumberConstant<int>(method, instrOffset, id);
                    method.Body.Instructions[instrOffset].OpCode = OpCodes.Ldc_I4;
                    break;
                case ElementType.R8:
                    FixNumberConstant<double>(method, instrOffset, id);
                    method.Body.Instructions[instrOffset].OpCode = OpCodes.Ldc_R8;
                    break;
                case ElementType.R4:
                    FixNumberConstant<Single>(method, instrOffset, id);
                    method.Body.Instructions[instrOffset].OpCode = OpCodes.Ldc_R4;
                    break;

                default:
                    throw new NotImplementedException($"Can't fix number constant. Type is {type.TypeName}");
            }
        }

        protected void FixNumberConstant<T>(MethodDef method, int instrOffset, int id)
        {
            T[] array = new T[1];
            Buffer.BlockCopy(data!, id, array, 0, Marshal.SizeOf(default(T)));

            method.Body.Instructions[instrOffset].Operand = array[0];
            method.Body.Instructions.RemoveAt(instrOffset + 1);
        }

        protected void FixObjectConstant(MethodDef method, int instrOffset, int id, TypeSig type)
        {
            int num0 = data![id] | (data[id + 1] << 8) | (data[id + 2] << 16) | (data[id + 3] << 24);
            uint num1 = (uint)(data![id + 4] | (data[id + 5] << 8) | (data[id + 6] << 16) | (data[id + 7] << 24));
            num1 = (num1 << 4) | (num1 >> 0x1C);

            throw new NotImplementedException("Object constant not handled");
        }

        protected void FixDefaultConstant(MethodDef method, int instrOffset, TypeSig type)
        {
            method.Body.Instructions[instrOffset].OpCode = OpCodes.Initobj;
            method.Body.Instructions[instrOffset].Operand = type.ToTypeDefOrRef();
            method.Body.Instructions.RemoveAt(instrOffset + 1);
        }
    }
}
