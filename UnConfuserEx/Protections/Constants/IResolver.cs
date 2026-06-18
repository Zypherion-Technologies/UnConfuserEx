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

            instrs[start].OpCode = OpCodes.Ldc_I4;
            instrs[start].Operand = value;
            for (int k = start + 1; k <= endInclusive; k++)
            {
                instrs[k].OpCode = OpCodes.Nop;
                instrs[k].Operand = null;
            }

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


        protected static bool IsStringType(TypeSig type)
        {
            return type.ElementType == ElementType.String || type.FullName == "System.String";
        }

        protected static bool IsSupportedNumberType(TypeSig type)
        {
            switch (type.ElementType)
            {
                case ElementType.I4:
                case ElementType.R8:
                case ElementType.R4:
                    return true;
                default:
                    return false;
            }
        }

        protected static void SimplifyStatefulHelperCalls(MethodDef method)
        {
            if (!method.HasBody || method.Body.Instructions.Count == 0)
                return;

            var states = new Dictionary<Local, HelperLocalState>();
            var instrs = method.Body.Instructions;
            int index = 0;
            while (index < instrs.Count)
            {
                if (TryInitializeHelperLocal(method, instrs, states, index, out var initEnd))
                {
                    index = initEnd + 1;
                    continue;
                }

                if (TryFoldHelperCall(method, instrs, states, index, out var replacementEnd))
                {
                    index = Math.Max(0, index - 1);
                    continue;
                }

                index++;
            }
        }

        private static bool TryInitializeHelperLocal(MethodDef method, IList<Instruction> instrs, Dictionary<Local, HelperLocalState> states, int index, out int endIndex)
        {
            endIndex = index;
            if (index + 2 >= instrs.Count)
                return false;
            if (!TryGetLdlocaLocal(instrs[index], out var local))
                return false;
            if (!instrs[index + 1].IsLdcI4())
                return false;
            if (instrs[index + 2].OpCode != OpCodes.Call)
                return false;
            if (instrs[index + 2].Operand is not IMethod ctorRef)
                return false;
            var ctor = ctorRef.ResolveMethodDef();
            if (ctor == null || !ctor.HasBody || !ctor.IsInstanceConstructor)
                return false;
            if (!TypeEqualityComparer.Instance.Equals(local.Type.ToTypeDefOrRef(), ctor.DeclaringType))
                return false;

            var seed = instrs[index + 1].GetLdcI4Value();
            if (!TryExecuteHelperCtor(ctor, (uint)seed, out var state))
                return false;

            states[local] = state;
            endIndex = index + 2;
            return true;
        }

        private static bool TryFoldHelperCall(MethodDef method, IList<Instruction> instrs, Dictionary<Local, HelperLocalState> states, int index, out int endIndex)
        {
            endIndex = index;
            if (index + 3 >= instrs.Count)
                return false;
            if (!TryGetLdlocaLocal(instrs[index], out var local))
                return false;
            if (!states.TryGetValue(local, out var state))
                return false;
            if (!instrs[index + 1].IsLdcI4() || !instrs[index + 2].IsLdcI4())
                return false;
            if (instrs[index + 3].OpCode != OpCodes.Call)
                return false;
            if (instrs[index + 3].Operand is not IMethod helperRef)
                return false;
            var helper = helperRef.ResolveMethodDef();
            if (helper == null || !helper.HasBody || helper.MethodSig.Params.Count != 2 || helper.ReturnType.ElementType != ElementType.U4)
                return false;
            if (!helper.MethodSig.HasThis)
                return false;
            if (!TypeEqualityComparer.Instance.Equals(local.Type.ToTypeDefOrRef(), helper.DeclaringType))
                return false;

            var arg1 = (byte)instrs[index + 1].GetLdcI4Value();
            var arg2 = (uint)instrs[index + 2].GetLdcI4Value();
            if (!TryExecuteHelperMethod(helper, state, arg1, arg2, out var result))
                return false;

            instrs[index].OpCode = OpCodes.Ldc_I4;
            instrs[index].Operand = unchecked((int)result);
            for (int replacementIndex = index + 1; replacementIndex <= index + 3; replacementIndex++)
            {
                instrs[replacementIndex].OpCode = OpCodes.Nop;
                instrs[replacementIndex].Operand = null;
            }
            endIndex = index;
            return true;
        }

        private static bool TryGetLdlocaLocal(Instruction instruction, out Local local)
        {
            local = null!;
            if (instruction.Operand is not Local candidate)
                return false;
            switch (instruction.OpCode.Code)
            {
                case Code.Ldloca:
                case Code.Ldloca_S:
                    local = candidate;
                    return true;
                default:
                    return false;
            }
        }

        private static bool TryExecuteHelperCtor(MethodDef ctor, uint seed, out HelperLocalState state)
        {
            state = new HelperLocalState(4);
            if (!ctor.HasBody)
                return false;

            var stack = new Stack<uint>();
            foreach (var instruction in ctor.Body.Instructions)
            {
                switch (instruction.OpCode.Code)
                {
                    case Code.Ldarg_0:
                        stack.Push(uint.MaxValue);
                        break;
                    case Code.Ldarg_1:
                        stack.Push(seed);
                        break;
                    case Code.Ldc_I4:
                    case Code.Ldc_I4_S:
                    case Code.Ldc_I4_0:
                    case Code.Ldc_I4_1:
                    case Code.Ldc_I4_2:
                    case Code.Ldc_I4_3:
                    case Code.Ldc_I4_4:
                    case Code.Ldc_I4_5:
                    case Code.Ldc_I4_6:
                    case Code.Ldc_I4_7:
                    case Code.Ldc_I4_8:
                    case Code.Ldc_I4_M1:
                        stack.Push(unchecked((uint)instruction.GetLdcI4Value()));
                        break;
                    case Code.Mul:
                    {
                        var right = stack.Pop();
                        var left = stack.Pop();
                        stack.Push(unchecked(left * right));
                        break;
                    }
                    case Code.Dup:
                        stack.Push(stack.Peek());
                        break;
                    case Code.Starg:
                    case Code.Starg_S:
                        seed = stack.Peek();
                        break;
                    case Code.Stfld:
                    {
                        var value = stack.Pop();
                        stack.Pop();
                        if (instruction.Operand is not FieldDef field)
                            return false;
                        int fieldIndex = ctor.DeclaringType.Fields.IndexOf(field);
                        if (fieldIndex < 0 || fieldIndex >= state.Fields.Length)
                            return false;
                        state.Fields[fieldIndex] = value;
                        break;
                    }
                    case Code.Ret:
                        return true;
                    default:
                        return false;
                }
            }

            return false;
        }

        private static bool TryExecuteHelperMethod(MethodDef helper, HelperLocalState state, byte arg1, uint arg2, out uint result)
        {
            result = 0;
            if (!helper.HasBody)
                return false;

            int lowBits = arg1 & 3;
            if ((arg1 & 0x80) != 0)
            {
                if (lowBits < 0 || lowBits >= state.Fields.Length)
                    return false;
                state.Fields[lowBits] = arg2;
            }
            else
            {
                if (lowBits < 0 || lowBits >= state.Fields.Length)
                    return false;
                state.Fields[lowBits] = lowBits switch
                {
                    0 => state.Fields[lowBits] ^ arg2,
                    1 => unchecked(state.Fields[lowBits] + arg2),
                    2 => state.Fields[lowBits] ^ arg2,
                    3 => unchecked(state.Fields[lowBits] - arg2),
                    _ => state.Fields[lowBits]
                };
            }

            int returnIndex = (arg1 >> 2) & 3;
            if (returnIndex < 0 || returnIndex >= state.Fields.Length)
                return false;
            result = state.Fields[returnIndex];
            return true;
        }

        private sealed class HelperLocalState
        {
            public HelperLocalState(int size)
            {
                Fields = new uint[size];
            }

            public uint[] Fields { get; }
        }

        protected int GetNextInstanceInMethod(MethodDef getter, MethodDef method, out TypeSig? genericType)
        {
            return GetNextInstanceInMethod(getter, method, 0, out genericType);
        }

        protected int GetNextInstanceInMethod(MethodDef getter, MethodDef method, int startIndex, out TypeSig? genericType)
        {
            var instrs = method.Body.Instructions;

            for (int i = Math.Max(0, startIndex); i < instrs.Count; i++)
            {
                if (instrs[i].OpCode == OpCodes.Call &&
                    instrs[i].Operand is MethodSpec ms &&
                    ms.Method.ResolveMethodDef() is MethodDef md &&
                    md.Equals(getter))
                {
                    genericType = ms.GenericInstMethodSig.GenericArguments[0];

                    if (i > 0 && instrs[i - 1].IsBr() &&
                        instrs[i - 1].Operand is Instruction target &&
                        target == instrs[i])
                    {
                        instrs[i - 1].OpCode = OpCodes.Nop;
                        instrs[i - 1].Operand = null;
                    }

                    return i - 1;
                }
            }
            genericType = null;
            return -1;
        }

        protected bool TryValidateDataRange(int id, int size, out int normalizedId)
        {
            normalizedId = id;
            if (data == null)
                return false;
            if (id < 0)
                return false;
            if (size < 0)
                return false;
            if (id > data.Length - size)
                return false;
            return true;
        }

        protected static bool CanReplaceConstant(MethodDef method, int instrOffset)
        {
            return instrOffset >= 0 && instrOffset + 1 < method.Body.Instructions.Count;
        }

        protected void FixStringConstant(MethodDef method, int instrOffset, int id)
        {
            if (!CanReplaceConstant(method, instrOffset) || !TryValidateDataRange(id, 4, out _))
                throw new IndexOutOfRangeException("String constant header is outside the decrypted blob");

            uint count = (uint)(data![id] | (data[id + 1] << 8) | (data[id + 2] << 16) | (data[id + 3] << 24));
            if (count > data.Length)
            {
                count = (count << 4) | (count >> 0x1C);
            }
            if (count > data.Length || id > data.Length - 4 - count)
                throw new IndexOutOfRangeException("String constant payload is outside the decrypted blob");

            string result = string.Intern(Encoding.UTF8.GetString(data, id + 4, (int)count));

            method.Body.Instructions[instrOffset].OpCode = OpCodes.Ldstr;
            method.Body.Instructions[instrOffset].Operand = result;
            method.Body.Instructions[instrOffset + 1].OpCode = OpCodes.Nop;
            method.Body.Instructions[instrOffset + 1].Operand = null;
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
            int size = Marshal.SizeOf(default(T));
            if (!CanReplaceConstant(method, instrOffset) || !TryValidateDataRange(id, size, out _))
                throw new IndexOutOfRangeException("Number constant is outside the decrypted blob");

            T[] array = new T[1];
            Buffer.BlockCopy(data!, id, array, 0, size);

            method.Body.Instructions[instrOffset].Operand = array[0];
            method.Body.Instructions[instrOffset + 1].OpCode = OpCodes.Nop;
            method.Body.Instructions[instrOffset + 1].Operand = null;
        }

        protected void FixObjectConstant(MethodDef method, int instrOffset, int id, TypeSig type)
        {
            if (!CanReplaceConstant(method, instrOffset) || !TryValidateDataRange(id, 8, out _))
                throw new IndexOutOfRangeException("Object constant header is outside the decrypted blob");

            int num0 = data![id] | (data[id + 1] << 8) | (data[id + 2] << 16) | (data[id + 3] << 24);
            uint num1 = (uint)(data![id + 4] | (data[id + 5] << 8) | (data[id + 6] << 16) | (data[id + 7] << 24));
            num1 = (num1 << 4) | (num1 >> 0x1C);

            throw new NotImplementedException("Object constant not handled");
        }

        protected void FixDefaultConstant(MethodDef method, int instrOffset, TypeSig type)
        {
            if (!CanReplaceConstant(method, instrOffset))
                throw new IndexOutOfRangeException("Default constant replacement is outside the method body");

            method.Body.Instructions[instrOffset].OpCode = OpCodes.Initobj;
            method.Body.Instructions[instrOffset].Operand = type.ToTypeDefOrRef();
            method.Body.Instructions[instrOffset + 1].OpCode = OpCodes.Nop;
            method.Body.Instructions[instrOffset + 1].Operand = null;
        }
    }
}
