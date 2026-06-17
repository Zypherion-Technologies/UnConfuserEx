using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;

namespace UnConfuserEx.Protections.AntiTamper
{
    internal class DynamicDeriver : IKeyDeriver
    {
        private IList<Instruction> derivation;

        public DynamicDeriver(IList<Instruction> derivation)
        {
            this.derivation = derivation;
        }

        public uint[] DeriveKey(uint[] dst, uint[] src)
        {
            int dstLocal = -1;
            int srcLocal = -1;
            for (int i = 0; i < derivation.Count - 2; i++)
            {
                if (IsLdloc(derivation[i], out int li)
                    && derivation[i + 2].OpCode == OpCodes.Ldelem_U4)
                {
                    if (dstLocal == -1) { dstLocal = li; continue; }
                    if (li != dstLocal && srcLocal == -1) { srcLocal = li; break; }
                }
            }
            if (dstLocal == -1 || srcLocal == -1)
                throw new Exception("Failed to identify dst/src locals in derivation IL :C");

            var locals = new Dictionary<int, uint[]>
            {
                [dstLocal] = dst,
                [srcLocal] = src
            };
            var scalars = new Dictionary<int, uint>();

            var stack = new Stack<uint>();
            var refStack = new Stack<uint[]>();
            int idx = 0;
            while (idx < derivation.Count)
            {
                var ins = derivation[idx];
                var op = ins.OpCode.Code;
                switch (op)
                {
                    case Code.Ldloc:
                    case Code.Ldloc_S:
                    case Code.Ldloc_0:
                    case Code.Ldloc_1:
                    case Code.Ldloc_2:
                    case Code.Ldloc_3:
                        {
                            int li = GetLocalIndex(ins);
                            if (locals.TryGetValue(li, out var arr))
                                refStack.Push(arr);
                            else
                                stack.Push(scalars.TryGetValue(li, out var sv) ? sv : 0);
                            break;
                        }
                    case Code.Stloc:
                    case Code.Stloc_S:
                    case Code.Stloc_0:
                    case Code.Stloc_1:
                    case Code.Stloc_2:
                    case Code.Stloc_3:
                        {
                            int li = GetLocalIndex(ins);
                            scalars[li] = stack.Pop();
                            break;
                        }
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
                        stack.Push((uint)ins.GetLdcI4Value());
                        break;
                    case Code.Ldelem_U4:
                        {
                            uint i = stack.Pop();
                            var arr = refStack.Pop();
                            stack.Push(arr[i]);
                            break;
                        }
                    case Code.Xor:
                        {
                            uint b = stack.Pop();
                            uint a = stack.Pop();
                            stack.Push(a ^ b);
                            break;
                        }
                    case Code.Add:
                        {
                            uint b = stack.Pop();
                            uint a = stack.Pop();
                            stack.Push(unchecked(a + b));
                            break;
                        }
                    case Code.Mul:
                        {
                            uint b = stack.Pop();
                            uint a = stack.Pop();
                            stack.Push(unchecked(a * b));
                            break;
                        }
                    case Code.Sub:
                        {
                            uint b = stack.Pop();
                            uint a = stack.Pop();
                            stack.Push(unchecked(a - b));
                            break;
                        }
                    case Code.And:
                        {
                            uint b = stack.Pop();
                            uint a = stack.Pop();
                            stack.Push(a & b);
                            break;
                        }
                    case Code.Or:
                        {
                            uint b = stack.Pop();
                            uint a = stack.Pop();
                            stack.Push(a | b);
                            break;
                        }
                    case Code.Shl:
                        {
                            int b = (int)stack.Pop();
                            uint a = stack.Pop();
                            stack.Push(a << b);
                            break;
                        }
                    case Code.Shr_Un:
                    case Code.Shr:
                        {
                            int b = (int)stack.Pop();
                            uint a = stack.Pop();
                            stack.Push(a >> b);
                            break;
                        }
                    case Code.Neg:
                        {
                            uint a = stack.Pop();
                            stack.Push(unchecked((uint)-(int)a));
                            break;
                        }
                    case Code.Not:
                        {
                            uint a = stack.Pop();
                            stack.Push(~a);
                            break;
                        }
                    case Code.Stelem_I4:
                        {
                            uint val = stack.Pop();
                            uint i = stack.Pop();
                            var arr = refStack.Pop();
                            arr[i] = val;
                            break;
                        }
                    case Code.Conv_U4:
                    case Code.Conv_I4:
                    case Code.Conv_U:
                    case Code.Conv_I:
                        break;
                    case Code.Dup:
                        if (refStack.Count > 0 && (stack.Count == 0 || refStack.Count >= stack.Count))
                            refStack.Push(refStack.Peek());
                        else
                            stack.Push(stack.Peek());
                        break;
                    case Code.Pop:
                        if (stack.Count > 0) stack.Pop();
                        else refStack.Pop();
                        break;
                    case Code.Nop:
                        break;
                    default:
                        throw new Exception($"Unhandled opcode in derivation IL: {ins.OpCode}");
                }
                idx++;
            }
            return locals[dstLocal];
        }

        private static bool IsLdloc(Instruction ins, out int index)
        {
            index = 0;
            switch (ins.OpCode.Code)
            {
                case Code.Ldloc_0: index = 0; return true;
                case Code.Ldloc_1: index = 1; return true;
                case Code.Ldloc_2: index = 2; return true;
                case Code.Ldloc_3: index = 3; return true;
                case Code.Ldloc:
                case Code.Ldloc_S:
                    index = ((Local)ins.Operand).Index;
                    return true;
            }
            return false;
        }

        private static int GetLocalIndex(Instruction ins)
        {
            switch (ins.OpCode.Code)
            {
                case Code.Ldloc_0: case Code.Stloc_0: return 0;
                case Code.Ldloc_1: case Code.Stloc_1: return 1;
                case Code.Ldloc_2: case Code.Stloc_2: return 2;
                case Code.Ldloc_3: case Code.Stloc_3: return 3;
                default: return ((Local)ins.Operand).Index;
            }
        }

    }
}
