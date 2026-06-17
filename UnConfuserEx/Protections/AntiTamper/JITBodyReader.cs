using System;
using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace UnConfuserEx.Protections.AntiTamper
{
    internal class JITBodyReader
    {
        readonly ModuleDefMD module;
        readonly MethodDef method;
        readonly byte[] code;
        readonly IList<Local> locals;
        readonly List<Instruction> instructions = new();
        readonly Dictionary<uint, Instruction> offsetMap = new();
        readonly GenericParamContext gpContext;

        public IList<Instruction> Instructions => instructions;
        public IList<Local> Locals => locals;

        public JITBodyReader(ModuleDefMD module, MethodDef method, byte[] code, IList<Local> locals)
        {
            this.module = module;
            this.method = method;
            this.code = code;
            this.locals = locals;
            this.gpContext = GenericParamContext.Create(method);
        }

        public bool Read()
        {
            using var ms = new MemoryStream(code);
            using var reader = new BinaryReader(ms);
            var pending = new List<(Instruction Instr, OpCode Op, object Raw)>();

            while (ms.Position < ms.Length)
            {
                uint offset = (uint)ms.Position;
                OpCode opcode = ReadOpCode(reader);

                var instr = new Instruction(opcode);
                instr.Offset = offset;

                object? raw = ReadOperand(reader, opcode);
                instr.Operand = raw;

                instructions.Add(instr);
                offsetMap[offset] = instr;
                
                pending.Add((instr, opcode, raw!));
            }

            foreach (var (instr, op, raw) in pending)
            {
                instr.Operand = ResolveOperand(op, raw, (uint)(instr.Offset + GetSize(op, raw)));
            }
            return true;
        }

        private int GetSize(OpCode op, object raw)
        {
            int size = op.Size;
            switch (op.OperandType)
            {
                case OperandType.InlineBrTarget:
                case OperandType.InlineField:
                case OperandType.InlineI:
                case OperandType.InlineMethod:
                case OperandType.InlineSig:
                case OperandType.InlineString:
                case OperandType.InlineTok:
                case OperandType.InlineType:
                case OperandType.ShortInlineR:
                    size += 4;
                    break;
                case OperandType.InlineI8:
                case OperandType.InlineR:
                    size += 8;
                    break;
                case OperandType.InlineVar:
                    size += 2;
                    break;
                case OperandType.ShortInlineBrTarget:
                case OperandType.ShortInlineI:
                case OperandType.ShortInlineVar:
                    size += 1;
                    break;
                case OperandType.InlineSwitch:
                    int n = ((uint[])raw).Length;
                    size += 4 + 4 * n;
                    break;
            }
            return size;
        }

        private OpCode ReadOpCode(BinaryReader reader)
        {
            byte b = reader.ReadByte();
            if (b == 0xFE)
            {
                byte b2 = reader.ReadByte();
                return OpCodes.TwoByteOpCodes[b2];
            }
            return OpCodes.OneByteOpCodes[b];
        }

        private object? ReadOperand(BinaryReader reader, OpCode op)
        {
            switch (op.OperandType)
            {
                case OperandType.InlineBrTarget:
                    return reader.ReadInt32();
                case OperandType.ShortInlineBrTarget:
                    return (int)reader.ReadSByte();
                case OperandType.InlineField:
                case OperandType.InlineMethod:
                case OperandType.InlineSig:
                case OperandType.InlineString:
                case OperandType.InlineTok:
                case OperandType.InlineType:
                    return reader.ReadUInt32();
                case OperandType.InlineI:
                    return reader.ReadInt32();
                case OperandType.InlineI8:
                    return reader.ReadInt64();
                case OperandType.InlineNone:
                    return null;
                case OperandType.InlineR:
                    return reader.ReadDouble();
                case OperandType.ShortInlineR:
                    return reader.ReadSingle();
                case OperandType.InlineSwitch:
                    uint n = reader.ReadUInt32();
                    var arr = new uint[n];
                    for (uint i = 0; i < n; i++)
                        arr[i] = reader.ReadUInt32();
                    return arr;
                case OperandType.InlineVar:
                    return reader.ReadUInt16();
                case OperandType.ShortInlineI:
                    if (op.Code == Code.Ldc_I4_S)
                        return reader.ReadSByte();
                    return reader.ReadByte();
                case OperandType.ShortInlineVar:
                    return reader.ReadByte();
                default:
                    return null;
            }
        }

        private object? ResolveOperand(OpCode op, object? raw, uint nextOffset)
        {
            switch (op.OperandType)
            {
                case OperandType.InlineBrTarget:
                    return GetInstruction((uint)((int)nextOffset + (int)raw!));
                case OperandType.ShortInlineBrTarget:
                    return GetInstruction((uint)((int)nextOffset + (int)raw!));
                case OperandType.InlineField:
                case OperandType.InlineMethod:
                case OperandType.InlineSig:
                case OperandType.InlineTok:
                case OperandType.InlineType:
                    return module.ResolveToken((uint)raw!, gpContext);
                case OperandType.InlineString:
                    return module.ReadUserString((uint)raw!);
                case OperandType.InlineSwitch:
                    var rawArr = (uint[])raw!;
                    var targets = new Instruction[rawArr.Length];
                    for (int i = 0; i < rawArr.Length; i++)
                        targets[i] = GetInstruction((uint)((int)nextOffset + (int)rawArr[i]))!;
                    return targets;
                case OperandType.InlineVar:
                    {
                        ushort idx = (ushort)raw!;
                        if (op.Code == Code.Ldarg || op.Code == Code.Ldarga || op.Code == Code.Starg)
                            return GetParameter(idx);
                        return GetLocalByIndex(idx);
                    }
                case OperandType.ShortInlineVar:
                    {
                        byte idx = (byte)raw!;
                        if (op.Code == Code.Ldarg_S || op.Code == Code.Ldarga_S || op.Code == Code.Starg_S)
                            return GetParameter(idx);
                        return GetLocalByIndex(idx);
                    }
                default:
                    return raw;
            }
        }

        private Parameter? GetParameter(int index)
        {
            if (index < 0 || index >= method.Parameters.Count)
                return null;
            return method.Parameters[index];
        }

        private Local? GetLocalByIndex(int index)
        {
            if (index < 0 || index >= locals.Count)
                return null;
            return locals[index];
        }

        public Instruction? GetInstruction(uint offset)
        {
            offsetMap.TryGetValue(offset, out var instr);
            return instr;
        }

        public Instruction? GetInstructionOrEnd(uint offset)
        {
            if (offsetMap.TryGetValue(offset, out var instr))
                return instr;
            return null;
        }
    }
}
