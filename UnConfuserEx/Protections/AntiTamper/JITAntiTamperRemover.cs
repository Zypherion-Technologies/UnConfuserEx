using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.IO;
using dnlib.PE;
using log4net;
using UnConfuserEx.Protections;

namespace UnConfuserEx.Protections.AntiTamper
{
    internal class JITAntiTamperRemover : IProtection
    {
        static ILog Logger = LogManager.GetLogger("AntiTamperJIT");

        private enum DeriverType
        {
            Normal,
            Dynamic
        }

        public string Name => "AntiTamperJIT";

        MethodDef? initMethod;
        MethodDef? initEntryMethod;
        MethodDef? cctor;
        int initCallIndex = -1;

        public bool IsPresent(ref ModuleDefMD module)
        {
            cctor = module.GlobalType.FindStaticConstructor();
            if (cctor == null || !cctor.HasBody || cctor.Body.Instructions.Count == 0)
                return false;

            for (int i = 0; i < cctor.Body.Instructions.Count; i++)
            {
                
                var instr = cctor.Body.Instructions[i];
                if (instr.OpCode != OpCodes.Call && instr.OpCode != OpCodes.Callvirt)
                    continue;

                var candidate = ResolveMethod(instr.Operand);

                if (candidate == null || !candidate.HasBody)
                    continue;
                
                var resolvedInit = FindJitInitialize(candidate, module, new HashSet<MethodDef>(), 0);

                if (resolvedInit == null)
                    continue;
                if (!HasJitArtifacts(module, resolvedInit))
                    continue;

                initEntryMethod = candidate;
                initMethod = resolvedInit;
                initCallIndex = i;
                return true;
            }
            return false;
        }

        public bool Remove(ref ModuleDefMD module)
        {
            uint[]? initialKeys = ExtractInitialKeys(initMethod!);
            if (initialKeys == null)
            {
                Logger.Error("Failed to extract initial keys");
                return false;
            }
            uint key = ExtractMethodKey(module);
            if (key == 0)
            {
                Logger.Error("Failed to extract per-method key");
                return false;
            }
            uint sectionNameHash = (uint)(initialKeys[0]);
            uint z = (uint)initialKeys[1];
            uint x = (uint)initialKeys[2];
            uint c = (uint)initialKeys[3];
            uint v = (uint)initialKeys[4];

            ImageSectionHeader? encrypted = FindEncryptedSection(module, sectionNameHash);
            if (encrypted == null)
            {
                Logger.Error("Failed to find encrypted JIT body section");
                return false;
            }
            Logger.Debug($"Found JIT section {Encoding.ASCII.GetString(encrypted.Name)}");

            (uint[] dst, uint[] src) = PrepareKeyArrays(module, encrypted, sectionNameHash, z, x, c, v);

            (DeriverType deriverType, IList<Instruction>? derivation) = DetectDeriver(initMethod!);
            Logger.Debug($"Detected deriver type {deriverType}");

            IKeyDeriver deriver = deriverType == DeriverType.Normal
                ? new NormalDeriver()
                : new DynamicDeriver(derivation!);
            
            uint[] sectionKey = deriver.DeriveKey(dst, src);

            byte[] sectionBytes = DecryptSection(module, encrypted, sectionKey);

            byte[]? fieldLayout = ExtractFieldLayout(module);

            if (fieldLayout == null || fieldLayout.Length != 6)
            {
                Logger.Error("Failed to extract field layout");
                return false;
            }

            Logger.Debug($"Field layout: [{string.Join(",", fieldLayout)}]");

            if (!RestoreBodies(module, sectionBytes, key, fieldLayout))
                return false;

            StripInitialization(module);
            return true;
        }

        private static bool LooksLikeJitInitialize(MethodDef method, ModuleDefMD module)
        {
            bool hasGlobalToken = false;
            bool hasDelegateMarker = false;
            bool hasMemoryProtectionMarker = false;

            foreach (var instr in method.Body.Instructions)
            {
                if (instr.OpCode == OpCodes.Ldtoken && instr.Operand == module.GlobalType)
                    hasGlobalToken = true;

                if ((instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt)
                    && instr.Operand is IMethod m
                )
                {

                    if (m.Name == "GetDelegateForFunctionPointer" || m.Name == "PrepareDelegate")
                        hasDelegateMarker = true;
                    
                    else if (m.Name == "VirtualProtect" || m.Name == "GetHINSTANCE")
                        hasMemoryProtectionMarker = true;
                }
            }
            return hasGlobalToken && (hasDelegateMarker || hasMemoryProtectionMarker);
        }

        private static MethodDef? FindJitInitialize(MethodDef method, ModuleDefMD module, HashSet<MethodDef> visited, int depth)
        {
            if (!visited.Add(method))
                return null;

            if (LooksLikeJitInitialize(method, module))
                return method;

            if (depth >= 2 || !method.HasBody)
                return null;

            foreach (var instr in method.Body.Instructions)
            {
                if (instr.OpCode != OpCodes.Call && instr.OpCode != OpCodes.Callvirt)
                    continue;

                var callee = ResolveMethod(instr.Operand);
                if (callee == null || !callee.HasBody)
                {
                    continue;
                }

                var found = FindJitInitialize(callee, module, visited, depth + 1);
                if (found != null)
                    return found;
            }

            return null;
        }

        private static MethodDef? ResolveMethod(object? operand)
        {
            if (operand is MethodDef methodDef)
                return methodDef;

            return (operand as IMethod)?.ResolveMethodDef();
        }

        private static bool HasJitArtifacts(ModuleDefMD module, MethodDef initMethod)
        {
            var initialKeys = ExtractInitialKeys(initMethod);

            if (initialKeys == null)
                return false;

            if (ExtractMethodKey(module) == 0)
                return false;

            if (FindEncryptedSection(module, initialKeys[0]) == null)
                return false;

            var fieldLayout = ExtractFieldLayout(module);
            return fieldLayout != null && fieldLayout.Length == 6;
        }

        private static uint[]? ExtractInitialKeys(MethodDef method)
        {
            var instrs = method.Body.Instructions;
            var stateKeys = new List<uint>();
            uint? sectionHash = null;

            for (int i = 0; i < instrs.Count - 1; i++)
            {
                if (instrs[i].OpCode != OpCodes.Ldc_I4)
                    continue;
                
                uint val = (uint)(int)instrs[i].Operand;
                var next = instrs[i + 1].OpCode;

                if (IsStloc(next) && stateKeys.Count < 4)
                {
                    stateKeys.Add(val);
                }

                else if (sectionHash == null
                    && (next == OpCodes.Bne_Un || next == OpCodes.Bne_Un_S
                        || next == OpCodes.Beq || next == OpCodes.Beq_S
                        || next == OpCodes.Ceq
                    )
                )
                {
                    sectionHash = val;
                }

                if (stateKeys.Count == 4 && sectionHash != null)
                    break;
            }

            if (stateKeys.Count < 4 || sectionHash == null)
                return null;
            
            return new[] { sectionHash.Value, stateKeys[0], stateKeys[1], stateKeys[2], stateKeys[3] };
        }

        private static uint ExtractMethodKey(ModuleDefMD module)
        {
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody)
                        continue;
                    if (!IsHookHandlerCandidate(method))
                        continue;
                    var instrs = method.Body.Instructions;
                    for (int i = 0; i < instrs.Count - 2; i++)
                    {
                        if (instrs[i].OpCode == OpCodes.Ldc_I4
                            && instrs[i + 1].OpCode == OpCodes.Mul
                            && IsStloc(instrs[i + 2].OpCode))
                        {
                            return (uint)(int)instrs[i].Operand;
                        }
                    }
                }
            }
            return 0;
        }

        private static bool IsHookHandlerCandidate(MethodDef method)
        {
            if (method.MethodSig == null)
                return false;

            if (method.MethodSig.RetType.ElementType != dnlib.DotNet.ElementType.U4)
                return false;

            if (method.Parameters.Count < 5)
                return false;

            bool hasShr = false, hasMul = false;
            foreach (var instr in method.Body.Instructions)
            {
                if (instr.OpCode == OpCodes.Shr_Un)
                    hasShr = true;
                if (instr.OpCode == OpCodes.Mul)
                    hasMul = true;
            }
            return hasShr && hasMul;
        }

        private static bool IsStloc(OpCode opcode)
        {
            return opcode == OpCodes.Stloc || opcode == OpCodes.Stloc_S
                || opcode == OpCodes.Stloc_0 || opcode == OpCodes.Stloc_1
                || opcode == OpCodes.Stloc_2 || opcode == OpCodes.Stloc_3;
        }

        private static ImageSectionHeader? FindEncryptedSection(ModuleDefMD module, uint nameHash)
        {
            foreach (var s in module.Metadata.PEImage.ImageSectionHeaders)
            {
                var n = s.Name;
                uint a = (uint)(n[0] | n[1] << 8 | n[2] << 16 | n[3] << 24);
                uint b = (uint)(n[4] | n[5] << 8 | n[6] << 16 | n[7] << 24);
                if (a * b == nameHash)
                    return s;
            }
            return null;
        }

        private static (uint[], uint[]) PrepareKeyArrays(ModuleDefMD module, ImageSectionHeader encrypted, uint nameHash, uint z, uint x, uint c, uint v)
        {
            var reader = module.Metadata.PEImage.CreateReader();
            foreach (var section in module.Metadata.PEImage.ImageSectionHeaders)
            {
                var n = section.Name;
                uint a = (uint)(n[0] | n[1] << 8 | n[2] << 16 | n[3] << 24);
                uint b = (uint)(n[4] | n[5] << 8 | n[6] << 16 | n[7] << 24);
                uint hash = a * b;
                if (section == encrypted)
                    continue;
                if (hash == 0)
                    continue;
                uint size = section.SizeOfRawData >> 2;
                reader.Position = section.PointerToRawData;
                for (uint i = 0; i < size; i++)
                {
                    uint data = reader.ReadUInt32();
                    uint t = (z ^ data) + x + c * v;
                    z = x;
                    x = v;
                    v = t;
                }
            }

            uint[] dst = new uint[16], src = new uint[16];
            for (int i = 0; i < 16; i++)
            {
                dst[i] = v;
                src[i] = x;
                z = (x >> 5) | (x << 27);
                x = (c >> 3) | (c << 29);
                c = (v >> 7) | (v << 25);
                v = (z >> 11) | (z << 21);
            }
            return (dst, src);
        }

        private static byte[] DecryptSection(ModuleDefMD module, ImageSectionHeader encrypted, uint[] key)
        {
            var reader = module.Metadata.PEImage.CreateReader();
            uint size = encrypted.SizeOfRawData >> 2;
            reader.Position = encrypted.PointerToRawData;
            uint[] result = new uint[size];
            for (uint i = 0; i < size; i++)
            {
                uint data = reader.ReadUInt32();
                result[i] = data ^ key[i & 0xf];
                key[i & 0xf] = (key[i & 0xf] ^ result[i]) + 0x3dbb2819;
            }
            byte[] bytes = new byte[size << 2];
            Buffer.BlockCopy(result, 0, bytes, 0, bytes.Length);
            return bytes;
        }

        private static (DeriverType, IList<Instruction>?) DetectDeriver(MethodDef method)
        {
            var instrs = method.Body.Instructions;
            int firstInstr = -1;
            for (int i = 0; i < instrs.Count - 1; i++)
            {
                if (instrs[i].IsLdcI4() && instrs[i].GetLdcI4Value() == 0x10
                    && (instrs[i + 1].OpCode == OpCodes.Blt_S || instrs[i + 1].OpCode == OpCodes.Blt))
                {
                    firstInstr = i + 2;
                    break;
                }
            }
            if (firstInstr == -1)
                return (DeriverType.Normal, null);

            int scanEnd = firstInstr;
            while (scanEnd < instrs.Count && IsDerivationOpCode(instrs[scanEnd].OpCode.Code))
                scanEnd++;

            int lastInstr = -1;
            for (int i = scanEnd - 1; i >= firstInstr; i--)
            {
                if (instrs[i].OpCode == OpCodes.Stelem_I4)
                {
                    lastInstr = i;
                    break;
                }
            }
            if (lastInstr == -1)
                return (DeriverType.Normal, null);

            var derivation = new List<Instruction>();
            for (int i = firstInstr; i <= lastInstr; i++)
                derivation.Add(instrs[i]);

            const int normalDerivationLength = 16 * 10;
            DeriverType type = derivation.Count == normalDerivationLength ? DeriverType.Normal : DeriverType.Dynamic;
            return (type, derivation);
        }

        private static bool IsDerivationOpCode(Code code)
        {
            switch (code)
            {
                case Code.Ldloc:
                case Code.Ldloc_S:
                case Code.Ldloc_0:
                case Code.Ldloc_1:
                case Code.Ldloc_2:
                case Code.Ldloc_3:
                case Code.Stloc:
                case Code.Stloc_S:
                case Code.Stloc_0:
                case Code.Stloc_1:
                case Code.Stloc_2:
                case Code.Stloc_3:
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
                case Code.Ldelem_U4:
                case Code.Stelem_I4:
                case Code.Add:
                case Code.Sub:
                case Code.Mul:
                case Code.Neg:
                case Code.Xor:
                case Code.And:
                case Code.Or:
                case Code.Not:
                case Code.Shl:
                case Code.Shr:
                case Code.Shr_Un:
                case Code.Dup:
                case Code.Pop:
                case Code.Nop:
                case Code.Conv_U4:
                case Code.Conv_I4:
                case Code.Conv_U:
                case Code.Conv_I:
                    return true;
                default:
                    return false;
            }
        }

        private static byte[]? ExtractFieldLayout(ModuleDefMD module)
        {
            TypeDef? methodDataType = null;
            foreach (var type in module.GetTypes())
            {
                if (!type.IsValueType || type.Fields.Count != 6)
                    continue;
                bool allUInt = true;
                foreach (var f in type.Fields)
                {
                    if (f.FieldType.ElementType != dnlib.DotNet.ElementType.U4)
                    {
                        allUInt = false;
                        break;
                    }
                }
                if (allUInt)
                {
                    methodDataType = type;
                    break;
                }
            }
            if (methodDataType == null)
                return null;

            var fieldToStructOffset = new Dictionary<FieldDef, int>();
            for (int i = 0; i < methodDataType.Fields.Count; i++)
                fieldToStructOffset[methodDataType.Fields[i]] = i;

            MethodDef? hookHandler = null;
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody)
                        continue;
                    if (!IsHookHandlerCandidate(method))
                        continue;
                    foreach (var ins in method.Body.Instructions)
                    {
                        if ((ins.OpCode == OpCodes.Ldfld || ins.OpCode == OpCodes.Ldflda)
                            && ins.Operand is FieldDef fd
                            && fieldToStructOffset.ContainsKey(fd))
                        {
                            hookHandler = method;
                            break;
                        }
                    }
                    if (hookHandler != null)
                        break;
                }
                if (hookHandler != null)
                    break;
            }
            if (hookHandler == null)
                return null;

            var accessOrder = new List<int>();
            foreach (var ins in hookHandler.Body.Instructions)
            {
                if ((ins.OpCode == OpCodes.Ldfld || ins.OpCode == OpCodes.Ldflda)
                    && ins.Operand is FieldDef fd
                    && fieldToStructOffset.TryGetValue(fd, out var off))
                {
                    if (!accessOrder.Contains(off))
                        accessOrder.Add(off);
                }
            }

            if (accessOrder.Count == 5)
            {
                int missing = 0 + 1 + 2 + 3 + 4 + 5;
                foreach (var off in accessOrder)
                    missing -= off;
                accessOrder.Add(missing);
            }
            if (accessOrder.Count != 6)
                return null;

            int[] semanticAccessOrder = { 0, 1, 2, 4, 3, 5 };
            byte[] semanticToStructOffset = new byte[6];
            for (int i = 0; i < 6; i++)
                semanticToStructOffset[semanticAccessOrder[i]] = (byte)accessOrder[i];

            byte[] layout = new byte[6];
            for (byte semantic = 0; semantic < 6; semantic++)
                layout[semanticToStructOffset[semantic]] = semantic;
            return layout;
        }

        private bool RestoreBodies(ModuleDefMD module, byte[] sectionBytes, uint key, byte[] fieldLayout)
        {
            int padding = 0x10;
            uint pos = (uint)padding;
            if (pos + 4 > sectionBytes.Length)
            {
                Logger.Error("Section too small for body index");
                return false;
            }
            uint indexCount = BitConverter.ToUInt32(sectionBytes, (int)pos);
            uint indexStart = pos;
            pos += 4;
            var entries = new List<(uint Token, uint Offset)>();
            for (uint i = 0; i < indexCount; i++)
            {
                if (pos + 8 > sectionBytes.Length)
                {
                    Logger.Error("Truncated body index");
                    return false;
                }
                uint tok = BitConverter.ToUInt32(sectionBytes, (int)pos);
                uint off = BitConverter.ToUInt32(sectionBytes, (int)(pos + 4));
                entries.Add((tok, off));
                pos += 8;
            }

            int restored = 0, failed = 0;
            foreach (var entry in entries)
            {
                uint blobStart = indexStart + 4 + (entry.Offset << 2);
                if (blobStart + 4 > sectionBytes.Length)
                {
                    failed++;
                    continue;
                }

                uint dwordLen = BitConverter.ToUInt32(sectionBytes, (int)blobStart);
                uint payloadStart = blobStart + 4;
                uint payloadLen = dwordLen << 2;

                if (payloadStart + payloadLen > sectionBytes.Length)
                {
                    failed++;
                    continue;
                }
                byte[] encrypted = new byte[payloadLen];
                Buffer.BlockCopy(sectionBytes, (int)payloadStart, encrypted, 0, (int)payloadLen);
                byte[] decrypted = DecryptMethodBlob(encrypted, entry.Token, key);

                var method = module.ResolveToken(entry.Token) as MethodDef;
                if (method == null)
                {
                    failed++;
                    continue;
                }

                if (!TryRestoreMethod(module, method, decrypted, fieldLayout))
                {
                    failed++;
                    continue;
                }
                restored++;
            }
            Logger.Info($"Restored {restored} method bodies, failed {failed}");
            return restored > 0;
        }

        private static byte[] DecryptMethodBlob(byte[] data, uint token, uint key)
        {
            byte[] result = new byte[data.Length];
            uint state = token * key;
            uint counter = state;
            for (int i = 0; i < data.Length; i += 4)
            {
                uint encrypted = (uint)(data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24));
                uint plain = encrypted ^ state;

                result[i + 0] = (byte)(plain >> 0);
                result[i + 1] = (byte)(plain >> 8);

                result[i + 2] = (byte)(plain >> 16);
                result[i + 3] = (byte)(plain >> 24);

                state += plain ^ counter;

                counter ^= (state >> 5) | (state << 27);
            }
            return result;
        }

        private bool TryRestoreMethod(ModuleDefMD module, MethodDef method, byte[] blob, byte[] fieldLayout)
        {
            try
            {
                int pos = 0;
                uint ilCodeSize = 0, maxStack = 0, ehCount = 0, localVarsLen = 0, options = 0;
                foreach (byte field in fieldLayout)
                {
                    uint val = BitConverter.ToUInt32(blob, pos);
                    pos += 4;
                    switch (field)
                    {
                        case 0: ilCodeSize = val;
                         break;

                        case 1: maxStack = val;
                         break;

                        case 2: ehCount = val;
                         break;

                        case 3: localVarsLen = val; 
                         break;

                        case 4: options = val;
                         break;

                        case 5: 
                         break;
                    }
                }
                if (ilCodeSize > blob.Length || localVarsLen > blob.Length)
                    return false;

                byte[] ilCode = new byte[ilCodeSize];
                Buffer.BlockCopy(blob, pos, ilCode, 0, (int)ilCodeSize);
                pos += (int)ilCodeSize;

                IList<Local> locals = new List<Local>();
                if (localVarsLen > 0)
                {
                    byte[] sigBlob = new byte[localVarsLen];
                    Buffer.BlockCopy(blob, pos, sigBlob, 0, (int)localVarsLen);
                    pos += (int)localVarsLen;
                    var sig = SignatureReader.ReadSig(module, sigBlob) as LocalSig;
                    if (sig != null)
                    {
                        foreach (var t in sig.Locals)
                            locals.Add(new Local(t));
                    }
                }

                var ehs = new List<JITRawEh>();
                for (uint i = 0; i < ehCount; i++)
                {
                    var eh = new JITRawEh
                    {
                        Flags = BitConverter.ToUInt32(blob, pos),
                        TryOffset = BitConverter.ToUInt32(blob, pos + 4),
                        TryLength = BitConverter.ToUInt32(blob, pos + 8),
                        HandlerOffset = BitConverter.ToUInt32(blob, pos + 12),
                        HandlerLength = BitConverter.ToUInt32(blob, pos + 16),
                        ClassTokenOrFilterOffset = BitConverter.ToUInt32(blob, pos + 20)
                    };
                    ehs.Add(eh);
                    pos += 24;
                }

                var reader = new JITBodyReader(module, method, ilCode, locals);

                if (!reader.Read())
                    return false;

                var body = new CilBody();
                body.MaxStack = (ushort)maxStack;

                body.InitLocals = (options & 0x10) != 0;
                foreach (var l in reader.Locals)
                    body.Variables.Add(l);
                
                foreach (var instr in reader.Instructions)
                    body.Instructions.Add(instr);

                foreach (var raw in ehs)
                {
                    var eh = new ExceptionHandler((ExceptionHandlerType)raw.Flags);
                    eh.TryStart = reader.GetInstruction(raw.TryOffset);
                    eh.TryEnd = reader.GetInstructionOrEnd(raw.TryOffset + raw.TryLength);
                    eh.HandlerStart = reader.GetInstruction(raw.HandlerOffset);
                    eh.HandlerEnd = reader.GetInstructionOrEnd(raw.HandlerOffset + raw.HandlerLength);
                    if (eh.HandlerType == ExceptionHandlerType.Catch)
                    {
                        eh.CatchType = module.ResolveToken(raw.ClassTokenOrFilterOffset) as ITypeDefOrRef;
                    }
                    else if (eh.HandlerType == ExceptionHandlerType.Filter)
                    {
                        eh.FilterStart = reader.GetInstruction(raw.ClassTokenOrFilterOffset);
                    }
                    body.ExceptionHandlers.Add(eh);
                }

                method.Body = body;
                return true;
            }
            catch (Exception ex)
            {
                Logger.Debug($"Restore failed for {method.FullName}: {ex.Message}");
                return false;
            }
        }

        private void StripInitialization(ModuleDefMD module)
        {
            if (cctor == null)
                return;

            for (int i = cctor.Body.Instructions.Count - 1; i >= 0; i--)
            {
                var instr = cctor.Body.Instructions[i];
                if (instr.OpCode != OpCodes.Call || instr.Operand is not MethodDef called)
                    continue;

                if (called == initEntryMethod || called == initMethod || IsNullThrowStub(called))
                    cctor.Body.Instructions.RemoveAt(i);
            }

            RemoveGlobalMethodIfPresent(module, initEntryMethod);
            RemoveGlobalMethodIfPresent(module, initMethod);

            foreach (var method in module.GlobalType.Methods.ToList())
            {
                if (IsNullThrowStub(method))
                    module.GlobalType.Methods.Remove(method);
            }
        }

        private static bool IsNullThrowStub(MethodDef method)
        {
            return method.HasBody
                && method.Body.Instructions.Count == 2
                && method.Body.Instructions[0].OpCode == OpCodes.Ldnull
                && method.Body.Instructions[1].OpCode == OpCodes.Throw;
        }

        private static void RemoveGlobalMethodIfPresent(ModuleDefMD module, MethodDef? method)
        {
            if (method != null && module.GlobalType.Methods.Contains(method))
                module.GlobalType.Methods.Remove(method);
        }

        private struct JITRawEh
        {
            public uint Flags;
            public uint TryOffset;
            public uint TryLength;
            public uint HandlerOffset;
            public uint HandlerLength;
            public uint ClassTokenOrFilterOffset;
        }
    }
}
