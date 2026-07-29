using dnlib.DotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet.Emit;
using UnConfuserEx.Protections.Constants;
using log4net;

namespace UnConfuserEx.Protections
{
    internal class ConstantsRemover : IProtection
    {
        private static ILog Logger = LogManager.GetLogger("Constants");

        private enum DecryptionType
        {
            Normal,
            Dynamic
        };

        private enum GetterType
        {
            Normal,
            Dynamic,
            X86
        };

        public string Name => "Constants";

        int callIndex;
        MethodDef? initializeMethod;
        byte[]? data;
        FieldDef? dataField;

        public bool IsPresent(ref ModuleDefMD module)
        {
            var cctor = module.GlobalType.FindStaticConstructor();

            if (cctor == null || !(cctor.HasBody) || cctor.Body.Instructions.Count == 0)
                return false;

            IList<Instruction> instrs;

            // Check the first calls in the constructor
            callIndex = 0;
            while (cctor.Body.Instructions[callIndex].OpCode == OpCodes.Call)
            {
                var method = cctor.Body.Instructions[callIndex].Operand as MethodDef;
                if (!method!.HasBody)
                {
                    callIndex++;
                    continue;
                }

                instrs = method!.Body.Instructions;
                for (int i = 0; i < instrs.Count - 2; i++)
                {
                    if (instrs[i].OpCode == OpCodes.Call
                        && instrs[i + 1].OpCode == OpCodes.Stsfld
                        && instrs[i + 2].OpCode == OpCodes.Ret)
                    {
                        initializeMethod = method;
                        Logger.Debug($"Constants init detected in helper method {initializeMethod.FullName} at cctor call index {callIndex}");

                        return true;
                    }
                }
                callIndex++;
            }
            callIndex = -1;

            // If we didn't find it there, check the cctor itself
            instrs = cctor.Body.Instructions;
            for (int i = 0; i < instrs.Count - 2; i++)
            {
                if (instrs[i].OpCode == OpCodes.Call
                    && instrs[i + 1].OpCode == OpCodes.Stsfld)
                {
                    initializeMethod = cctor;
                    Logger.Debug("Constants init detected directly inside module cctor");

                    return true;
                }
            }
            return false;
        }

        public bool Remove(ref ModuleDefMD module)
        {
            IList<MethodDef> constantGetters = GetAllGetters(module);

            if (constantGetters.Count == 0)
            {
                Logger.Warn("Failed to find any getters for constants obfuscation. Might not be removed!");
                return true;
            }
            Logger.Debug($"Found {constantGetters.Count} constant getter(s)");

            if (!GetEncryptedData())
            {
                Logger.Error("Failed to get encrypted constant data");
                return false;
            }

            Logger.Debug($"Loaded encrypted constants blob with {data!.Length} byte(s)");
            if (!DecryptData())
            {
                Logger.Error("[-] Failed to decrypt constant data");
                return false;
            }

            // Only LZMA is actually implemented?
            data = Utils.DecompressLZMA(data!, initializeMethod!);
            Logger.Debug($"Decompressed constants blob to {data.Length} byte(s)");

            var instrs = initializeMethod!.Body.Instructions;
            for (var i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode == OpCodes.Ldsfld &&
                    instrs[i + 1].IsLdloc() &&
                    instrs[i + 3].IsStloc())
                {
                    for (int j = 0; j < data!.Length; j += 4)
                    {
                        byte b1 = data[j];
                        byte b2 = data[j + 2];
                        byte b3 = data[j + 3];
                        data[j] = b2;
                        data[j + 2] = b3;
                        data[j + 3] = b1;
                    }

                    break;
                }
            }

            foreach (var getter in constantGetters)
            {
                var instances = GetAllInstances(getter);

                var getterType = GetGetterType(getter);
                Logger.Debug($"Resolving getter {getter.FullName} as {getterType} with {instances.Count} call site method(s)");

                Constants.IResolver resolver;
                switch (getterType)
                {
                    case GetterType.X86:
                        resolver = new X86Resolver(module, data!);
                        break;
                    case GetterType.Normal:
                        resolver = new NormalResolver(module, data!);
                        break;
                    default:
                        throw new NotImplementedException();
                }

                resolver.Resolve(getter, instances.ToList());

                Logger.Debug($"Removed all instances of getter {getter.FullName}");

                StubMethod(getter);
            }

            module.GlobalType.Fields.Remove(dataField);

            var cctor = module.GlobalType.FindStaticConstructor();

            // Remove the decryption call/instructions
            if (callIndex == -1)
            {
                int offset = 0;
                while (cctor.Body.Instructions[offset].OpCode == OpCodes.Call)
                {
                    offset++;
                }

                for (int i = offset; i < initializeMethod.Body.Instructions.Count; i++)
                {
                    var instr = initializeMethod.Body.Instructions[i];

                    if (instr.OpCode == OpCodes.Ldtoken &&
                        instr.Operand is TypeDef td &&
                        td == module.GlobalType)
                    {
                        break;
                    }
                    initializeMethod.Body.Instructions.RemoveAt(offset);
                    i--;
                }
                initializeMethod.Body.Instructions.UpdateInstructionOffsets();
            }
            else
            {
                cctor.Body.Instructions.RemoveAt(callIndex);
                module.GlobalType.Methods.Remove(initializeMethod);
            }
            return true;
        }

        private bool GetEncryptedData()
        {
            var instrs = initializeMethod!.Body.Instructions;
            for (int i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode == OpCodes.Ldtoken
                    && instrs[i + 1].OpCode == OpCodes.Call)
                {
                    dataField = instrs[i].Operand as FieldDef;
                    data = dataField!.InitialValue;
                    Logger.Debug($"Constants data field resolved as {dataField.FullName}");
                    
                    return true;
                }
            }
            return false;
        }

        private (DecryptionType?, List<Instruction>?) GetDecryptionType()
        {
            var instrs = initializeMethod!.Body.Instructions;

            bool firstLoopEnd = true;
            var firstInstr = -1;
            for (int i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode == OpCodes.Ldc_I4_S
                    && instrs[i + 1].OpCode == OpCodes.Blt_S)
                {
                    if (firstLoopEnd)
                    {
                        firstLoopEnd = false;
                        continue;
                    }
                    firstInstr = i + 2;
                    break;
                }
            }

            if (firstInstr == -1)
            {
                return (null, null);
            }

            var lastInstr = -1;
            for (int i = firstInstr; i < instrs.Count - 2; i++)
            {
                if (instrs[i].OpCode == OpCodes.Stloc_S
                    && instrs[i + 1].OpCode == OpCodes.Br_S)
                {
                    lastInstr = i - 1;
                    break;
                }
            }

            if (lastInstr == -1)
            {
                return (null, null);
            }

            int decryptlength = (lastInstr - firstInstr);

            var decryptInstructions = initializeMethod.Body.Instructions.Skip(firstInstr).Take(decryptlength).ToList();
            const int normalDecryptLength = 16 * 10;
            DecryptionType type = (decryptlength == normalDecryptLength) ? DecryptionType.Normal : DecryptionType.Dynamic;

            return (type, decryptInstructions);
        }

        private uint[]? GetInitialArray()
        {
            uint? key = null;
            bool? shlFirst = null;

            var instrs = initializeMethod!.Body.Instructions;

            // Get the key value and if we left shift first
            for (int i = 0; i < instrs.Count - 2; i++)
            {
                if (instrs[i].OpCode == OpCodes.Newarr
                    && instrs[i + 2].OpCode == OpCodes.Ldc_I4)
                {
                    key = (uint)(int)instrs[i + 2].Operand;
                }
                else if (instrs[i].OpCode == OpCodes.Ldc_I4_S
                        && instrs[i].Operand is sbyte val
                        && val == 12)
                {
                    shlFirst = instrs[i + 1].OpCode == OpCodes.Shl;
                }

                if (key != null && shlFirst != null)
                    break;
            }

            if (key == null || shlFirst == null)
                return null;

            Logger.Debug($"Resolved initial constants key seed={key} shlFirst={shlFirst}");

            uint[] ret = new uint[16];
            for (int j = 0; j < 16; j++)
            {
                key ^= (bool)shlFirst ? key << 12 : key >> 12;
                key ^= (bool)shlFirst ? key >> 25 : key << 25;
                key ^= (bool)shlFirst ? key << 27 : key >> 27;
                ret[j] = (uint)key;
            }
            return ret;
        }

        private bool DecryptData()
        {
            var (type, decryptInstructions) = GetDecryptionType();
            if (type == null || decryptInstructions == null)
            {
                Logger.Error("Failed to get decryption type");
                return false;
            }
            Logger.Debug($"Detected constant decryption type is {type}");

            uint[] uintData = new uint[data!.Length >> 2];
            Buffer.BlockCopy(data, 0, uintData, 0, data.Length);

            uint[]? key = GetInitialArray();
            if (key == null)
            {
                Logger.Error("Failed to get initial array");
                return false;
            }

            IDecryptor decryptor;
            if (type == DecryptionType.Normal)
            {
                decryptor = new NormalDecryptor();
            }
            else
            {
                decryptor = new DynamicDecryptor(decryptInstructions);
            }

            data = decryptor.DecryptData(uintData, key);

            return true;
        }

        private static IList<MethodDef> GetAllGetters(ModuleDefMD module)
        {
            var methods = module.GlobalType.Methods;
            var getters = new List<MethodDef>();

            foreach (var method in methods)
            {
                if (!method.HasBody)
                    continue;

                if (method.Signature.ToString()!.Contains("- <!!0>(System."))
                {
                    getters.Add(method);
                }

                //var instrs = method.Body.Instructions;
                //if (instrs[0].OpCode == OpCodes.Call && instrs[0].Operand.ToString()!.Contains("Assembly::GetExecutingAssembly")
                //    && instrs[1].OpCode == OpCodes.Call && instrs[1].Operand.ToString()!.Contains("Assembly::GetCallingAssembly"))
                //{
                //    getters.Add(method);
                //    Logger.Debug(method.Signature);
                //}
            }

            return getters;
        }

        private HashSet<MethodDef> GetAllInstances(MethodDef getter)
        {
            var placesUsed = new HashSet<MethodDef>();

            foreach (var method in getter.Module.GetTypes().SelectMany(m => m.Methods))
            {
                if (!method.HasBody)
                    continue;

                foreach (var instr in method.Body.Instructions)
                {
                    if (instr.OpCode == OpCodes.Call && instr.Operand is MethodSpec called)
                    {
                        if (called.Method.Equals(getter))
                        {
                            placesUsed.Add(method.ResolveMethodDef());
                        }
                    }
                }
            }
            return placesUsed;
        }
        
        private static GetterType GetGetterType(MethodDef getter)
        {
            var instrs = getter.Body.Instructions;

            int offset = instrs[0].OpCode == OpCodes.Call && instrs[0].Operand.ToString()!.Contains("Assembly::GetExecutingAssembly") ? 5 : 1;
            if (instrs[offset].OpCode == OpCodes.Call)
            {
                return GetterType.X86;
            }
            else if (instrs[offset].IsLdcI4() && instrs[offset + 2].IsLdcI4())
            {
                return GetterType.Normal;
            }
            else
            {
                return GetterType.Dynamic;
            }
        }

        private static bool HasMethodReference(ModuleDefMD module, MethodDef target)
        {
            foreach (var method in module.GetTypes().SelectMany(type => type.Methods))
            {
                if (!method.HasBody)
                    continue;

                foreach (var instr in method.Body.Instructions)
                {
                    switch (instr.Operand)
                    {
                        case MethodDef called when called == target:
                            return true;
                        case MethodSpec called when called.Method == target:
                            return true;
                        case IMethod called when called.ResolveMethodDef() == target:
                            return true;
                    }
                }
            }

            return false;
        }

        private static void StubMethod(MethodDef method)
        {
            if (!method.HasBody)
            {
                method.Body = new CilBody();
            }
            else
            {
                method.Body.ExceptionHandlers.Clear();
                method.Body.Variables.Clear();
                method.Body.Instructions.Clear();
            }

            method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
            method.Body.Instructions.Add(Instruction.Create(OpCodes.Throw));
            method.Body.UpdateInstructionOffsets();
        }

    }
}
