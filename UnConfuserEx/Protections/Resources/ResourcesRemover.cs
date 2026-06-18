using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using log4net;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Resources;
using System.Resources.Extensions;
using UnConfuserEx.Protections.Resources;

namespace UnConfuserEx.Protections
{
    internal class ResourcesRemover : IProtection
    {
        private static ILog Logger = LogManager.GetLogger("Resources");

        private enum DecryptionType
        {
            Normal,
            Dynamic
        };

        public string Name => "Resources";

        int callIndex;
        MethodDef? initializeMethod;
        byte[]? data;

        FieldDef? dataField;
        FieldDef? assemblyField;
        MethodDef? handlerMethod;

        public bool IsPresent(ref ModuleDefMD module)
        {
            var cctor = module.GlobalType.FindStaticConstructor();

            if (cctor == null || !(cctor.HasBody) || cctor.Body.Instructions.Count == 0)
                return false;

            IList<Instruction> instrs;

            callIndex = 0;
            while (cctor.Body.Instructions[callIndex].OpCode == OpCodes.Call)
            {
                var method = cctor.Body.Instructions[callIndex].Operand as MethodDef;
                if (!method!.HasBody)
                {
                    callIndex++;
                    continue;
                }

                instrs = method.Body.Instructions;
                for (int i = 0; i < instrs.Count - 3; i++)
                {
                    if (instrs[i].OpCode == OpCodes.Stsfld
                        && instrs[i + 1].OpCode == OpCodes.Call
                        && instrs[i + 1].Operand.ToString()!.Contains("AppDomain::get_CurrentDomain")
                        && instrs[i + 2].OpCode == OpCodes.Ldnull
                        && instrs[i + 3].OpCode == OpCodes.Ldftn)
                    {
                        assemblyField = instrs[i].Operand as FieldDef;
                        initializeMethod = method;
                        handlerMethod = instrs[i + 3].Operand as MethodDef;
                        Logger.Debug($"Resources init detected in helper method {initializeMethod.FullName} at cctor call index {callIndex}");
                        return true;
                    }
                }
                callIndex++;
            }

            callIndex = -1;
            instrs = cctor.Body.Instructions;
            for (int i = 0; i < instrs.Count - 3; i++)
            {
                if (instrs[i].OpCode == OpCodes.Stsfld
                    && instrs[i + 1].OpCode == OpCodes.Call
                    && instrs[i + 1].Operand.ToString()!.Contains("AppDomain::get_CurrentDomain")
                    && instrs[i + 2].OpCode == OpCodes.Ldnull
                    && instrs[i + 3].OpCode == OpCodes.Ldftn)
                {
                    assemblyField = instrs[i].Operand as FieldDef;
                    initializeMethod = cctor;
                    handlerMethod = instrs[i + 3].Operand as MethodDef;
                    Logger.Debug("Resources init detected directly inside module cctor");
                    return true;
                }
            }

            return false;
        }

        public bool Remove(ref ModuleDefMD module)
        {
            if (!GetEncryptedData())
            {
                Logger.Error("Failed to get encrypted resource data");
                return false;
            }

            Logger.Debug($"Loaded encrypted resource blob with {data!.Length} byte(s)");
            if (!DecryptData())
            {
                Logger.Error("Failed to decrypt resource data");
                return false;
            }

            data = Utils.DecompressLZMA(data!, initializeMethod!);
            Logger.Debug($"Decompressed resource blob to {data.Length} byte(s)");

            var loadedModule = ModuleDefMD.Load(data);
            NormalizeImportedResources(loadedModule.Resources);
            int replacedResources = 0;
            foreach (var resource in loadedModule.Resources)
            {
                int index = module.Resources.ToList().FindIndex(r => r.Name.Equals(resource.Name));
                if (index != -1)
                {
                    module.Resources.RemoveAt(index);
                    replacedResources++;
                }
                module.Resources.Add(resource);
            }
            Logger.Debug($"Imported {loadedModule.Resources.Count} resource(s), replaced {replacedResources} existing resource(s)");

            module.GlobalType.Methods.Remove(handlerMethod);
            module.GlobalType.Fields.Remove(assemblyField);
            module.GlobalType.Fields.Remove(dataField);

            var cctor = module.GlobalType.FindStaticConstructor();
            if (callIndex == -1)
            {
                int startIndex = 0;
                while (startIndex < cctor.Body.Instructions.Count &&
                       cctor.Body.Instructions[startIndex].OpCode == OpCodes.Call)
                {
                    startIndex++;
                }

                int endIndex = -1;
                for (int i = startIndex; i < cctor.Body.Instructions.Count - 3; i++)
                {
                    if (cctor.Body.Instructions[i].OpCode == OpCodes.Stsfld &&
                        cctor.Body.Instructions[i].Operand == assemblyField &&
                        cctor.Body.Instructions[i + 1].OpCode == OpCodes.Call &&
                        cctor.Body.Instructions[i + 1].Operand.ToString()!.Contains("AppDomain::get_CurrentDomain") &&
                        cctor.Body.Instructions[i + 2].OpCode == OpCodes.Ldnull &&
                        cctor.Body.Instructions[i + 3].OpCode == OpCodes.Ldftn &&
                        cctor.Body.Instructions[i + 3].Operand == handlerMethod)
                    {
                        endIndex = i + 3;
                        while (endIndex + 1 < cctor.Body.Instructions.Count)
                        {
                            var next = cctor.Body.Instructions[endIndex + 1];
                            if ((next.OpCode == OpCodes.Call || next.OpCode == OpCodes.Callvirt) &&
                                next.Operand?.ToString()!.Contains("::add_") == true)
                            {
                                endIndex++;
                                break;
                            }
                            endIndex++;
                        }
                        break;
                    }
                }

                if (endIndex == -1)
                    return false;

                for (int i = endIndex; i >= startIndex; i--)
                    cctor.Body.Instructions.RemoveAt(i);
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
                    Logger.Debug($"Resource data field resolved as {dataField.FullName}");
                    return true;
                }
            }
            return false;
        }

        private uint[]? GetInitialArray()
        {
            uint? key = null;
            bool? shlFirst = null;

            var instrs = initializeMethod!.Body.Instructions;
            for (int i = 0; i < instrs.Count - 2; i++)
            {
                if (instrs[i].OpCode == OpCodes.Newarr
                    && instrs[i + 2].OpCode == OpCodes.Ldc_I4)
                {
                    key = (uint)(int)instrs[i + 2].Operand;
                }
                else if (instrs[i].OpCode == OpCodes.Ldc_I4_S
                        && instrs[i].Operand is sbyte val
                        && val == 13)
                {
                    shlFirst = instrs[i + 1].OpCode == OpCodes.Shl;
                }

                if (key != null && shlFirst != null)
                    break;
            }

            if (key == null || shlFirst == null)
                return null;

            Logger.Debug($"Resolved initial resource key seed={key} shlFirst={shlFirst}");

            uint[] ret = new uint[16];
            for (int j = 0; j < 16; j++)
            {
                key ^= (bool)shlFirst ? key << 13 : key >> 13;
                key ^= (bool)shlFirst ? key >> 25 : key << 25;
                key ^= (bool)shlFirst ? key << 27 : key >> 27;
                ret[j] = (uint)key;
            }
            return ret;
        }

        private (DecryptionType?, List<Instruction>?) GetDecryptionTypeAndInstructions()
        {
            var instrs = initializeMethod!.Body.Instructions;

            bool firstLoopEnd = true;
            var firstInstr = -1;
            for (int i = 0; i < instrs.Count - 1; i++)
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
                return (null, null);

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
                return (null, null);

            int length = lastInstr - firstInstr;
            var decryptInstructions = instrs.Skip(firstInstr).Take(length).ToList();
            const int normalDecryptLength = 16 * 10;
            DecryptionType type = (length == normalDecryptLength) ? DecryptionType.Normal : DecryptionType.Dynamic;
            return (type, decryptInstructions);
        }

        private bool DecryptData()
        {
            var (type, decryptInstructions) = GetDecryptionTypeAndInstructions();
            if (type == null || decryptInstructions == null)
            {
                Logger.Error("Failed to get decryption type");
                return false;
            }

            Logger.Debug($"Detected resource decryption type is {type}");

            uint[] uintData = new uint[data!.Length >> 2];
            Buffer.BlockCopy(data, 0, uintData, 0, data.Length);

            uint[]? key = GetInitialArray();
            if (key == null)
            {
                Logger.Error("Failed to get initial array");
                return false;
            }

            IDecryptor decryptor = type == DecryptionType.Normal
                ? new NormalDecryptor()
                : new DynamicDecryptor(decryptInstructions);

            data = decryptor.Decrypt(key, uintData);
            return true;
        }

        private static void NormalizeImportedResources(IList<Resource> resources)
        {
            for (int i = 0; i < resources.Count; i++)
            {
                var resource = resources[i];
                if (resource is not EmbeddedResource embedded)
                    continue;

                var bytes = embedded.CreateReader().ToArray();
                if (TryDescribePortableExecutable(bytes, out var description))
                {
                    Logger.Debug($"Imported resource {resource.Name} is {description}");
                    if (RuntimeOptions.RebuildEmbeddedPe && TryRebuildManagedPortableExecutable(bytes, out var rebuiltBytes, out var rebuiltDescription))
                    {
                        resources[i] = new EmbeddedResource(resource.Name, rebuiltBytes, resource.Attributes);
                        Logger.Debug($"Rebuilt imported resource {resource.Name} as {rebuiltDescription}");
                    }
                    continue;
                }

                if (!IsDotNetResources(bytes))
                    continue;

                try
                {
                    bool changed = false;
                    using var output = new MemoryStream();
                    using var writer = new PreserializedResourceWriter(output);
                    using var stream = new MemoryStream(bytes, writable: false);
                    using var reader = new DeserializingResourceReader(stream);
                    var enumerator = reader.GetEnumerator();
                    while (enumerator.MoveNext())
                    {
                        object? value = enumerator.Value;
                        if (value is byte[] payload && TryDescribePortableExecutable(payload, out description))
                        {
                            Logger.Debug($"Resource entry {resource.Name}/{enumerator.Key} is {description}");
                            if (RuntimeOptions.RebuildEmbeddedPe && TryRebuildManagedPortableExecutable(payload, out var rebuiltPayload, out var rebuiltDescription))
                            {
                                value = rebuiltPayload;
                                changed = true;
                                Logger.Debug($"Rebuilt resource entry {resource.Name}/{enumerator.Key} as {rebuiltDescription}");
                            }
                        }

                        writer.AddResource((string)enumerator.Key, value);
                    }

                    if (!changed)
                        continue;

                    writer.Generate();
                    resources[i] = new EmbeddedResource(resource.Name, output.ToArray(), resource.Attributes);
                }
                catch (Exception ex)
                {
                    Logger.Debug($"Failed to inspect embedded .resources payload {resource.Name}: {ex.Message}");
                }
            }
        }

        private static bool IsDotNetResources(byte[] data)
        {
            return data.Length >= 4
                && data[0] == 0xCE
                && data[1] == 0xCA
                && data[2] == 0xEF
                && data[3] == 0xBE;
        }

        private static bool TryDescribePortableExecutable(byte[] data, out string description)
        {
            description = string.Empty;
            if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z')
                return false;

            int peOffset = BitConverter.ToInt32(data, 0x3C);
            if (peOffset < 0 || peOffset > data.Length - 0x18)
                return false;

            if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || data[peOffset + 2] != 0 || data[peOffset + 3] != 0)
                return false;

            ushort machine = BitConverter.ToUInt16(data, peOffset + 4);
            ushort characteristics = BitConverter.ToUInt16(data, peOffset + 22);
            ushort optionalMagic = BitConverter.ToUInt16(data, peOffset + 24);
            ushort subsystem = data.Length >= peOffset + 0x5E ? BitConverter.ToUInt16(data, peOffset + 0x5C) : (ushort)0;

            string arch = machine switch
            {
                0x014C => "x86",
                0x8664 => "x64",
                0x01C4 => "ARM",
                0xAA64 => "ARM64",
                _ => $"machine 0x{machine:X4}"
            };

            string kind = (characteristics & 0x2000) != 0
                ? "DLL"
                : subsystem switch
                {
                    2 => "GUI EXE",
                    3 => "Console EXE",
                    _ => "EXE"
                };

            string format = optionalMagic switch
            {
                0x010B => "PE32",
                0x020B => "PE32+",
                _ => $"optional 0x{optionalMagic:X4}"
            };

            description = $"{kind} ({arch}, {format})";
            return true;
        }

        private static bool TryRebuildManagedPortableExecutable(byte[] data, out byte[] rebuiltData, out string description)
        {
            rebuiltData = data;
            description = string.Empty;

            string tempInput = Path.Combine(Path.GetTempPath(), $"ucex-{Guid.NewGuid():N}.bin");
            string tempOutput = Path.Combine(Path.GetTempPath(), $"ucex-{Guid.NewGuid():N}.bin");

            try
            {
                File.WriteAllBytes(tempInput, data);
                using var module = ModuleDefMD.Load(tempInput);

                if (!TryDescribePortableExecutable(data, out description))
                    description = module.IsILOnly ? "managed PE" : "mixed-mode PE";

                UnConfuserEx.PrepareModuleForWrite(module);

                if (module.IsILOnly)
                {
                    var writerOptions = new ModuleWriterOptions(module);
                    writerOptions.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
                    module.Write(tempOutput, writerOptions);
                }
                else
                {
                    var writerOptions = new NativeModuleWriterOptions(module, true);
                    writerOptions.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
                    module.NativeWrite(tempOutput, writerOptions);
                }

                rebuiltData = File.ReadAllBytes(tempOutput);
                return true;
            }
            catch (Exception ex)
            {
                Logger.Debug($"Failed to rebuild embedded PE: {ex.Message}");
                rebuiltData = data;
                return false;
            }
            finally
            {
                TryDeleteFile(tempInput);
                TryDeleteFile(tempOutput);
            }
        }

        private static void TryDeleteFile(string path)
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch
            {
            }
        }
    }
}
