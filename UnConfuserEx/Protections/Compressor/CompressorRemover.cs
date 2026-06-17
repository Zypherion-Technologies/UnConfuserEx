using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using log4net;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace UnConfuserEx.Protections.Compressor
{
    internal class CompressorRemover : IProtection
    {
        private static ILog Logger = LogManager.GetLogger("Compressor");

        private enum CompressorMode
        {
            Normal,
            Compact
        }

        public string Name => "Compressor";

        public static ModuleDefMD? DecompressedModule { get; private set; }

        MethodDef? mainMethod;
        MethodDef? decryptMethod;
        FieldDef? dataField;
        CompressorMode mode;
        uint seed;
        int dataLength;
        int keyI2Token;

        public bool IsPresent(ref ModuleDefMD module)
        {
            DecompressedModule = null;

            if (module.EntryPoint == null || !module.EntryPoint.HasBody)
                return false;

            mainMethod = module.EntryPoint;

            if (!TryDetectMain(mainMethod, out decryptMethod, out mode))
                return false;

            return true;
        }

        public bool Remove(ref ModuleDefMD module)
        {
            if (!ExtractKeysAndData(module))
            {
                Logger.Error("Failed to extract keys or data from stub");
                return false;
            }

            Logger.Debug($"Mode={mode}, seed=0x{seed:X8}, len={dataLength}");

            byte[] encrypted = dataField!.InitialValue!;
            if (encrypted.Length < dataLength * 4)
            {
                Logger.Error($"Data field too small: {encrypted.Length} < {dataLength * 4}");
                return false;
            }

            if (!ExtractDerivation(out List<Instruction>? derivation) || derivation == null)
            {
                Logger.Error("Failed to extract derivation IL");
                return false;
            }

            BuildSeedState(seed, out uint[] w, out uint[] k, out ulong endS);

            uint[] derivedKey = EmulateDerivation(derivation, w, k);

            byte[] decompressed = DecryptAndDecompress(encrypted, derivedKey, endS);

            ModuleDefMD inner;
            try
            {
                inner = ModuleDefMD.Load(decompressed);
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to load decompressed module");
                Logger.Error(ex.ToString());
                return false;
            }

            if (mode == CompressorMode.Normal)
            {
                FixupNormalModule(module, inner);
            }

            DecompressedModule = inner;
            module = inner;

            return true;
        }

        private static bool TryDetectMain(MethodDef main, out MethodDef? decrypt, out CompressorMode mode)
        {
            decrypt = null;
            mode = CompressorMode.Compact;

            bool sawAssemblyLoad = false;
            bool sawLoadModule = false;
            bool sawResolveSig = false;
            MethodDef? candidate = null;

            foreach (var instr in main.Body.Instructions)
            {
                if (instr.OpCode == OpCodes.Call && instr.Operand is MethodDef md)
                {
                    if (md.HasReturnType && md.ReturnType.FullName == "System.Runtime.InteropServices.GCHandle"
                        && md.Parameters.Count == 2)
                    {
                        candidate = md;
                    }
                }
                else if (instr.Operand != null)
                {
                    //nLoadImage(...) - > Native Backend for Assembly.Load - not done
                    
                    string s = instr.Operand.ToString() ?? "";
                    if (s.Contains("Assembly::Load(System.Byte[])") || s.Contains("Assembly::Load"))
                        sawAssemblyLoad = true;

                    if (s.Contains("Assembly::LoadModule"))
                        sawLoadModule = true;

                    if (s.Contains("Module::ResolveSignature") || s.Contains("ResolveSignature"))
                        sawResolveSig = true;
                    
                }
            }

            if (candidate == null)
                return false;

            if (sawLoadModule)
                mode = CompressorMode.Normal;

            else if (sawAssemblyLoad && sawResolveSig)
                mode = CompressorMode.Compact;

            else if (sawAssemblyLoad)
                mode = CompressorMode.Compact;

            else
                return false;

            decrypt = candidate;
            return true;
        }

        private bool ExtractKeysAndData(ModuleDefMD module)
        {
            var instrs = mainMethod!.Body.Instructions;

            int decryptCallIdx = -1;
            for (int i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode == OpCodes.Call && instrs[i].Operand == decryptMethod)
                {
                    decryptCallIdx = i;
                    break;
                }
            }

            if (decryptCallIdx == -1)
                return false;

            for (int i = decryptCallIdx - 1; i >= 0; i--)
            {
                if (instrs[i].IsLdcI4())
                {
                    seed = (uint)instrs[i].GetLdcI4Value();
                    break;
                }
            }

            for (int i = 0; i < instrs.Count - 1; i++)
            {
                if (instrs[i].OpCode == OpCodes.Ldtoken && instrs[i].Operand is FieldDef fd
                    && fd.HasFieldRVA && fd.InitialValue != null && fd.InitialValue.Length > 0)
                {
                    dataField = fd;
                    break;
                }
            }
            if (dataField == null)
                return false;

            for (int i = 0; i < instrs.Count - 1; i++)
            {
                if (instrs[i].IsLdcI4() && instrs[i + 1].OpCode == OpCodes.Newarr)
                {
                    dataLength = instrs[i].GetLdcI4Value();
                    break;
                }
            }

            for (int i = 1; i < instrs.Count; i++)
            {
                if (instrs[i].Operand != null
                    && (instrs[i].Operand.ToString() ?? "").Contains("ResolveSignature")
                    && instrs[i - 1].IsLdcI4())
                {
                    keyI2Token = instrs[i - 1].GetLdcI4Value();
                    break;
                }
            }

            return true;
        }

        private bool ExtractDerivation(out List<Instruction>? derivation)
        {
            derivation = null;
            var instrs = decryptMethod!.Body.Instructions;

            int startIdx = -1;
            for (int i = 0; i < instrs.Count - 1; i++)
            {
                if ((instrs[i].OpCode == OpCodes.Ldc_I4 || instrs[i].OpCode == OpCodes.Ldc_I4_S)
                    && instrs[i].GetLdcI4Value() == 0x10
                    && (instrs[i + 1].OpCode == OpCodes.Blt_S || instrs[i + 1].OpCode == OpCodes.Blt))
                {
                    startIdx = i + 2;
                    break;
                }
            }

            if (startIdx == -1)
                return false;

            int endIdx = -1;
            for (int i = startIdx; i < instrs.Count - 3; i++)
            {
                if (instrs[i].OpCode == OpCodes.Call
                    && (instrs[i].Operand?.ToString() ?? "").Contains("Array::Clear"))
                {
                    endIdx = i - 4;
                    break;
                }
                if (instrs[i].OpCode == OpCodes.Newarr)
                {
                    endIdx = i - 3;
                    break;
                }
            }
            if (endIdx < startIdx)
                return false;

            var d = new List<Instruction>();
            for (int i = startIdx; i <= endIdx; i++)
                d.Add(instrs[i]);
            
            derivation = d;
            return true;
        }

        private static void BuildSeedState(uint seedVal, out uint[] w, out uint[] k, out ulong endS)
        {
            ulong s = seedVal;
            w = new uint[0x10];
            k = new uint[0x10];
            for (int i = 0; i < 0x10; i++)
            {
                s = (s * s) % 0x143fc089;
                k[i] = (uint)s;
                w[i] = (uint)((s * s) % 0x444d56fb);
            }
            endS = s;
        }

        private static uint[] EmulateDerivation(List<Instruction> instrs, uint[] w, uint[] k)
        {
            int dstLocal = -1;
            int srcLocal = -1;
            for (int i = 0; i < instrs.Count - 2; i++)
            {
                if (IsLdloc(instrs[i], out int li)
                    && instrs[i + 2].OpCode == OpCodes.Ldelem_U4)
                {
                    if (dstLocal == -1) { dstLocal = li; continue; }
                    if (li != dstLocal && srcLocal == -1) { srcLocal = li; break; }
                }
            }
            if (dstLocal == -1 || srcLocal == -1)
                throw new Exception("Failed to identify dst/src locals in derivation IL");

            var locals = new Dictionary<int, uint[]>
            {
                [dstLocal] = w,
                [srcLocal] = k
            };

            var stack = new Stack<uint>();
            var refStack = new Stack<uint[]>();
            int idx = 0;
            while (idx < instrs.Count)
            {
                var ins = instrs[idx];
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
                            refStack.Push(locals[li]);
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
                        {
                            var t = refStack.Peek();
                            refStack.Push(t);
                        }
                        else
                        {
                            var t = stack.Peek();
                            stack.Push(t);
                        }
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
                case Code.Ldloc_0: return 0;
                case Code.Ldloc_1: return 1;
                case Code.Ldloc_2: return 2;
                case Code.Ldloc_3: return 3;
                default: return ((Local)ins.Operand).Index;
            }
        }

        private byte[] DecryptAndDecompress(byte[] encrypted, uint[] derivedKey, ulong endS)
        {
            uint[] data = new uint[encrypted.Length >> 2];
            Buffer.BlockCopy(encrypted, 0, data, 0, encrypted.Length);

            var w = (uint[])derivedKey.Clone();
            var b = new byte[data.Length << 2];
            uint h = 0;
            for (int i = 0; i < data.Length; i++)
            {
                uint d = data[i] ^ w[i & 0xf];
                w[i & 0xf] = (w[i & 0xf] ^ d) + 0x3ddb2819;
                b[h + 0] = (byte)(d >> 0);
                b[h + 1] = (byte)(d >> 8);
                b[h + 2] = (byte)(d >> 16);
                b[h + 3] = (byte)(d >> 24);
                h += 4;
            }

            byte[] j = DecompressLzma(b);

            ulong s = endS;
            for (int i = 0; i < j.Length; i++)
            {
                j[i] ^= (byte)s;
                if ((i & 0xff) == 0)
                    s = (s * s) % 0x8a5cb7;
            }

            return j;
        }

        private static byte[] DecompressLzma(byte[] data)
        {
            return RuntimeLzma.Lzma.Decompress(data);
        }

        private void FixupNormalModule(ModuleDefMD stub, ModuleDefMD inner)
        {
            inner.Kind = stub.Kind;
            inner.Name = stub.Name;

            if (keyI2Token != 0)
            {
                try
                {
                    uint rid = (uint)(keyI2Token & 0x00FFFFFF);
                    byte[]? blob = null;
                    if (stub.TablesStream.TryReadStandAloneSigRow(rid, out var row))
                    {
                        blob = stub.BlobStream.Read(row.Signature);
                    }
                    if (blob != null && blob.Length >= 4)
                    {
                        uint entryToken = (uint)(blob[0] | (blob[1] << 8) | (blob[2] << 16) | (blob[3] << 24));
                        var mtoken = new MDToken(entryToken);
                        if (mtoken.Table == Table.Method)
                        {
                            var ep = inner.ResolveMethod(mtoken.Rid);
                            if (ep != null)
                                inner.EntryPoint = ep;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Warn($"Failed to recover entry point: {ex.Message}");
                }
            }

            foreach (var res in stub.Resources)
            {
                if (inner.Resources.Find(res.Name) == null)
                    inner.Resources.Add(res);
            }
        }
    }
}
