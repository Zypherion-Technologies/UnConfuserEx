using dnlib.DotNet;
using dnlib.DotNet.Emit;
using log4net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace UnConfuserEx.Protections.Constants
{
    internal class NormalResolver : IResolver
    {
        private static ILog Logger = LogManager.GetLogger("Constants");

        public NormalResolver(ModuleDefMD module, byte[] data)
        {
            Module = module;
            this.data = data;
        }

        public override void Resolve(MethodDef getter, IList<MethodDef> instances)
        {
            var instrs = getter.Body.Instructions;
            int offset = instrs[0].OpCode == OpCodes.Call && instrs[0].Operand.ToString()!.Contains("Assembly::GetExecutingAssembly") ? 5 : 1;

            var key1 = (int)instrs[offset].Operand;
            var key2 = (int)instrs[offset + 2].Operand;

            var (stringId, numId, objectId) = GetIdsFromGetter(getter);

            foreach (var method in instances)
            {
                if (ConstantsCFG.IsCFGPresent(method))
                {
                    new ConstantsCFG(method).RemoveFromMethod();
                }

                SimplifyStatefulHelperCalls(method);

                TypeSig? genericType;
                int instanceOffset = GetNextInstanceInMethod(getter, method, out genericType);

                while (instanceOffset != -1)
                {
                    instrs = method.Body.Instructions;

                    try
                    {
                        instanceOffset = CollapseToLdcI4(method.Body.Instructions, instanceOffset);
                    }
                    catch (Exception ex)
                    {
                        Logger.Debug($"Skipping constant at offset {instanceOffset} in {method.FullName} ({ex.Message})");
                        instanceOffset = GetNextInstanceInMethod(getter, method, instanceOffset + 2, out genericType);
                        continue;
                    }

                    instrs = method.Body.Instructions;
                    var id = instrs[instanceOffset].GetLdcI4Value();
                    id = (id * key1) ^ key2;
                    int type = (int)((uint)id >> 0x1e);
                    id = (id & 0x3fffffff) << 2;

                    try
                    {
                        if (IsStringType(genericType!))
                        {
                            FixStringConstant(method, instanceOffset, id);
                        }
                        else if (IsSupportedNumberType(genericType!))
                        {
                            FixNumberConstant(method, instanceOffset, id, genericType!);
                        }
                        else if (type == objectId)
                        {
                            FixObjectConstant(method, instanceOffset, id, genericType!);
                        }
                        else if (type == stringId)
                        {
                            FixStringConstant(method, instanceOffset, id);
                        }
                        else if (type == numId)
                        {
                            FixNumberConstant(method, instanceOffset, id, genericType!);
                        }
                        else
                        {
                            FixDefaultConstant(method, instanceOffset, genericType!);
                        }
                    }
                    catch (NotImplementedException ex) when (ex.Message == "Object constant not handled")
                    {
                        Logger.Debug($"Skipping unsupported object constant in method ${method.FullName}");
                        instanceOffset = GetNextInstanceInMethod(getter, method, instanceOffset + 2, out genericType);
                        continue;
                    }
                    catch (Exception ex)
                    {
                        Logger.Debug($"Skipping constant in method ${method.FullName} ({ex.Message})");
                        instanceOffset = GetNextInstanceInMethod(getter, method, instanceOffset + 2, out genericType);
                        continue;
                    }


                    instanceOffset = GetNextInstanceInMethod(getter, method, out genericType);
                }
                
                method.Body.UpdateInstructionOffsets();
            }
        }
    }
}
