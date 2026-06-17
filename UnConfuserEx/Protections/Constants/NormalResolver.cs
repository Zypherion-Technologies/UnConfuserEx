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

        public NormalResolver(byte[] data)
        {
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
                        Logger.Error($"Failed to compute id at offset {instanceOffset} in {method.FullName} ({ex.Message})");
                        instanceOffset = GetNextInstanceInMethod(getter, method, out genericType);
                        continue;
                    }

                    instrs = method.Body.Instructions;
                    var id = instrs[instanceOffset].GetLdcI4Value();
                    id = (id * key1) ^ key2;
                    int type = (int)((uint)id >> 0x1e);
                    id = (id & 0x3fffffff) << 2;

                    try
                    {
                        if (type == stringId)
                        {
                            FixStringConstant(method, instanceOffset, id);
                        }
                        else if (type == numId)
                        {
                            FixNumberConstant(method, instanceOffset, id, genericType!);
                        }
                        else if (type == objectId)
                        {
                            FixObjectConstant(method, instanceOffset, id, genericType!);
                        }
                        else
                        {
                            FixDefaultConstant(method, instanceOffset, genericType!);
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Error($"Failed to remove constants obfuscation from method ${method.FullName} ({ex.Message})");
                        return;
                    }


                    instanceOffset = GetNextInstanceInMethod(getter, method, out genericType);
                }
                
                method.Body.UpdateInstructionOffsets();
            }
        }
    }
}
