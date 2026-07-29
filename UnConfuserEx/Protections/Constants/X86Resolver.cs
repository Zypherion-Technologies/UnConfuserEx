using dnlib.DotNet;
using dnlib.DotNet.Emit;
using log4net;
using System;
using System.Collections.Generic;
using X86Emulator;

namespace UnConfuserEx.Protections.Constants
{
    internal class X86Resolver : IResolver
    {
        private static ILog Logger = LogManager.GetLogger("Constants");

        public X86Resolver(ModuleDefMD module, byte[] data)
        {
            Module = module;
            this.data = data;
        }

        public override void Resolve(MethodDef getter, IList<MethodDef> instances)
        {
            var x86MethodDef = (MethodDef)getter.Body.Instructions[5].Operand;
            var x86Method = new X86Method(Module, x86MethodDef);

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

                    var instrs = method.Body.Instructions;

                    var id = instrs[instanceOffset].GetLdcI4Value();
                    id = x86Method.Emulate(new int[] { id });
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

            }
        }

    }
}
