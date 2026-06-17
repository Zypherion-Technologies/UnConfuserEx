using de4dot.blocks.cflow;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using log4net;

namespace UnConfuserEx.Protections.Delegates
{
    internal class RefProxyRemover : IProtection
    {
        private static readonly ILog Logger = LogManager.GetLogger("RefProxy");

        public string Name => "RefProxy";

        private ModuleDefMD? Module;
        private List<MethodDef> HandlerMethods = new();
        private HashSet<TypeDef> Delegates = new();
        private HashSet<MethodDef> DelegateCtors = new();
        private Dictionary<MethodDef, RefProxyHandler> DelegateHandlers = new();
        private Dictionary<FieldDef, Tuple<OpCode, IMethodDefOrRef>> ResolvedDelegates = new();

        public bool IsPresent(ref ModuleDefMD module)
        {
            Module = module;
            HandlerMethods.Clear();
            Delegates.Clear();
            DelegateCtors.Clear();
            DelegateHandlers.Clear();
            ResolvedDelegates.Clear();

            // Check in the default module for methods with the signature
            // static void SMethod1(RuntimeFieldHandle field, byte opKey)

            foreach (var method in Module.GlobalType.Methods)
            {
                if (method.MethodSig.ToString() == "System.Void (System.RuntimeFieldHandle,System.Byte)")
                {
                    HandlerMethods.Add(method);
                }
            }

            Logger.Debug($"RefProxy detection found {HandlerMethods.Count} handler method(s)");
            return HandlerMethods.Any();
        }

        public bool Remove(ref ModuleDefMD module)
        {
            Logger.Debug($"Resolving reference proxies from {HandlerMethods.Count} handler method(s)");
            foreach (var handler in HandlerMethods)
            {
                var instances = GetAllInstances(handler);
                Logger.Debug($"Handler {handler.FullName} is referenced by {instances.Count} method(s)");

                Delegates.UnionWith(instances.Select(instance => instance.DeclaringType));
                DelegateCtors.UnionWith(instances);

                var delegateHandler = new RefProxyHandler(module, handler);
                DelegateHandlers[handler] = delegateHandler;
            }

            ResolveAllDelegates();
            int replacements = ReplaceDelegateInvocations();

            RemoveHandlers();
            RemoveDelegateClasses();

            Logger.Debug($"Resolved {ResolvedDelegates.Count} delegate field(s), replaced {replacements} invocation(s), removed {HandlerMethods.Count} handler(s) and {DelegateCtors.Select(ctor => ctor.DeclaringType).Distinct().Count()} delegate type(s)");

            return true;
        }

        private HashSet<MethodDef> GetAllInstances(MethodDef delegateHandler)
        {
            var placesUsed = new HashSet<MethodDef>();

            foreach (var method in Module!.GetTypes().SelectMany(m => m.Methods))
            {
                if (!method.HasBody)
                    continue;

                foreach (var instr in method.Body.Instructions)
                {
                    if (instr.OpCode == OpCodes.Call && instr.Operand is MethodDef called)
                    {
                        if (called == delegateHandler)
                        {
                            placesUsed.Add(method);
                        }
                    }
                }
            }

            return placesUsed;
        }

        private void ResolveAllDelegates()
        {
            foreach (var @delegate in DelegateCtors)
            {
                if (!@delegate.HasBody) continue;
                Logger.Debug($"Resolving delegate constructor { @delegate.FullName }");
                for (int i = 0; i < @delegate.Body.Instructions.Count - 2; i += 3)
                {
                    if (@delegate.Body.Instructions[i].Operand is not FieldDef field) continue;
                    if (!@delegate.Body.Instructions[i + 1].IsLdcI4()) continue;
                    if (@delegate.Body.Instructions[i + 2].Operand is not MethodDef handler) continue;

                    var opKey = (byte)@delegate.Body.Instructions[i + 1].GetLdcI4Value();

                    var token = DelegateHandlers[handler].GetMethodMDToken(field);
                    var opCode = DelegateHandlers[handler].GetOpCode(field, opKey);

                    if (token.Table == Table.MemberRef)
                    {
                        var method = Module!.ResolveMemberRef(token.Rid);
                        ResolvedDelegates[field] = new(opCode, method);
                        Logger.Debug($"Resolved delegate field {field.FullName} -> {opCode} {method.FullName}");
                    }
                    else if (token.Table == Table.Method)
                    {
                        var method = Module!.ResolveMethod(token.Rid);
                        ResolvedDelegates[field] = new(opCode, method);
                        Logger.Debug($"Resolved delegate field {field.FullName} -> {opCode} {method.FullName}");
                    }
                    else
                    {
                        throw new NotImplementedException($"Unhandled token type: {token.Table}");
                    }
                }
            }
        }

        private int ReplaceDelegateInvocations()
        {
            int replacements = 0;
            var fieldStack = new Stack<FieldDef>();
            foreach (var method in Module!.GetTypes().SelectMany(m => m.Methods).Where(m => m.HasBody))
            {
                var instrsToRemove = new List<int>();

                var instrs = method.Body.Instructions;
                for (int i = 0; i < instrs.Count; i++)
                {
                    var instr = instrs[i];
                    if (instr.OpCode == OpCodes.Ldsfld &&
                        instr.Operand is FieldDef f &&
                        ResolvedDelegates.ContainsKey(f))
                    {
                        instrsToRemove.Add(i);
                        fieldStack.Push(f);
                    }
                    else if (instr.OpCode == OpCodes.Call &&
                        instr.Operand is MethodDef m)
                    {
                        // Normal delegate invocation
                        if (fieldStack.Count > 0 &&
                            m.DeclaringType == fieldStack.Peek().DeclaringType)
                        {
                            var field = fieldStack.Pop();
                            var (opCode, resolvedMethod) = ResolvedDelegates[field];

                            instr.OpCode = opCode;
                            instr.Operand = resolvedMethod;
                            replacements++;
                        }
                        else if (Delegates.Contains(m.DeclaringType))
                        {
                            var staticInvoke = (MethodDef)instr.Operand;
                            if (!staticInvoke.HasBody || staticInvoke.Body.Instructions.Count == 0)
                            {
                                continue;
                            }
                            var invokeInstrs = staticInvoke.Body.Instructions;

                            if (invokeInstrs[0].OpCode == OpCodes.Ldsfld
                                && invokeInstrs[0].Operand is FieldDef field
                                && ResolvedDelegates.TryGetValue(field, out var resolved))
                            {
                                instr.OpCode = resolved.Item1;
                                instr.Operand = resolved.Item2;
                                replacements++;
                            }
                            else if (staticInvoke.Parameters.Count < invokeInstrs.Count)
                            {
                                var invokeInstr = invokeInstrs[staticInvoke.Parameters.Count];

                                instrs[i].OpCode = invokeInstr.OpCode;
                                instrs[i].Operand = invokeInstr.Operand;
                                replacements++;
                            }
                        }

                    }
                }

                if (instrsToRemove.Count > 0)
                {
                    if (fieldStack.Count > 0)
                    {
                        throw new Exception("Delegate Field stack not empty!");
                    }

                    instrsToRemove.Reverse();

                    foreach (var instrIndex in instrsToRemove)
                    {
                        instrs[instrIndex].OpCode = instrs[instrIndex + 1].OpCode;
                        instrs[instrIndex].Operand = instrs[instrIndex + 1].Operand;

                        instrs.RemoveAt(instrIndex + 1);
                    }
                }
            }

            return replacements;
        }

        private void RemoveHandlers()
        {
            foreach (var handler in HandlerMethods)
            {
                Logger.Debug($"Removing handler method {handler.FullName}");
                handler.DeclaringType.Methods.Remove(handler);
            }
        }

        private void RemoveDelegateClasses()
        {
            foreach (var type in DelegateCtors.Select(ctor => ctor.DeclaringType))
            {
                Logger.Debug($"Removing delegate type {type.FullName}");
                if (type.DeclaringType is not null)
                {
                    type.DeclaringType.NestedTypes.Remove(type);
                }
                else
                {
                    Module!.Types.Remove(type);
                }
            }
        }

    }
}
