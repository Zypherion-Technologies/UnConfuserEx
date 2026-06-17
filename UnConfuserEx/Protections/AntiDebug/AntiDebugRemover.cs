using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UnConfuserEx.Protections.AntiDebug
{
    internal class AntiDebugRemover : IProtection
    {
        public string Name => "AntiDebug";

        private enum AntiDebugType
        {
            Safe,
            Win32,
            Antinet
        };

        MethodDef? antiDebugMethod;
        AntiDebugType? antiDebugType;

        public bool IsPresent(ref ModuleDefMD module)
        {
            var cctor = module.GlobalType.FindStaticConstructor();

            if (cctor == null || !(cctor.HasBody) || cctor.Body.Instructions.Count == 0)
                return false;

            IList<Instruction> instrs;

            // Check the first call in the cctor
            if (cctor.Body.Instructions[0].OpCode == OpCodes.Call)
            {
                var method = cctor.Body.Instructions[0].Operand as MethodDef;

                instrs = method!.Body.Instructions;

                for (int i = 0; i < instrs.Count; i++)
                {
                    // common antidebug methods, u can go by other few flags, e.g is debuggerpresent,checkremotedebugger
                    // and the list goes on :)
                    if (instrs[i].OpCode == OpCodes.Ldstr &&
                        instrs[i].Operand is String str1 &&
                        str1 == "COR_ENABLE_PROFILING") 
                    {
                        antiDebugMethod = method;
                        antiDebugType = AntiDebugType.Safe;
                        return true;
                    }
                    else if (instrs[i].OpCode == OpCodes.Ldstr &&
                        instrs[i].Operand is String str2 &&
                        str2 == "_ENABLE_PROFILING")
                    {
                        antiDebugMethod = method;
                        antiDebugType = AntiDebugType.Win32;
                        return true;
                    }
                    else if (instrs[i].OpCode == OpCodes.Ldnull &&
                        instrs[i + 1].OpCode == OpCodes.Call &&
                        instrs[i + 1].Operand is MemberRef m &&
                        m.Name == "FailFast")
                    {
                        antiDebugMethod = method;
                        antiDebugType = AntiDebugType.Antinet;
                        return true;
                    }
                }

            }

            return false;
        }

        public bool Remove(ref ModuleDefMD module)
        {
            var cctor = module.GlobalType.FindStaticConstructor()!;
            var injectedMethod = antiDebugMethod;

            switch (antiDebugType)
            {
                case AntiDebugType.Safe:
                case AntiDebugType.Win32:
                case AntiDebugType.Antinet:
                    cctor.Body.Instructions.RemoveAt(0);
                    CleanupInjectedMembers(module, injectedMethod);
                    return true;
            }

            return false;
        }

        private static void CleanupInjectedMembers(ModuleDefMD module, MethodDef? rootMethod)
        {
            if (rootMethod == null)
                return;

            var methodsToRemove = new HashSet<MethodDef>();
            var fieldsToRemove = new HashSet<FieldDef>();
            var typesToRemove = new HashSet<TypeDef>();
            var pendingMethods = new Stack<MethodDef>();

            methodsToRemove.Add(rootMethod);
            pendingMethods.Push(rootMethod);

            while (pendingMethods.Count > 0)
            {
                var method = pendingMethods.Pop();
                if (!method.HasBody)
                    continue;

                foreach (var instr in method.Body.Instructions)
                {
                    if (instr.Operand is MethodDef calledMethod && calledMethod.DeclaringType == module.GlobalType && methodsToRemove.Add(calledMethod))
                    {
                        pendingMethods.Push(calledMethod);
                    }
                    else if (instr.Operand is FieldDef field && field.DeclaringType == module.GlobalType)
                    {
                        fieldsToRemove.Add(field);
                    }
                    else if (instr.Operand is TypeDef type && type.DeclaringType == module.GlobalType)
                    {
                        typesToRemove.Add(type);
                    }
                }
            }

            if (methodsToRemove.Count == 0 && fieldsToRemove.Count == 0 && typesToRemove.Count == 0)
                return;

            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (methodsToRemove.Contains(method))
                        continue;

                    if (!method.HasBody)
                        continue;

                    foreach (var instr in method.Body.Instructions)
                    {
                        if (instr.Operand is MethodDef calledMethod)
                            methodsToRemove.Remove(calledMethod);
                        else if (instr.Operand is FieldDef field)
                            fieldsToRemove.Remove(field);
                        else if (instr.Operand is TypeDef referencedType)
                            typesToRemove.Remove(referencedType);
                    }
                }
            }

            foreach (var method in methodsToRemove)
                method.DeclaringType.Methods.Remove(method);

            foreach (var field in fieldsToRemove)
                field.DeclaringType.Fields.Remove(field);

            foreach (var type in typesToRemove)
                type.DeclaringType?.NestedTypes.Remove(type);
        }
    }
}
