using dnlib.DotNet;
using dnlib.DotNet.Emit;
using log4net;
using System;
using System.Collections.Generic;
using System.Linq;

namespace UnConfuserEx.Protections
{
    internal class StaticCleanupRemover : IProtection
    {
        private static readonly ILog Logger = LogManager.GetLogger("StaticCleanup");

        public string Name => "StaticCleanup";

        public bool IsPresent(ref ModuleDefMD module)
        {
            return true;
        }

        public bool Remove(ref ModuleDefMD module)
        {
            NormalizeGlobalType(module);
            int removedAttributes = RemoveObfuscatorAttributes(module);
            int rewrittenLocals = RewriteUnusedLocals(module);
            int removedMethods = 0;
            int removedFields = 0;
            int removedTypes = RemoveDeadTypes(module);

            bool changed;
            do
            {
                changed = false;
                var referencedMethods = new HashSet<MethodDef>();
                var referencedFields = new HashSet<FieldDef>();
                CollectReferences(module, referencedMethods, referencedFields);

                foreach (var method in module.GlobalType.Methods.ToList())
                {
                    if (!CanRemoveMethod(module, method, referencedMethods))
                        continue;

                    module.GlobalType.Methods.Remove(method);
                    removedMethods++;
                    changed = true;
                }

                foreach (var field in module.GlobalType.Fields.ToList())
                {
                    if (referencedFields.Contains(field))
                        continue;

                    module.GlobalType.Fields.Remove(field);
                    removedFields++;
                    changed = true;
                }

            }
            while (changed);

            Logger.Debug($"Static cleanup removed {removedMethods} global method(s), {removedFields} global field(s), {removedTypes} type(s), rewrote {rewrittenLocals} unused local(s), and {removedAttributes} attribute(s)");
            return true;
        }

        private static void NormalizeGlobalType(ModuleDefMD module)
        {
            module.GlobalType.Name = "<Module>";
            module.GlobalType.Namespace = string.Empty;
        }

        private static bool CanRemoveMethod(ModuleDefMD module, MethodDef method, HashSet<MethodDef> referencedMethods)
        {
            if (method == module.EntryPoint)
                return false;

            if (method == module.GlobalType.FindStaticConstructor())
                return false;

            if (method.IsRuntimeSpecialName || method.IsSpecialName)
                return false;

            return !referencedMethods.Contains(method);
        }

        private static void CollectReferences(ModuleDefMD module, HashSet<MethodDef> referencedMethods, HashSet<FieldDef> referencedFields)
        {
            CollectAttributeReferences(module.CustomAttributes, referencedMethods);
            CollectAttributeReferences(module.Assembly?.CustomAttributes, referencedMethods);

            foreach (var type in module.GetTypes())
            {
                CollectAttributeReferences(type.CustomAttributes, referencedMethods);

                foreach (var gp in type.GenericParameters)
                {
                    CollectAttributeReferences(gp.CustomAttributes, referencedMethods);
                    foreach (var c in gp.GenericParamConstraints)
                        CollectAttributeReferences(c.CustomAttributes, referencedMethods);
                }

                foreach (var ii in type.Interfaces)
                    CollectAttributeReferences(ii.CustomAttributes, referencedMethods);

                foreach (var property in type.Properties)
                    CollectAttributeReferences(property.CustomAttributes, referencedMethods);

                foreach (var evt in type.Events)
                    CollectAttributeReferences(evt.CustomAttributes, referencedMethods);

                foreach (var field in type.Fields)
                    CollectAttributeReferences(field.CustomAttributes, referencedMethods);

                foreach (var method in type.Methods)
                {
                    CollectAttributeReferences(method.CustomAttributes, referencedMethods);
                    if (method.Parameters is not null)
                    {
                        foreach (var p in method.Parameters)
                        {
                            if (p.ParamDef is not null)
                                CollectAttributeReferences(p.ParamDef.CustomAttributes, referencedMethods);
                        }
                    }
                    foreach (var gp in method.GenericParameters)
                    {
                        CollectAttributeReferences(gp.CustomAttributes, referencedMethods);
                        foreach (var c in gp.GenericParamConstraints)
                            CollectAttributeReferences(c.CustomAttributes, referencedMethods);
                    }

                    foreach (var ovr in method.Overrides)
                    {
                        var resolved = ovr.MethodDeclaration?.ResolveMethodDef();
                        if (resolved is not null)
                            referencedMethods.Add(resolved);
                    }

                    if (!method.HasBody)
                        continue;

                    foreach (var instr in method.Body.Instructions)
                    {
                        switch (instr.Operand)
                        {
                            case MethodDef calledMethod:
                                referencedMethods.Add(calledMethod);
                                break;
                            case IMethod calledMethod:
                                {
                                    var resolvedMethod = calledMethod.ResolveMethodDef();
                                    if (resolvedMethod is not null)
                                        referencedMethods.Add(resolvedMethod);
                                    break;
                                }
                            case FieldDef field:
                                referencedFields.Add(field);
                                break;
                            case IField referencedField:
                                {
                                    var resolvedField = referencedField.ResolveFieldDef();
                                    if (resolvedField is not null)
                                        referencedFields.Add(resolvedField);
                                    break;
                                }
                        }
                    }
                }
            }
        }

        private static void CollectAttributeReferences(IList<CustomAttribute>? attributes, HashSet<MethodDef> referencedMethods)
        {
            if (attributes is null)
                return;

            foreach (var ca in attributes)
            {
                if (ca is null)
                    continue;

                var ctor = ca.Constructor?.ResolveMethodDef();
                if (ctor is not null)
                    referencedMethods.Add(ctor);
            }
        }

        private static int RemoveObfuscatorAttributes(ModuleDefMD module)
        {
            int removed = 0;

            removed += RemoveAttributes(module.CustomAttributes);
            removed += RemoveAttributes(module.Assembly?.CustomAttributes);

            foreach (var type in module.GetTypes())
            {
                removed += RemoveAttributes(type.CustomAttributes);

                foreach (var method in type.Methods)
                    removed += RemoveAttributes(method.CustomAttributes);

                foreach (var field in type.Fields)
                    removed += RemoveAttributes(field.CustomAttributes);
            }

            return removed;
        }

        private static int RemoveAttributes(IList<CustomAttribute>? attributes)
        {
            if (attributes is null)
                return 0;

            int removed = 0;
            for (int i = attributes.Count - 1; i >= 0; i--)
            {
                if (!ShouldRemoveAttribute(attributes[i]))
                    continue;

                attributes.RemoveAt(i);
                removed++;
            }

            return removed;
        }

        private static bool ShouldRemoveAttribute(CustomAttribute attribute)
        {
            if (attribute.AttributeType.FullName == "System.Runtime.CompilerServices.SuppressIldasmAttribute")
                return true;

            var type = attribute.AttributeType.ResolveTypeDef();
            if (type is null || type.Module != attribute.AttributeType.Module)
                return false;

            return type.BaseType?.FullName == "System.Attribute";
        }

        private static int RemoveDeadTypes(ModuleDefMD module)
        {
            var reachable = new HashSet<TypeDef>();
            var typeWorklist = new Queue<TypeDef>();
            var reachableMethods = new HashSet<MethodDef>();
            var methodWorklist = new Queue<MethodDef>();
            var reachableFields = new HashSet<FieldDef>();
            var fieldWorklist = new Queue<FieldDef>();

            AddReachableType(module.GlobalType, reachable, typeWorklist);
            EnqueueMethod(module.GlobalType.FindStaticConstructor(), reachableMethods, methodWorklist);
            EnqueueMethod(module.EntryPoint, reachableMethods, methodWorklist);
            AddReachableType(module.EntryPoint?.DeclaringType, reachable, typeWorklist);

            EnqueueAttributesForAllOwners(module, reachable, typeWorklist, reachableMethods, methodWorklist);

            foreach (var type in GetProbableEntryPointTypes(module))
            {
                AddReachableType(type, reachable, typeWorklist);
                EnqueueTypeRootMembers(type, reachableMethods, methodWorklist, reachableFields, fieldWorklist);
            }

            foreach (var type in module.GetTypes())
            {
                if (!IsTypeExternallyVisible(type))
                    continue;

                AddReachableType(type, reachable, typeWorklist);
                EnqueueTypeRootMembers(type, reachableMethods, methodWorklist, reachableFields, fieldWorklist);
            }

            while (typeWorklist.Count > 0 || methodWorklist.Count > 0 || fieldWorklist.Count > 0)
            {
                while (typeWorklist.Count > 0)
                {
                    var type = typeWorklist.Dequeue();
                    AddReachableType(type.BaseType?.ResolveTypeDef(), reachable, typeWorklist);
                    foreach (var iface in type.Interfaces)
                        AddReachableType(iface.Interface.ResolveTypeDef(), reachable, typeWorklist);

                    foreach (var field in type.Fields)
                        EnqueueTypeSignature(field.FieldSig?.Type, reachable, typeWorklist);

                    foreach (var method in type.Methods)
                    {
                        EnqueueMethodSignature(method.MethodSig, reachable, typeWorklist);
                        EnqueueGenericParameterConstraints(method.GenericParameters, reachable, typeWorklist);
                        EnqueueMethodBodyTypeReferences(method, reachable, typeWorklist);
                    }

                    foreach (var property in type.Properties)
                        EnqueuePropertySignature(property, reachable, typeWorklist);

                    foreach (var evt in type.Events)
                        AddReachableType(evt.EventType.ResolveTypeDef(), reachable, typeWorklist);

                    EnqueueGenericParameterConstraints(type.GenericParameters, reachable, typeWorklist);
                }

                while (methodWorklist.Count > 0)
                    ProcessReachableMethod(methodWorklist.Dequeue(), reachable, typeWorklist, reachableMethods, methodWorklist, reachableFields, fieldWorklist);

                while (fieldWorklist.Count > 0)
                    ProcessReachableField(fieldWorklist.Dequeue(), reachable, typeWorklist);
            }

            AddModuleReferenceFence(module, reachable);

            int removed = 0;
            foreach (var type in module.Types.ToList())
                removed += RemoveDeadNestedTypes(type, reachable);

            for (int i = module.Types.Count - 1; i >= 0; i--)
            {
                var type = module.Types[i];
                if (type == module.GlobalType || reachable.Contains(type))
                    continue;

                module.Types.RemoveAt(i);
                removed++;
            }

            return removed;
        }

        private static void EnqueueAttributesForAllOwners(
            ModuleDefMD module,
            HashSet<TypeDef> reachable,
            Queue<TypeDef> typeWorklist,
            HashSet<MethodDef> reachableMethods,
            Queue<MethodDef> methodWorklist)
        {
            EnqueueAttributes(module.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);
            EnqueueAttributes(module.Assembly?.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);

            foreach (var type in module.GetTypes())
            {
                EnqueueAttributes(type.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);

                foreach (var gp in type.GenericParameters)
                {
                    EnqueueAttributes(gp.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);
                    foreach (var c in gp.GenericParamConstraints)
                        EnqueueAttributes(c.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);
                }

                foreach (var ii in type.Interfaces)
                    EnqueueAttributes(ii.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);

                foreach (var property in type.Properties)
                    EnqueueAttributes(property.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);

                foreach (var evt in type.Events)
                    EnqueueAttributes(evt.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);

                foreach (var field in type.Fields)
                    EnqueueAttributes(field.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);

                foreach (var method in type.Methods)
                {
                    EnqueueAttributes(method.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);
                    if (method.Parameters is not null)
                    {
                        foreach (var p in method.Parameters)
                        {
                            if (p.ParamDef is not null)
                                EnqueueAttributes(p.ParamDef.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);
                        }
                    }
                    foreach (var gp in method.GenericParameters)
                    {
                        EnqueueAttributes(gp.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);
                        foreach (var c in gp.GenericParamConstraints)
                            EnqueueAttributes(c.CustomAttributes, reachable, typeWorklist, reachableMethods, methodWorklist);
                    }
                }
            }
        }

        private static void EnqueueAttributes(
            IList<CustomAttribute>? attributes,
            HashSet<TypeDef> reachable,
            Queue<TypeDef> typeWorklist,
            HashSet<MethodDef> reachableMethods,
            Queue<MethodDef> methodWorklist)
        {
            if (attributes is null)
                return;

            foreach (var ca in attributes)
            {
                if (ca is null)
                    continue;

                AddReachableType(ca.AttributeType?.ResolveTypeDef(), reachable, typeWorklist);
                var ctor = ca.Constructor?.ResolveMethodDef();
                if (ctor is not null)
                {
                    AddReachableType(ctor.DeclaringType, reachable, typeWorklist);
                    EnqueueMethod(ctor, reachableMethods, methodWorklist);
                }

                foreach (var arg in ca.ConstructorArguments)
                    EnqueueCAArgumentTypes(arg, reachable, typeWorklist);
                foreach (var named in ca.NamedArguments)
                {
                    EnqueueTypeSignature(named.Type, reachable, typeWorklist);
                    EnqueueCAArgumentTypes(named.Argument, reachable, typeWorklist);
                }
            }
        }

        private static void EnqueueCAArgumentTypes(CAArgument arg, HashSet<TypeDef> reachable, Queue<TypeDef> worklist)
        {
            EnqueueTypeSignature(arg.Type, reachable, worklist);
            switch (arg.Value)
            {
                case TypeSig ts:
                    EnqueueTypeSignature(ts, reachable, worklist);
                    break;
                case ITypeDefOrRef tdr:
                    AddReachableType(tdr.ResolveTypeDef(), reachable, worklist);
                    break;
                case CAArgument inner:
                    EnqueueCAArgumentTypes(inner, reachable, worklist);
                    break;
                case System.Collections.IList list:
                    foreach (var item in list)
                    {
                        if (item is CAArgument innerArg)
                            EnqueueCAArgumentTypes(innerArg, reachable, worklist);
                    }
                    break;
            }
        }

        private static void AddModuleReferenceFence(ModuleDefMD module, HashSet<TypeDef> reachable)
        {
            var worklist = new Queue<TypeDef>();

            foreach (var type in module.GetTypes())
            {
                AddReachableType(type.BaseType?.ResolveTypeDef(), reachable, worklist);
                foreach (var iface in type.Interfaces)
                    AddReachableType(iface.Interface.ResolveTypeDef(), reachable, worklist);

                EnqueueGenericParameterConstraints(type.GenericParameters, reachable, worklist);

                foreach (var field in type.Fields)
                    EnqueueTypeSignature(field.FieldSig?.Type, reachable, worklist);

                foreach (var method in type.Methods)
                {
                    EnqueueMethodSignature(method.MethodSig, reachable, worklist);
                    EnqueueGenericParameterConstraints(method.GenericParameters, reachable, worklist);
                    EnqueueMethodBodyTypeReferences(method, reachable, worklist);
                }

                foreach (var property in type.Properties)
                    EnqueuePropertySignature(property, reachable, worklist);

                foreach (var evt in type.Events)
                    AddReachableType(evt.EventType.ResolveTypeDef(), reachable, worklist);
            }

            while (worklist.Count > 0)
            {
                var type = worklist.Dequeue();
                AddReachableType(type.BaseType?.ResolveTypeDef(), reachable, worklist);
                foreach (var iface in type.Interfaces)
                    AddReachableType(iface.Interface.ResolveTypeDef(), reachable, worklist);
                EnqueueGenericParameterConstraints(type.GenericParameters, reachable, worklist);
            }
        }

        private static void ProcessReachableMethod(
            MethodDef method,
            HashSet<TypeDef> reachableTypes,
            Queue<TypeDef> typeWorklist,
            HashSet<MethodDef> reachableMethods,
            Queue<MethodDef> methodWorklist,
            HashSet<FieldDef> reachableFields,
            Queue<FieldDef> fieldWorklist)
        {
            AddReachableType(method.DeclaringType, reachableTypes, typeWorklist);
            EnqueueMethodSignature(method.MethodSig, reachableTypes, typeWorklist);
            EnqueueGenericParameterConstraints(method.GenericParameters, reachableTypes, typeWorklist);
            EnqueueMethodBodyTypeReferences(method, reachableTypes, typeWorklist);

            if (!method.HasBody)
                return;

            foreach (var variable in method.Body.Variables)
                EnqueueTypeSignature(variable.Type, reachableTypes, typeWorklist);

            foreach (var handler in method.Body.ExceptionHandlers)
                AddReachableType(handler.CatchType?.ResolveTypeDef(), reachableTypes, typeWorklist);

            foreach (var instr in method.Body.Instructions)
            {
                switch (instr.Operand)
                {
                    case ITypeDefOrRef typeRef:
                        AddReachableType(typeRef.ResolveTypeDef(), reachableTypes, typeWorklist);
                        break;
                    case IMethod calledMethod:
                        AddReachableType(calledMethod.DeclaringType.ResolveTypeDef(), reachableTypes, typeWorklist);
                        EnqueueMethodSignature(calledMethod.MethodSig, reachableTypes, typeWorklist);
                        EnqueueMethod(calledMethod.ResolveMethodDef(), reachableMethods, methodWorklist);
                        break;
                    case IField fieldRef:
                        AddReachableType(fieldRef.DeclaringType.ResolveTypeDef(), reachableTypes, typeWorklist);
                        EnqueueTypeSignature(fieldRef.FieldSig?.Type, reachableTypes, typeWorklist);
                        EnqueueField(fieldRef.ResolveFieldDef(), reachableFields, fieldWorklist);
                        break;
                }
            }
        }

        private static void ProcessReachableField(FieldDef field, HashSet<TypeDef> reachable, Queue<TypeDef> worklist)
        {
            AddReachableType(field.DeclaringType, reachable, worklist);
            EnqueueTypeSignature(field.FieldSig?.Type, reachable, worklist);
        }

        private static void EnqueueTypeRootMembers(
            TypeDef type,
            HashSet<MethodDef> reachableMethods,
            Queue<MethodDef> methodWorklist,
            HashSet<FieldDef> reachableFields,
            Queue<FieldDef> fieldWorklist)
        {
            EnqueueMethod(type.FindStaticConstructor(), reachableMethods, methodWorklist);

            foreach (var method in type.Methods)
            {
                if (IsMethodExternallyVisible(method))
                    EnqueueMethod(method, reachableMethods, methodWorklist);
            }

            foreach (var field in type.Fields)
            {
                if (IsFieldExternallyVisible(field))
                    EnqueueField(field, reachableFields, fieldWorklist);
            }

            foreach (var property in type.Properties)
            {
                if (!IsPropertyExternallyVisible(property))
                    continue;

                EnqueueMethod(property.GetMethod, reachableMethods, methodWorklist);
                EnqueueMethod(property.SetMethod, reachableMethods, methodWorklist);
                foreach (var method in property.OtherMethods)
                    EnqueueMethod(method, reachableMethods, methodWorklist);
            }

            foreach (var evt in type.Events)
            {
                if (!IsEventExternallyVisible(evt))
                    continue;

                EnqueueMethod(evt.AddMethod, reachableMethods, methodWorklist);
                EnqueueMethod(evt.RemoveMethod, reachableMethods, methodWorklist);
                EnqueueMethod(evt.InvokeMethod, reachableMethods, methodWorklist);
                foreach (var method in evt.OtherMethods)
                    EnqueueMethod(method, reachableMethods, methodWorklist);
            }
        }

        private static void EnqueueMethod(MethodDef? method, HashSet<MethodDef> reachableMethods, Queue<MethodDef> methodWorklist)
        {
            if (method is not null && reachableMethods.Add(method))
                methodWorklist.Enqueue(method);
        }

        private static void EnqueueField(FieldDef? field, HashSet<FieldDef> reachableFields, Queue<FieldDef> fieldWorklist)
        {
            if (field is not null && reachableFields.Add(field))
                fieldWorklist.Enqueue(field);
        }

        private static bool IsTypeExternallyVisible(TypeDef type)
        {
            if (type == type.Module.GlobalType)
                return true;

            if (type.IsPublic || type.IsNestedPublic)
                return true;

            return type.IsNestedFamily || type.IsNestedFamilyOrAssembly;
        }

        private static bool IsMethodExternallyVisible(MethodDef method)
        {
            if (method.IsConstructor || method.IsRuntimeSpecialName || method.IsSpecialName)
                return true;

            return method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly || method.IsVirtual || method.IsAbstract;
        }

        private static bool IsFieldExternallyVisible(FieldDef field)
        {
            return field.IsPublic || field.IsFamily || field.IsFamilyOrAssembly;
        }

        private static bool IsPropertyExternallyVisible(PropertyDef property)
        {
            return IsMethodExternallyVisible(property.GetMethod)
                || IsMethodExternallyVisible(property.SetMethod)
                || property.OtherMethods.Any(IsMethodExternallyVisible);
        }

        private static bool IsEventExternallyVisible(EventDef evt)
        {
            return IsMethodExternallyVisible(evt.AddMethod)
                || IsMethodExternallyVisible(evt.RemoveMethod)
                || IsMethodExternallyVisible(evt.InvokeMethod)
                || evt.OtherMethods.Any(IsMethodExternallyVisible);
        }

        private static int RewriteUnusedLocals(ModuleDefMD module)
        {
            int rewritten = 0;

            foreach (var method in module.GetTypes().SelectMany(type => type.Methods))
            {
                if (!method.HasBody || method.Body.Variables.Count == 0)
                    continue;

                var usedLocals = new HashSet<Local>();
                foreach (var instr in method.Body.Instructions)
                {
                    if (!TryGetReferencedLocal(method, instr, out var local))
                        continue;

                    usedLocals.Add(local);
                }

                for (int i = method.Body.Variables.Count - 1; i >= 0; i--)
                {
                    var local = method.Body.Variables[i];
                    if (usedLocals.Contains(local))
                        continue;

                    if (local.Type.ElementType == ElementType.I4)
                        continue;

                    local.Type = module.CorLibTypes.Int32;
                    rewritten++;
                }
            }

            return rewritten;
        }

        private static bool TryGetReferencedLocal(MethodDef method, Instruction instr, out Local local)
        {
            local = null!;

            int index;
            switch (instr.OpCode.Code)
            {
                case Code.Ldloc:
                case Code.Ldloc_S:
                case Code.Ldloc_0:
                case Code.Ldloc_1:
                case Code.Ldloc_2:
                case Code.Ldloc_3:
                    index = Utils.GetLoadLocalIndex(instr);
                    break;
                case Code.Stloc:
                case Code.Stloc_S:
                case Code.Stloc_0:
                case Code.Stloc_1:
                case Code.Stloc_2:
                case Code.Stloc_3:
                    index = Utils.GetStoreLocalIndex(instr);
                    break;
                case Code.Ldloca:
                case Code.Ldloca_S:
                    index = ((Local)instr.Operand).Index;
                    break;
                default:
                    return false;
            }

            if ((uint)index >= (uint)method.Body.Variables.Count)
                return false;

            local = method.Body.Variables[index];
            return true;
        }

        private static IEnumerable<TypeDef> GetProbableEntryPointTypes(ModuleDefMD module)
        {
            foreach (var type in module.Types)
            {
                if (type == module.GlobalType)
                    continue;

                foreach (var method in type.Methods)
                {
                    if (!method.IsStatic || method.MethodSig is null)
                        continue;

                    string signature = method.MethodSig.ToString();
                    if (signature == "System.Int32 (System.String[])" ||
                        signature == "System.Void (System.String[])" ||
                        signature == "System.Int32 ()" ||
                        signature == "System.Void ()")
                    {
                        yield return type;
                        break;
                    }
                }
            }
        }

        private static int RemoveDeadNestedTypes(TypeDef owner, HashSet<TypeDef> reachable)
        {
            if (reachable.Contains(owner))
                return 0;

            int removed = 0;
            foreach (var nested in owner.NestedTypes.ToList())
                removed += RemoveDeadNestedTypes(nested, reachable);

            for (int i = owner.NestedTypes.Count - 1; i >= 0; i--)
            {
                var nested = owner.NestedTypes[i];
                if (reachable.Contains(nested))
                    continue;

                owner.NestedTypes.RemoveAt(i);
                removed++;
            }

            return removed;
        }

        private static void EnqueueMethodSignature(MethodSig? signature, HashSet<TypeDef> reachable, Queue<TypeDef> worklist)
        {
            if (signature is null)
                return;

            EnqueueTypeSignature(signature.RetType, reachable, worklist);
            foreach (var parameter in signature.Params)
                EnqueueTypeSignature(parameter, reachable, worklist);
        }

        private static void EnqueueMethodBodyTypeReferences(MethodDef method, HashSet<TypeDef> reachable, Queue<TypeDef> worklist)
        {
            if (!method.HasBody)
                return;

            foreach (var variable in method.Body.Variables)
                EnqueueTypeSignature(variable.Type, reachable, worklist);

            foreach (var handler in method.Body.ExceptionHandlers)
                AddReachableType(handler.CatchType?.ResolveTypeDef(), reachable, worklist);

            foreach (var instr in method.Body.Instructions)
            {
                switch (instr.Operand)
                {
                    case ITypeDefOrRef typeRef:
                        AddReachableType(typeRef.ResolveTypeDef(), reachable, worklist);
                        break;
                    case IMethod calledMethod:
                        AddReachableType(calledMethod.DeclaringType.ResolveTypeDef(), reachable, worklist);
                        EnqueueMethodSignature(calledMethod.MethodSig, reachable, worklist);
                        break;
                    case IField fieldRef:
                        AddReachableType(fieldRef.DeclaringType.ResolveTypeDef(), reachable, worklist);
                        EnqueueTypeSignature(fieldRef.FieldSig?.Type, reachable, worklist);
                        break;
                }
            }
        }

        private static void EnqueuePropertySignature(PropertyDef property, HashSet<TypeDef> reachable, Queue<TypeDef> worklist)
        {
            EnqueueTypeSignature(property.PropertySig?.RetType, reachable, worklist);
            EnqueueMethodSignature(property.GetMethod?.MethodSig, reachable, worklist);
            EnqueueMethodSignature(property.SetMethod?.MethodSig, reachable, worklist);
            foreach (var method in property.OtherMethods)
                EnqueueMethodSignature(method.MethodSig, reachable, worklist);
        }

        private static void EnqueueGenericParameterConstraints(IList<GenericParam> genericParameters, HashSet<TypeDef> reachable, Queue<TypeDef> worklist)
        {
            foreach (var genericParameter in genericParameters)
            {
                foreach (var constraint in genericParameter.GenericParamConstraints)
                    AddReachableType(constraint.Constraint.ResolveTypeDef(), reachable, worklist);
            }
        }

        private static void EnqueueTypeSignature(TypeSig? signature, HashSet<TypeDef> reachable, Queue<TypeDef> worklist)
        {
            if (signature is null)
                return;

            if (signature.ToTypeDefOrRef() is { } typeRef)
                AddReachableType(typeRef.ResolveTypeDef(), reachable, worklist);

            if (signature.Next is not null)
                EnqueueTypeSignature(signature.Next, reachable, worklist);

            if (signature is GenericInstSig generic)
            {
                foreach (var arg in generic.GenericArguments)
                    EnqueueTypeSignature(arg, reachable, worklist);
            }
        }

        private static void AddReachableType(TypeDef? type, HashSet<TypeDef> reachable, Queue<TypeDef> worklist)
        {
            if (type is null)
                return;

            for (var current = type; current is not null; current = current.DeclaringType)
            {
                if (reachable.Add(current))
                    worklist.Enqueue(current);
            }
        }

    }
}
