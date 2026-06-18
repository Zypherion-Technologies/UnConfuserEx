using dnlib.DotNet;
using dnlib.DotNet.Writer;
using log4net;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UnConfuserEx.Protections.Renamer;

namespace UnConfuserEx.Protections
{
    internal class UnicodeRemover : IProtection
    {
        private static readonly ILog Logger = LogManager.GetLogger("Renamer");

        public string Name => "Renamer";

        private ModuleDefMD? Module = null;
        private Dictionary<TypeDef, TypeInfo> NewTypeInfo = new();

        public bool IsPresent(ref ModuleDefMD module)
        {
            return true;
        }

        public bool Remove(ref ModuleDefMD module)
        {
            Module = module;

            RenameTypeDefs();
            RenameTypeRefs();
            RenameMemberRefs();

            return true;
        }

        private void RenameTypeDefs()
        {
            foreach (var type in Module!.GetTypes())
            {
                NewTypeInfo[type] = new TypeInfo(type);
            }
        }

        private void RenameTypeRefs()
        {
            foreach (var typeRef in Module!.GetTypeRefs())
            {
                if (Utils.IsInvalidName(typeRef.Name))
                {
                    throw new NotImplementedException();
                }
            }
        }

        private void RenameMemberRefs()
        {
            foreach (var methodDef in Module!.GetTypes().SelectMany(type => type.Methods))
            {
                foreach (var ov in methodDef.Overrides)
                {
                    RenameMemberRef(ov.MethodBody);
                    RenameMemberRef(ov.MethodDeclaration);
                }

                if (!methodDef.HasBody)
                {
                    continue;
                }

                foreach (var instr in methodDef.Body.Instructions)
                {
                    if (instr.Operand is MemberRef || instr.Operand is MethodSpec)
                    {
                        RenameMemberRef((IMemberRef)instr.Operand);
                    }
                }
            }
        }

        private void RenameMemberRef(IMemberRef memberRef)
        {
            if (!Utils.IsInvalidName(memberRef.Name))
                return;

            TypeDef? declaringType = null;
            try
            {
                declaringType = memberRef.DeclaringType.ResolveTypeDef();
            }
            catch (TypeResolveException ex)
            {
                Logger.Warn($"Skipping unresolved member ref {memberRef.FullName} ({ex.Message})");
                return;
            }

            if (declaringType == null || !NewTypeInfo.TryGetValue(declaringType, out var typeInfo))
            {
                Logger.Warn($"Skipping member ref with unresolved declaring type {memberRef.FullName}");
                return;
            }

            if (memberRef.IsField)
            {
                if (typeInfo.FieldNames.TryGetValue(memberRef.Name, out var fieldName))
                    memberRef.Name = fieldName;
                else
                    Logger.Warn($"Skipping unknown field ref {memberRef.FullName}");
            }
            else if (memberRef.IsMethod)
            {
                if (typeInfo.MethodNames.TryGetValue(memberRef.Name, out var methodName))
                    memberRef.Name = methodName;
                else
                    Logger.Warn($"Skipping unknown method ref {memberRef.FullName}");
            }
            else
            {
                Logger.Warn($"Skipping unsupported member ref {memberRef.FullName}");
            }
        }
    }
}
