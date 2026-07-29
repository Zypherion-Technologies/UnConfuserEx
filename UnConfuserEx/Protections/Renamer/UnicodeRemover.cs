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

            RenameNamespaces();
            RenameTypeDefs();
            RenameTypeRefs();
            RenameMemberRefs();

            return true;
        }

        /// <summary>
        /// Collapses obfuscated namespaces onto generated names. Only namespaces
        /// whose every segment is a short placeholder are touched, so a real
        /// namespace is never rewritten just because one segment is terse.
        ///
        /// This is what removes the "namespace a sitting next to namespace A"
        /// effect — they are distinct namespaces (identifiers are case
        /// sensitive) but read as duplicates in a decompiler tree.
        /// </summary>
        private void RenameNamespaces()
        {
            if (!RuntimeOptions.RenameShortNames)
                return;

            var replacements = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (var type in Module!.GetTypes())
            {
                if (type.IsGlobalModuleType || type.IsNested)
                    continue;

                var ns = type.Namespace?.String;
                if (string.IsNullOrEmpty(ns))
                    continue;

                if (!ns.Split('.').All(Utils.IsMeaninglessName))
                    continue;

                if (!replacements.TryGetValue(ns, out var replacement))
                {
                    replacement = "Namespace" + replacements.Count;
                    replacements[ns] = replacement;
                }

                type.Namespace = replacement;
            }

            if (replacements.Count > 0)
            {
                Logger.Debug($"Renamed {replacements.Count} obfuscated namespace(s): "
                    + string.Join(", ", replacements.Select(kv => $"{kv.Key} -> {kv.Value}")));
            }
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
            // An illegal name always has to be fixed. A merely short one is only
            // in scope when short-name renaming is on — and because plenty of
            // *external* members legitimately have short names, a miss there is
            // expected and stays quiet rather than warning on every one.
            bool hasInvalidName = Utils.IsInvalidName(memberRef.Name);
            bool hasShortName = RuntimeOptions.RenameShortNames && Utils.IsMeaninglessName(memberRef.Name);
            if (!hasInvalidName && !hasShortName)
                return;

            TypeDef? declaringType = null;
            try
            {
                declaringType = memberRef.DeclaringType.ResolveTypeDef();
            }
            catch (TypeResolveException ex)
            {
                if (hasInvalidName)
                    Logger.Warn($"Skipping unresolved member ref {memberRef.FullName} ({ex.Message})");
                return;
            }

            if (declaringType == null || !NewTypeInfo.TryGetValue(declaringType, out var typeInfo))
            {
                if (hasInvalidName)
                    Logger.Warn($"Skipping member ref with unresolved declaring type {memberRef.FullName}");
                return;
            }

            if (memberRef.IsField)
            {
                if (typeInfo.FieldNames.TryGetValue(memberRef.Name, out var fieldName))
                    memberRef.Name = fieldName;
                else if (hasInvalidName)
                    Logger.Warn($"Skipping unknown field ref {memberRef.FullName}");
            }
            else if (memberRef.IsMethod)
            {
                if (typeInfo.MethodNames.TryGetValue(memberRef.Name, out var methodName))
                    memberRef.Name = methodName;
                else if (hasInvalidName)
                    Logger.Warn($"Skipping unknown method ref {memberRef.FullName}");
            }
            else if (hasInvalidName)
            {
                Logger.Warn($"Skipping unsupported member ref {memberRef.FullName}");
            }
        }
    }
}
