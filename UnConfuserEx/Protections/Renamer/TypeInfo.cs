using dnlib.DotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UnConfuserEx.Protections.Renamer
{
    internal class TypeInfo
    {
        private readonly TypeDef Type;
        public string OriginalName;
        public string NewName;

        /// <summary>
        /// True when this type's own name is obfuscator output rather than
        /// something a human wrote. Gates short-name renaming of its members.
        /// </summary>
        private readonly bool IsPlaceholderType;

        public Dictionary<UTF8String, string> FieldNames = new();
        public Dictionary<UTF8String, string> MethodNames = new();
        public Dictionary<UTF8String, string> PropNames = new();
        public Dictionary<UTF8String, string> GenericParamNames = new();

        public TypeInfo(TypeDef type)
        {
            Type = type;
            NewName = OriginalName = type.Name;


            // Short member names are only placeholders when the type holding
            // them is itself a placeholder. A renamer rewrites a type and its
            // members together, so a type that kept a real name (TBHAfkMod.
            // AfkComponent) kept real member names too — and plenty of those
            // are legitimately two characters: Go, Id, X, Y, To, OK. Renaming
            // on length alone destroys them.
            IsPlaceholderType = Utils.IsInvalidName(OriginalName)
                || (RuntimeOptions.RenameShortNames && Utils.IsMeaninglessName(OriginalName));

            RenameGenericParameters();
            RenameMethods();
            RenameFields();
            RenameProperties();

            // The global <Module> type must keep its name — it is looked up by
            // name, not token, and renaming it produces a non-conformant image.
            if (ShouldRename(OriginalName) && !type.IsGlobalModuleType)
            {
                NewName = TypeRenamer.GetRenamer(type).Generate();
                if (type.HasGenericParameters)
                {
                    NewName += "`" + Type.GenericParameters.Count;
                }
                type.Name = NewName;
            }

        }

        /// <summary>
        /// A name is rewritten when it is structurally illegal (unprintable /
        /// punctuation-laden, the usual ConfuserEx unicode output) or — only
        /// when the user opted in — when it is a short all-letter placeholder.
        /// </summary>
        private static bool ShouldRename(string name)
        {
            return Utils.IsInvalidName(name)
                || (RuntimeOptions.RenameShortNames && Utils.IsMeaninglessName(name));
        }

        /// <summary>
        /// Short-name renaming is deliberately skipped for anything that can be
        /// bound by name at runtime rather than by token: virtual/abstract
        /// members and explicit overrides participate in dispatch, and an
        /// implicit interface implementation is matched on name + signature, so
        /// renaming one side of that pair silently breaks the implementation.
        /// P/Invoke entry points and .ctor/.cctor are likewise off limits.
        /// </summary>
        private bool CanRenameMethodByShortName(MethodDef method)
        {
            if (!RuntimeOptions.RenameShortNames || !IsPlaceholderType || !Utils.IsMeaninglessName(method.Name))
                return false;

            return !method.IsVirtual
                && !method.IsAbstract
                && !method.IsConstructor
                && !method.IsStaticConstructor
                && !method.IsRuntimeSpecialName
                && !method.IsSpecialName
                && method.Overrides.Count == 0
                && method.ImplMap == null;
        }

        private bool CanRenameFieldByShortName(FieldDef field)
        {
            if (!RuntimeOptions.RenameShortNames || !IsPlaceholderType || !Utils.IsMeaninglessName(field.Name))
                return false;

            // Enum members carry meaning in their names, and value__ is fixed.
            return !field.IsRuntimeSpecialName
                && !field.IsSpecialName
                && !field.DeclaringType.IsEnum;
        }

        private void RenameGenericParameters()
        {
            if (Type.HasGenericParameters)
            {
                if (Type.GenericParameters.Count == 1)
                {
                    GenericParamNames[Type.GenericParameters[0].Name] = "T";
                    Type.GenericParameters[0].Name = "T";
                }
                else
                {
                    var count = 0;
                    foreach (var param in Type.GenericParameters)
                    {
                        GenericParamNames[param.Name] = "T" + count;
                        param.Name = "T" + count++;
                    }
                }
            }
        }

        private void RenameMethods()
        {
            var staticCount = 0;
            var count = 0;
            foreach (var method in Type.Methods)
            {
                if (Utils.IsInvalidName(method.Name) || CanRenameMethodByShortName(method))
                {

                    string newName;
                    if (method.ImplMap != null)
                    {
                        newName = method.ImplMap.Name;
                    }
                    else if (method.IsStatic)
                    {
                        newName = "StaticMethod" + staticCount++;
                    }
                    else
                    {
                        newName = "Method" + count++;
                    }

                    MethodNames[method.Name] = newName;
                    method.Name = newName;
                }

                var paramCount = 0;
                foreach (var param in method.Parameters)
                {
                    if (param.Name == "")
                    {
                        if (!param.HasParamDef)
                        {
                            param.CreateParamDef();
                        }
                        param.ParamDef.Name = "A_" + paramCount++;
                    }
                }

                if (method.HasGenericParameters)
                {
                    if (method.GenericParameters.Count == 1)
                    {
                        method.GenericParameters[0].Name = "T";
                    }
                    else
                    {
                        var genericParamCount = 0;
                        foreach (var param in method.GenericParameters)
                        {
                            param.Name = "T" + genericParamCount++;
                        }
                    }
                }

            }
        }

        private void RenameFields()
        {
            var count = 0;
            foreach (var field in Type.Fields)
            {
                if (Utils.IsInvalidName(field.Name) || CanRenameFieldByShortName(field))
                {
                    var newName = "Field" + count++;

                    FieldNames[field.Name] = newName;
                    field.Name = newName;
                }
            }
        }

        private void RenameProperties()
        {
            var count = 0;
            foreach (var prop in Type.Properties)
            {
                if (Utils.IsInvalidName(prop.Name))
                {
                    var newName = "Prop" + count++;

                    PropNames[prop.Name] = newName;
                    prop.Name = newName;
                }
            }
        }

    }
}
