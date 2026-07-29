namespace UnConfuserEx
{
    internal static class RuntimeOptions
    {
        public static bool RebuildEmbeddedPe { get; set; }
        public static bool EnableSerializedResourceDeserialization { get; set; }

        /// <summary>
        /// Also rewrite short, meaningless-but-legal identifiers (a, A, b, B …)
        /// into generated placeholder names. Off by default: those names are
        /// valid identifiers, so leaving them alone is the conservative choice.
        /// Turning this on trades "short and ambiguous" for "long and unique",
        /// which mainly helps when the obfuscator emitted case-only collisions
        /// such as namespace <c>a</c> alongside namespace <c>A</c>.
        /// </summary>
        public static bool RenameShortNames { get; set; }
    }
}
