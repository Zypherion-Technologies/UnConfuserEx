using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using System.Collections.Generic;
using UnConfuserEx.Protections;
using log4net;
using log4net.Config;
using UnConfuserEx.Protections.Delegates;
using UnConfuserEx.Protections.AntiDebug;
using UnConfuserEx.Protections.AntiDump;
using UnConfuserEx.Protections.AntiTamper;
using UnConfuserEx.Protections.Compressor;
using dnlib.DotNet.Emit;

namespace UnConfuserEx
{
    internal class UnConfuserEx
    {
        static ILog Logger = LogManager.GetLogger("UnConfuserEx");

        internal static void NormalizeMethodBodiesForWrite(ModuleDef module)
        {
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    var body = method.Body;
                    if (body == null)
                        continue;

                    body.SimplifyBranches();
                    body.OptimizeBranches();
                }
            }
        }

        internal static void PrepareModuleForWrite(ModuleDef module)
        {
            NormalizeMethodBodiesForWrite(module);
        }

        sealed class FailureInfo
        {
            public required string ProtectionName { get; init; }
            public required string Stage { get; init; }
            public required string Message { get; init; }
            public string? ExceptionType { get; init; }
        }

        static void LogFailureSummary(string inputPath, string outputPath, ModuleDefMD module, IList<string> detectedProtections, IList<FailureInfo> failures)
        {
            Logger.Warn("----- FAILURE SUMMARY BEGIN -----");
            Logger.Warn($"Input path: {inputPath}");
            Logger.Warn($"Output path: {outputPath}");
            Logger.Warn($"Module kind: {module.Kind}");
            Logger.Warn($"IL only: {module.IsILOnly}");
            Logger.Warn($"Entry point: {(module.EntryPoint?.FullName ?? "<null>")}");
            Logger.Warn($"Detected protections: {(detectedProtections.Count == 0 ? "<none>" : string.Join(", ", detectedProtections))}");
            Logger.Warn($"Failure count: {failures.Count}");

            for (int i = 0; i < failures.Count; i++)
            {
                var failure = failures[i];
                Logger.Warn($"Failure {i + 1}:");
                Logger.Warn($"  Protection: {failure.ProtectionName}");
                Logger.Warn($"  Stage: {failure.Stage}");
                Logger.Warn($"  Message: {failure.Message}");
                if (!string.IsNullOrWhiteSpace(failure.ExceptionType))
                    Logger.Warn($"  Exception type: {failure.ExceptionType}");
            }

            Logger.Warn("If you open an issue, include the full console output and say whether the failure happened during detection, removal, writing output, or runtime after deobfuscation.");
            Logger.Warn("----- FAILURE SUMMARY END -----");
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

        private const int STD_OUTPUT_HANDLE = -11;
        private const int STD_ERROR_HANDLE = -12;
        private const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;

        private static void EnableVirtualTerminal()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return;

            foreach (var handleId in new[] { STD_OUTPUT_HANDLE, STD_ERROR_HANDLE })
            {
                var handle = GetStdHandle(handleId);
                if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                    continue;
                if (!GetConsoleMode(handle, out uint mode))
                    continue;
                SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }

        static int Main(string[] args)
        {
            EnableVirtualTerminal();
            XmlConfigurator.Configure(typeof(UnConfuserEx).Assembly.GetManifestResourceStream("UnConfuserEx.log4net.xml"));

            string? pathArg = null;
            string? outputArg = null;
            RuntimeOptions.RebuildEmbeddedPe = false;
            RuntimeOptions.EnableSerializedResourceDeserialization = false;
            RuntimeOptions.RenameShortNames = false;

            foreach (var arg in args)
            {
                if (arg.Equals("--rebuild-embedded-pe", StringComparison.OrdinalIgnoreCase))
                {
                    RuntimeOptions.RebuildEmbeddedPe = true;
                    continue;
                }

                if (arg.Equals("--enable-serialized-resources", StringComparison.OrdinalIgnoreCase))
                {
                    RuntimeOptions.EnableSerializedResourceDeserialization = true;
                    continue;
                }

                if (arg.Equals("--rename-short-names", StringComparison.OrdinalIgnoreCase))
                {
                    RuntimeOptions.RenameShortNames = true;
                    continue;
                }

                if (arg.StartsWith("-", StringComparison.Ordinal))
                {
                    Logger.Error($"Unknown option: {arg}");
                    Logger.Error("Usage: unconfuser.exe <module path> <output path> [--rebuild-embedded-pe] [--enable-serialized-resources] [--rename-short-names]");
                    return 1;
                }

                if (pathArg is null)
                {
                    pathArg = arg;
                }
                else if (outputArg is null)
                {
                    outputArg = arg;
                }
                else
                {
                    Logger.Error("Usage: unconfuser.exe <module path> <output path> [--rebuild-embedded-pe] [--enable-serialized-resources] [--rename-short-names]");
                    return 1;
                }
            }

            if (pathArg is null)
            {
                Logger.Error("Usage: unconfuser.exe <module path> <output path> [--rebuild-embedded-pe] [--enable-serialized-resources] [--rename-short-names]");
                return 1;
            }

            if (RuntimeOptions.EnableSerializedResourceDeserialization)
                AppContext.SetSwitch("System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization", true);

            var path = Path.GetFullPath(pathArg);
            if (!File.Exists(path))
            {
                Logger.Error($"File {path} does not exist");
                return 1;
            }

            // Load the module
            ModuleContext context = new();
            ModuleDefMD module = ModuleDefMD.Load(path, context);

            var pipeline = new List<IProtection>
            {
                new CompressorRemover(),
                new JITAntiTamperRemover(),
                new AntiTamperRemover(),

                new ControlFlowRemover(),

                new ResourcesRemover(),
                new ConstantsRemover(),
                new RefProxyRemover(),
                new AntiDumpRemover(),
                new UnicodeRemover(),

                new AntiDebugRemover(),
                new StaticCleanupRemover(),
            };

            List<string> detectedProtections = new();
            List<FailureInfo> failures = new();
            foreach (var p in pipeline)
            {
                var stopwatch = Stopwatch.StartNew();
                bool present;
                try
                {
                    present = p.IsPresent(ref module);
                }
                catch (Exception ex)
                {
                    stopwatch.Stop();
                    Logger.Error($"Detection for {p.Name} threw — skipping ({ex.Message})");
                    Logger.Error(ex.ToString());
                    failures.Add(new FailureInfo
                    {
                        ProtectionName = p.Name,
                        Stage = "detection",
                        Message = ex.Message,
                        ExceptionType = ex.GetType().FullName
                    });
                    continue;
                }

                stopwatch.Stop();
                Logger.Debug($"Detection for {p.Name}: present={present} elapsed={stopwatch.ElapsedMilliseconds}ms");

                if (!present) continue;
                detectedProtections.Add(p.Name);

                Logger.Info($"{p.Name} detected, attempting to remove");
                stopwatch.Restart();
                try
                {
                    if (p.Remove(ref module))
                    {
                        stopwatch.Stop();
                        Logger.Debug($"Removal for {p.Name} completed in {stopwatch.ElapsedMilliseconds}ms");
                        Logger.Info($"Successfully removed {p.Name} protection");
                    }
                    else
                    {
                        stopwatch.Stop();
                        Logger.Warn($"Removal for {p.Name} returned false after {stopwatch.ElapsedMilliseconds}ms");
                        Logger.Error($"Failed to remove {p.Name} protection — continuing with remaining protections");
                        failures.Add(new FailureInfo
                        {
                            ProtectionName = p.Name,
                            Stage = "removal",
                            Message = "Remove() returned false"
                        });
                    }
                }
                catch (Exception ex)
                {
                    stopwatch.Stop();
                    Logger.Fatal($"Caught exception when trying to remove {p.Name} protection");
                    Logger.Error(ex.ToString());
                    failures.Add(new FailureInfo
                    {
                        ProtectionName = p.Name,
                        Stage = "removal",
                        Message = ex.Message,
                        ExceptionType = ex.GetType().FullName
                    });
                }
            }

            if (failures.Count > 0)
            {
                Logger.Warn($"{failures.Count} protection(s) could not be removed cleanly. Writing best-effort output anyway");
            }

            if ((module.Kind == ModuleKind.Console || module.Kind == ModuleKind.Windows)
                && module.EntryPoint == null)
            {
                MethodDef? best = null;
                int bestScore = -1;
                foreach (var t in module.GetTypes())
                {
                    foreach (var m in t.Methods)
                    {
                        if (!m.IsStatic || !m.HasBody || m.IsSpecialName || m.MethodSig == null)
                            continue;
                        var sig = m.MethodSig.ToString();
                        int score = sig switch
                        {
                            "System.Int32 (System.String[])" => 4,
                            "System.Void (System.String[])" => 3,
                            "System.Int32 ()" => 2,
                            "System.Void ()" => 1,
                            _ => 0
                        };
                        if (score == 0) continue;
                        if (m.Name == "Main" || m.Name == "<Main>$") score += 10;
                        if (score > bestScore)
                        {
                            bestScore = score;
                            best = m;
                        }
                    }
                }
                if (best != null)
                {
                    module.EntryPoint = best;
                    Logger.Info($"Recovered entry point via heuristic: {best.FullName}");
                }
            }

            var newPath = $"{Path.GetDirectoryName(path)}\\{Path.GetFileNameWithoutExtension(path)}-deobfuscated{Path.GetExtension(path)}";
            if (!string.IsNullOrWhiteSpace(outputArg))
            {
                newPath = outputArg;
            }

            if (failures.Count > 0)
            {
                LogFailureSummary(
                    path,
                    newPath,
                    module,
                    detectedProtections,
                    failures
                );
            }

            Logger.Info($"All detected protections removed. Writing new module to {newPath}");

            try
            {
                PrepareModuleForWrite(module);

                if (module.IsILOnly)
                {
                    ModuleWriterOptions writerOptions = new ModuleWriterOptions(module);
                    writerOptions.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
                    module.Write(newPath, writerOptions);
                }
                else
                {
                    NativeModuleWriterOptions writerOptions = new NativeModuleWriterOptions(module, true);
                    writerOptions.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
                    //writerOptions.Logger = DummyLogger.NoThrowInstance;
                    module.NativeWrite(newPath, writerOptions);
                }
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to write module");
                Logger.Error(ex.ToString());
                failures.Add(new FailureInfo
                {
                    ProtectionName = "module writer",
                    Stage = "writing output",
                    Message = ex.Message,
                    ExceptionType = ex.GetType().FullName
                });
                LogFailureSummary(path, newPath, module, detectedProtections, failures);
                return 1;
            }
            Logger.Info("Deobfuscated module successfully written");

            return 0;
        }

    }
}
