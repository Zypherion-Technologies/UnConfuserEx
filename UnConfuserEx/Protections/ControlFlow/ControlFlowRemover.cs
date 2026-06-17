using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using log4net;
using UnConfuserEx.Protections.ControlFlow;
using de4dot.blocks;
using de4dot.blocks.cflow;

namespace UnConfuserEx.Protections
{
    internal class ControlFlowRemover : IProtection
    {
        static ILog Logger = LogManager.GetLogger("ControlFlow");

        public string Name => "ControlFlow";

        private readonly IList<MethodDef> ObfuscatedMethods = new List<MethodDef>();

        public bool IsPresent(ref ModuleDefMD module)
        {
            ObfuscatedMethods.Clear();
            /*
             * Go through all of the methods in the module
             * if they all contain a switch then it's present
             */
            foreach (var method in module.GetTypes().SelectMany(t => t.Methods))
            {
                if (IsMethodObfuscated(method))
                {
                    ObfuscatedMethods.Add(method);
                }
            }

            Logger.Debug($"ControlFlow detection marked {ObfuscatedMethods.Count} method(s) as obfuscated");
            return ObfuscatedMethods.Any();
        }

        public bool Remove(ref ModuleDefMD module)
        {
            int numSolved = 0;
            int numFailed = 0;
            int numPartial = 0;

            Logger.Debug($"Found {ObfuscatedMethods.Count} obfuscated methods");
            foreach (var method in ObfuscatedMethods)
            {
                var snapshot = SnapshotBody(method);
                try
                {
                    Logger.Debug($"Removing obfuscation from method {method.FullName}");
                    Logger.Debug($"Method starts with {method.Body.Instructions.Count} instruction(s) and {method.Body.ExceptionHandlers.Count} handler(s)");

                    var deobfuscatedBlocks = DeobfuscateMethod(ref module, method);

                    IList<Instruction> instructions;
                    IList<ExceptionHandler> exceptionHandlers;
                    deobfuscatedBlocks.GetCode(out instructions, out exceptionHandlers);
                    DotNetUtils.RestoreBody(method, instructions, exceptionHandlers);

                    if (IsMethodObfuscated(method))
                    {
                        RestoreSnapshot(method, snapshot);
                        Logger.Warn($"Method {method.FullName} still appears obfuscated after deobfuscation — left original body intact");
                        numPartial++;
                        continue;
                    }

                    Logger.Debug($"Method {method.FullName} now has {method.Body.Instructions.Count} instruction(s) after deobfuscation");

                    numSolved++;
                }
                catch (Exception ex)
                {
                    RestoreSnapshot(method, snapshot);
                    Logger.Error($"Failed to remove obfuscation for method {method.FullName} ({ex.Message})");
                    Logger.Error(ex.ToString());
                    numFailed++;
                }
            }

            var msg = $"Removed obfuscation from {numSolved} methods. Failed to remove from {numFailed} methods. {numPartial} methods left untouched";
            if (numFailed > 0 || numPartial > 0)
            {
                Logger.Warn(msg);
            }
            else
            {
                Logger.Debug(msg);
            }
            return true;
        }

        private static (IList<Instruction>, IList<ExceptionHandler>) SnapshotBody(MethodDef method)
        {
            return (method.Body.Instructions.ToList(), method.Body.ExceptionHandlers.ToList());
        }

        private static void RestoreSnapshot(MethodDef method, (IList<Instruction>, IList<ExceptionHandler>) snapshot)
        {
            DotNetUtils.RestoreBody(method, snapshot.Item1, snapshot.Item2);
        }

        public static bool IsMethodObfuscated(MethodDef method)
        {
            if (!method.HasBody || method.Body.Instructions.Count == 0)
                return false;


            var instrs = method.Body.Instructions.ToList();
            return IsSwitchObfuscation(instrs) || IsJumpObfuscation(method);
        }
        // NOT TESTED PROPERLY!
        public static bool IsJumpObfuscation(MethodDef method)
        {
            if (!method.HasBody || method.Body.Instructions.Count < 8)
            {
                return false;
            }

            var blocks = new Blocks(method);
            blocks.RemoveDeadBlocks();
            blocks.RepartitionBlocks();
            blocks.UpdateBlocks();

            int trampolineBlocks = blocks.MethodBlocks.GetAllBlocks().Count(JumpDeobfuscator.IsTrampolineBlock);
            return trampolineBlocks >= 2;
        }

        public static bool IsSwitchObfuscation(List<Instruction> instrs)
        {
            if (instrs.Count < 3)
            {
                return false;
            }

            for (int i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode == OpCodes.Switch
                    && instrs[i - 1].OpCode == OpCodes.Rem_Un
                    && instrs[i - 2].IsLdcI4()
                    && instrs[i].Operand is Instruction[] cases
                    && cases.Length == instrs[i - 2].GetLdcI4Value())
                {
                    return true;
                }
            }
            return false;
        }

        public static Blocks DeobfuscateMethod(ref ModuleDefMD module, MethodDef method)
        {
            var deobfuscator = new BlocksCflowDeobfuscator();
            var blocks = new Blocks(method);
            blocks.RemoveDeadBlocks();
            blocks.RepartitionBlocks();
            blocks.UpdateBlocks();

            blocks.Method.Body.SimplifyBranches();
            blocks.Method.Body.OptimizeBranches();

            deobfuscator.Initialize(blocks);
            deobfuscator.Add(new SwitchDeobfuscator(module));
            deobfuscator.Add(new JumpDeobfuscator(module));
            deobfuscator.Deobfuscate();

            blocks.RepartitionBlocks();

            return blocks;
        }
    }
}
