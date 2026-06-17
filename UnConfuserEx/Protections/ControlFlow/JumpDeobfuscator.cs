using de4dot.blocks;
using de4dot.blocks.cflow;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using log4net;
using System.Collections.Generic;
using System.Linq;

namespace UnConfuserEx.Protections.ControlFlow
{
    internal class JumpDeobfuscator : BlockDeobfuscator
    {
        static ILog Logger = LogManager.GetLogger("ControlFlow");

        private ModuleDefMD Module;
        private bool loggedCandidate;
        private int rewrites;

        public JumpDeobfuscator(ModuleDefMD module)
        {
            Module = module;
        }

        public override void DeobfuscateBegin(Blocks blocks)
        {
            base.DeobfuscateBegin(blocks);
            rewrites = 0;
        }

        protected override bool Deobfuscate(Block block)
        {
            if (!loggedCandidate && block != null && block.Instructions.Count > 0)
            {
                loggedCandidate = true;
                Logger.Debug($"JumpDeobfuscator inspected block with {block.Instructions.Count} instruction(s) in module {Module.Name}");
            }

            if (!TryResolveTrampolineTarget(block, out var finalTarget) || finalTarget == null)
            {
                return false;
            }

            bool modified = false;
            foreach (var source in block.Sources.ToList())
            {
                if (source == block || source == finalTarget)
                {
                    continue;
                }

                if (source.FallThrough == block)
                {
                    source.SetNewFallThrough(finalTarget);
                    modified = true;
                }

                if (source.Targets != null)
                {
                    for (int i = 0; i < source.Targets.Count; i++)
                    {
                        if (source.Targets[i] == block)
                        {
                            source.SetNewTarget(i, finalTarget);
                            modified = true;
                        }
                    }
                }
            }

            if (modified)
            {
                rewrites++;
                Logger.Debug($"JumpDeobfuscator rewired trampoline block to {finalTarget.FirstInstr.Instruction.Offset:X4} in module {Module.Name} (total rewrites={rewrites})");
            }

            return modified;
        }

        internal static bool IsTrampolineBlock(Block block)
        {
            return TryResolveTrampolineTarget(block, out _);
        }

        private static bool TryResolveTrampolineTarget(Block block, out Block? finalTarget)
        {
            finalTarget = null;

            if (!IsPureBranchTrampoline(block))
            {
                return false;
            }

            var seen = new HashSet<Block> { block };
            var current = block.GetOnlyTarget();
            while (current != null && seen.Add(current) && IsPureBranchTrampoline(current))
            {
                current = current.GetOnlyTarget();
            }

            if (current == null || current == block)
            {
                return false;
            }

            finalTarget = current;
            return true;
        }

        private static bool IsPureBranchTrampoline(Block block)
        {
            if (block.Targets == null || block.Targets.Count != 1 || block.FallThrough != null)
            {
                return false;
            }

            if (!block.LastInstr.IsBr())
            {
                return false;
            }

            for (int i = 0; i < block.Instructions.Count - 1; i++)
            {
                if (!block.Instructions[i].IsNop())
                {
                    return false;
                }
            }

            return true;
        }
    }
}
