// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "compiler/mir/basic_block.h"
#include "compiler/mir/function.h"
#include "compiler/mir/instruction.h"
#include "compiler/mir/instructions.h"
#include "compiler/mir/module.h"
#include "llvm/ADT/BitVector.h"

namespace COMPILER {

/// DeadMCodeElim — eliminate dead DASSIGN statements whose target variable
/// is never read by any DREAD in the function.
///
/// This is a conservative per-function DCE that:
///   1. Collects all variable indices that appear in DREAD instructions
///      (including DREADs nested inside expression trees).
///   2. Removes DASSIGN statements whose target variable is not in the
///      "read" set.
///   3. Removes the freed DASSIGN instructions from MFunction::Instructions.
///
/// Limitations (by design, for safety):
///   - Does NOT recursively delete the operand expression trees of dead
///     DASSIGNs, because the MIR's single-parent-pointer model makes it
///     difficult to determine whether an expression has other users.
///   - Does NOT eliminate dead PHI incoming values or trivial PHIs.
///   - Does NOT perform cross-BB liveness analysis (a variable written in
///     one BB and never read anywhere is dead; a variable written and read
///     within the same BB could be further optimized with local DCE, but
///     this pass is intentionally global and simple).
///
/// Expected impact: reduces the number of DASSIGN statements flowing into
/// the cgIR lowering and register allocator, lowering register pressure
/// especially for EVM U256 operations that produce 4-limb temporaries.
class DeadMCodeElim {
public:
  void runOnMFunction(MFunction &F) {
    uint32_t NumVars = F.getNumVariables();
    if (NumVars == 0) {
      return;
    }

    // Phase 1: Collect all variable indices that are READ.
    // DREAD instructions are expression nodes (IsStmt=false), so they live
    // in MFunction::Instructions but NOT in BB statement lists.
    llvm::BitVector ReadVars(NumVars, false);

    for (const MInstruction *Inst : F.getInstructions()) {
      if (Inst->getOpcode() == OP_dread) {
        auto *Dread = static_cast<const DreadInstruction *>(Inst);
        ReadVars.set(Dread->getVarIdx());
      }
    }

    // Phase 2: Identify dead DASSIGN statements and remove them from BBs.
    // DASSIGN instructions are statements (IsStmt=true), so they appear in
    // BB statement lists.  We collect dead instructions first, then remove
    // them, to avoid iterator invalidation during removal.
    llvm::SmallVector<MInstruction *, 64> DeadInsts;

    for (MBasicBlock *BB : F) {
      for (MInstruction *Inst : *BB) {
        if (Inst->getOpcode() == OP_dassign) {
          auto *Dassign = static_cast<DassignInstruction *>(Inst);
          if (!ReadVars.test(Dassign->getVarIdx())) {
            DeadInsts.push_back(Inst);
          }
        }
      }
    }

    if (DeadInsts.empty()) {
      return;
    }

    // Phase 3: Remove dead DASSIGNs from their BBs and from the function's
    // instruction list.
    for (MInstruction *DeadInst : DeadInsts) {
      // Remove from parent BB's statement list by iterating and erasing.
      MBasicBlock *ParentBB = DeadInst->getParentBB();
      for (auto It = ParentBB->begin(); It != ParentBB->end(); ++It) {
        if (*It == DeadInst) {
          // MBasicBlock::Statements is a CompileList (std::list), so we can
          // erase via the BB's public iterator type.
          // We use a const_cast to access the underlying list iterator for
          // erasure, since begin()/end() return the list iterator directly.
          auto ListIt = It;
          ParentBB->eraseStatement(ListIt);
          break;
        }
      }
      // Remove from MFunction's instruction list and free.
      F.deleteInstruction(DeadInst);
    }

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    llvm::dbgs() << "\n########## MIR Dump After Dead MCode Elimination ("
                 << DeadInsts.size() << " DASSIGNs removed) ##########\n\n";
    F.dump();
#endif
  }
};

} // namespace COMPILER
