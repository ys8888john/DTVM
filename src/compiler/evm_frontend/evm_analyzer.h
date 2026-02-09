// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_ANALYZER_H
#define EVM_FRONTEND_EVM_ANALYZER_H

#include "compiler/common/common_defs.h"
#include "evm/evm.h"
#include "evmc/evmc.h"
#include "evmc/instructions.h"

namespace COMPILER {

class EVMAnalyzer {
  using Byte = zen::common::Byte;
  using Bytes = zen::common::Bytes;

public:
  EVMAnalyzer(evmc_revision Rev = zen::evm::DEFAULT_REVISION) : Revision(Rev) {}

  struct BlockInfo {
    uint64_t EntryPC = 0;
    int32_t MaxStackHeight = 0;
    int32_t MinStackHeight = 0;
    int32_t MinPopHeight = 0;
    int32_t StackHeightDiff = 0;
    bool IsJumpDest = false;
    bool HasUndefinedInstr = false;

    BlockInfo() = default;
    BlockInfo(uint64_t PC) : EntryPC(PC) {}
  };

  const std::map<uint64_t, BlockInfo> &getBlockInfos() const {
    return BlockInfos;
  }

  bool analyze(const uint8_t *Bytecode, size_t BytecodeSize) {
    BlockInfos.clear();
    const uint8_t *Ip = Bytecode;
    const uint8_t *IpEnd = Bytecode + BytecodeSize;

    // Get instruction tables based on revision
    const auto *InstructionMetrics =
        evmc_get_instruction_metrics_table(Revision);
    const auto *InstructionNames = evmc_get_instruction_names_table(Revision);
    if (!InstructionMetrics) {
      InstructionMetrics =
          evmc_get_instruction_metrics_table(zen::evm::DEFAULT_REVISION);
    }
    if (!InstructionNames) {
      InstructionNames =
          evmc_get_instruction_names_table(zen::evm::DEFAULT_REVISION);
    }

    // Initialize block info for the first block
    BlockInfo CurInfo(0);

    while (Ip < IpEnd) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(*Ip);
      ptrdiff_t Diff = Ip - Bytecode;
      PC = static_cast<uint64_t>(Diff >= 0 ? Diff : 0);

      Ip++;

      // Check if opcode is undefined for current revision
      bool IsUndefined = (InstructionNames[Opcode] == nullptr);
      if (IsUndefined) {
        CurInfo.HasUndefinedInstr = true;
#ifdef ZEN_ENABLE_JIT_FALLBACK_TEST
        // Reset undefined instruction flag in fallback test
        CurInfo.HasUndefinedInstr = false;
#endif
      }

      // Get stack metrics from the instruction metrics table
      const auto &Metrics = InstructionMetrics[Opcode];
      // stack_height_required equals PopCount
      int PopCount = Metrics.stack_height_required;
      // PushCount = PopCount + stack_height_change
      int PushCount = PopCount + Metrics.stack_height_change;

      // Handle PUSH instructions - need to skip the immediate bytes
      if (Opcode >= OP_PUSH1 && Opcode <= OP_PUSH32) {
        uint8_t PushBytes = Opcode - OP_PUSH0;
        Ip += PushBytes;
      }

      // Update stack height
      CurInfo.StackHeightDiff -= PopCount;
      if (CurInfo.StackHeightDiff < CurInfo.MinStackHeight) {
        CurInfo.MinStackHeight = CurInfo.StackHeightDiff;
      }
      if (!(Opcode >= OP_SWAP1 && Opcode <= OP_SWAP16) &&
          !(Opcode >= OP_DUP1 && Opcode <= OP_DUP16)) {
        CurInfo.MinPopHeight =
            std::min(CurInfo.StackHeightDiff, CurInfo.MinPopHeight);
      }
      CurInfo.StackHeightDiff += PushCount;
      if (CurInfo.StackHeightDiff > CurInfo.MaxStackHeight) {
        CurInfo.MaxStackHeight = CurInfo.StackHeightDiff;
      }

      // Check if this is a block starting opcode
      bool IsBlockStart = (Opcode == OP_JUMPDEST || Opcode == OP_JUMPI);
      // Check if this is a block ending opcode
      bool IsBlockEnd = (Opcode == OP_JUMP || Opcode == OP_RETURN ||
                         Opcode == OP_STOP || Opcode == OP_INVALID ||
                         Opcode == OP_REVERT || Opcode == OP_SELFDESTRUCT);

      if (IsBlockStart) {
        if (PC != CurInfo.EntryPC) {
          BlockInfos.emplace(CurInfo.EntryPC, CurInfo);
        }
        // Create new block info
        CurInfo = BlockInfo(PC);
        if (Opcode == OP_JUMPDEST) {
          CurInfo.IsJumpDest = true;
        }
      } else if (IsBlockEnd) {
        // Save current block info
        BlockInfos.emplace(CurInfo.EntryPC, CurInfo);
        // Skip dead code
        while (Ip < IpEnd) {
          evmc_opcode NextOp = static_cast<evmc_opcode>(*Ip);
          if (NextOp == OP_JUMPDEST) {
            break;
          }
          Ip++;
          if (NextOp >= OP_PUSH0 && NextOp <= OP_PUSH32) {
            uint8_t NumBytes =
                static_cast<uint8_t>(NextOp) - static_cast<uint8_t>(OP_PUSH0);
            Ip += NumBytes;
          }
        }
      }
    }
    if (BlockInfos.count(CurInfo.EntryPC) == 0) {
      BlockInfos.emplace(CurInfo.EntryPC, CurInfo);
    }

    return true;
  }

private:
  std::map<uint64_t, BlockInfo> BlockInfos;
  uint64_t PC = 0;
  evmc_revision Revision = zen::evm::DEFAULT_REVISION;
};

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_ANALYZER_H
