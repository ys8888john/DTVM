// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_UTILS_EVM_H
#define ZEN_UTILS_EVM_H

#include "utils/others.h"
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <intx/intx.hpp>
#include <optional>

namespace zen::utils {

void trimString(std::string &Str);

std::optional<std::vector<uint8_t>> fromHex(std::string_view HexStr);

// Address conversion utilities
std::string stripHexPrefix(const std::string &HexStr);
evmc::bytes hexToBytes(const std::string &HexStr);
evmc::address parseAddress(const std::string &HexAddr);
evmc::bytes32 parseBytes32(const std::string &HexStr);
evmc::uint256be parseUint256(const std::string &HexStr);
std::vector<uint8_t> parseHexData(const std::string &HexStr);

// Address to hex string conversion
std::string addressToHex(const evmc::address &Value);
std::string bytes32ToHex(const evmc::bytes32 &Value);
std::string bytesToHex(const std::vector<uint8_t> &Value);

std::vector<uint8_t> uint256beToBytes(const evmc::uint256be &Value);
evmc::address computeCreateAddress(const evmc::address &Sender,
                                   uint64_t SenderNonce);
bool saveState(const evmc::MockedHost &Host, const std::string &FilePath);
bool loadState(evmc::MockedHost &Host, const std::string &FilePath);

/// Compute the intrinsic gas cost of a transaction (EIP-2028, EIP-3860).
/// Includes: 21000 base + calldata cost + CREATE cost + initcode cost.
/// Does NOT include access list cost or authorization list cost; callers
/// that need those (e.g. state tests) should add them separately.
int64_t computeIntrinsicGas(evmc_revision Revision, evmc_call_kind MsgKind,
                            const uint8_t *InputData, size_t InputSize);
/// Pre-warm transaction-level accounts per EIP-2929 and EIP-3651.
/// EIP-2929 (Berlin+): warms sender, recipient, and precompiled contracts
/// (0x01-0x09).
/// EIP-3651 (Shanghai+): warms the coinbase address.
/// For contract-creation transactions, pass a zero address as Recipient
/// to skip recipient warming (CREATE txs have no transaction-level "to").
void prewarmTransactionAccounts(evmc::MockedHost &Host, evmc_revision Revision,
                                const evmc::address &Sender,
                                const evmc::address &Recipient,
                                const evmc::address &Coinbase);

/// EIP-3529 refund cap: London and later cap refunds at GasUsed/5;
/// pre-London caps at GasUsed/2.
uint64_t computeRefundCap(evmc_revision Revision, uint64_t GasUsed);

struct EvmFeeComponents {
  intx::uint256 EffectiveGasPrice;
  intx::uint256 PriorityFee;
};

/// Compute the effective gas price and priority fee for an EVM transaction.
/// When MaxPriorityFee is provided, EffectiveOrMaxFeePerGas is the EIP-1559
/// maxFeePerGas, PriorityFee is min(maxPriorityFee, maxFeePerGas - baseFee),
/// and EffectiveGasPrice is baseFee + PriorityFee.
/// Otherwise EffectiveOrMaxFeePerGas is already the effective gas price for a
/// legacy transaction, PriorityFee is max(effectiveGasPrice - baseFee, 0),
/// and EffectiveGasPrice is effectiveGasPrice.
EvmFeeComponents computeEvmTransactionFees(
    const evmc::uint256be &EffectiveOrMaxFeePerGas,
    const evmc::uint256be &BaseFee,
    const std::optional<evmc::uint256be> &MaxPriorityFee = std::nullopt);

enum class EvmUpfrontGasResult {
  Success,
  IntrinsicGasExceedsLimit,
  InsufficientBalance
};

/// Deduct intrinsic gas from Msg.gas and pre-warm transaction-level accounts.
/// Also deducts gas_limit * effective_gas_price from the sender's balance.
/// Call this before callEVMMain.
EvmUpfrontGasResult applyEvmUpfrontGas(evmc::MockedHost &Host,
                                       evmc_message &Msg, uint64_t GasLimit,
                                       evmc_revision Revision);

/// Apply the dtvm-cli post-execution gas settlement: refund cap (EIP-3529),
/// refund unused gas to sender, and pay priority fee to coinbase.
void applyEvmPostExecutionSettlement(evmc::MockedHost &Host,
                                     const evmc_message &Msg, uint64_t GasLimit,
                                     const evmc::Result &Result,
                                     evmc_revision Revision);

} // namespace zen::utils

#endif // ZEN_UTILS_EVM_H
