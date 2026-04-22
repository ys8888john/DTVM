// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "dt_evmc_vm.h"
#include "action/compiler.h"
#include "common/enums.h"
#include "common/errors.h"
#include "evm/interpreter.h"
#include "runtime/config.h"
#include "runtime/evm_instance.h"
#include "runtime/isolation.h"
#include "runtime/runtime.h"
#include "wrapped_host.h"
#ifdef ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
#include "compiler/evm_frontend/evm_analyzer.h"
#endif // ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
#include <algorithm>

#include <evmc/evmc.h>
#include <evmc/evmc.hpp>
#include <evmc/helpers.h>

#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <future>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <vector>

#ifdef ZEN_ENABLE_VIRTUAL_STACK
#include "utils/virtual_stack.h"
#endif // ZEN_ENABLE_VIRTUAL_STACK

namespace {

using namespace zen::runtime;
using namespace zen::common;

// ---- Profile-Guided JIT: tunable parameters ----
namespace profile {
// Ring buffer capacity: number of recent global contract call records.
static constexpr size_t RING_BUFFER_CAPACITY = 10000;
// JIT trigger conditions: both must be met within the sliding window.
static constexpr uint64_t JIT_TRIGGER_CALL_COUNT = 32;
static constexpr uint64_t JIT_TRIGGER_TOTAL_GAS = 100000;
} // namespace profile

// ---- Profile-Guided JIT: data structures ----

struct CallRecord {
  std::string ModName;
  uint64_t GasUsed = 0;
};

struct ContractProfile {
  uint64_t WindowCallCount = 0;
  uint64_t WindowGasUsed = 0;
  bool JITTriggered = false;
  bool JITRejected = false;
};

struct CallRingBuffer {
  std::vector<CallRecord> Buffer;
  size_t Head = 0;
  size_t Count = 0;
  size_t Capacity;

  explicit CallRingBuffer(size_t Cap) : Buffer(Cap), Capacity(Cap) {}

  std::optional<CallRecord> push(CallRecord NewRecord) {
    std::optional<CallRecord> Evicted;
    if (Count == Capacity) {
      Evicted = std::move(Buffer[Head]);
    } else {
      Count++;
    }
    Buffer[Head] = std::move(NewRecord);
    Head = (Head + 1) % Capacity;
    return Evicted;
  }
};

std::string getStableModName(const evmc_message *Msg) {
  static const char HexChars[] = "0123456789abcdef";
  std::string Name = "mod_0x";
  Name.reserve(6 + 40);
  for (size_t I = 0; I < sizeof(Msg->code_address.bytes); ++I) {
    uint8_t Byte = Msg->code_address.bytes[I];
    Name.push_back(HexChars[Byte >> 4]);
    Name.push_back(HexChars[Byte & 0x0F]);
  }
  return Name;
}

// ---- JIT Compile Thread Pool ----
// A simple fixed-size thread pool for background JIT compilation tasks.
// Limits the number of concurrent compilations to avoid resource exhaustion.
class JITCompilePool {
public:
  explicit JITCompilePool(uint32_t NumThreads) : Shutdown(false) {
    for (uint32_t I = 0; I < NumThreads; ++I) {
      Workers.emplace_back([this]() { workerLoop(); });
    }
  }

  ~JITCompilePool() {
    {
      std::lock_guard<std::mutex> Lock(QueueMutex);
      Shutdown = true;
    }
    QueueCV.notify_all();
    for (auto &Worker : Workers) {
      Worker.join();
    }
  }

  // Submit a compilation task. Returns a future that completes when
  // the task finishes. The caller can use future.valid()/wait() to
  // check or wait for completion.
  std::future<void> submit(std::function<void()> Task) {
    auto Promise = std::make_shared<std::promise<void>>();
    std::future<void> Future = Promise->get_future();
    {
      std::lock_guard<std::mutex> Lock(QueueMutex);
      TaskQueue.push(
          [Task = std::move(Task), Promise = std::move(Promise)]() mutable {
            try {
              Task();
              Promise->set_value();
            } catch (...) {
              Promise->set_exception(std::current_exception());
            }
          });
    }
    QueueCV.notify_one();
    return Future;
  }

  // Non-copyable, non-movable.
  JITCompilePool(const JITCompilePool &) = delete;
  JITCompilePool &operator=(const JITCompilePool &) = delete;

private:
  void workerLoop() {
    while (true) {
      std::function<void()> Task;
      {
        std::unique_lock<std::mutex> Lock(QueueMutex);
        QueueCV.wait(Lock, [this]() { return Shutdown || !TaskQueue.empty(); });
        if (Shutdown && TaskQueue.empty())
          return;
        Task = std::move(TaskQueue.front());
        TaskQueue.pop();
      }
      Task();
    }
  }

  std::vector<std::thread> Workers;
  std::queue<std::function<void()>> TaskQueue;
  std::mutex QueueMutex;
  std::condition_variable QueueCV;
  bool Shutdown;
};
// RAII helper for temporarily changing runtime configuration
class ScopedConfig {
public:
  ScopedConfig(Runtime *Runtime, const RuntimeConfig &NewConfig)
      : RT(Runtime), PreviousConfig(Runtime->getConfig()) {
    RT->setConfig(NewConfig);
  }

  ~ScopedConfig() { RT->setConfig(PreviousConfig); }

private:
  Runtime *RT;
  RuntimeConfig PreviousConfig;
};

// Forward declaration for InstanceGuard
struct DTVM;

// RAII guard for unloading transient modules that must not be persisted in the
// address-based cache. Destruction order matters: instance guards must run
// before unloading the module they execute.
struct ModuleGuard {
  DTVM *VM;
  EVMModule *Mod;
  bool ShouldUnload;

  ModuleGuard(DTVM *VM, EVMModule *Mod, bool ShouldUnload)
      : VM(VM), Mod(Mod), ShouldUnload(ShouldUnload) {}

  ModuleGuard(const ModuleGuard &) = delete;
  ModuleGuard &operator=(const ModuleGuard &) = delete;

  ~ModuleGuard();

  void release() { ShouldUnload = false; }
};

// RAII helper for host context save/restore (exception safety).
// Ensures host context is always restored on all exit paths, including
// exceptions.
struct HostContextScope {
  ::WrappedHost *ExecHost;
  const evmc_host_interface *PrevInterface;
  evmc_host_context *PrevContext;

  HostContextScope(::WrappedHost *Host, const evmc_host_interface *Interface,
                   evmc_host_context *Context)
      : ExecHost(Host), PrevInterface(Host->getInterface()),
        PrevContext(Host->getContext()) {
    ExecHost->reinitialize(Interface, Context);
  }

  ~HostContextScope() { ExecHost->reinitialize(PrevInterface, PrevContext); }

  // Non-copyable
  HostContextScope(const HostContextScope &) = delete;
  HostContextScope &operator=(const HostContextScope &) = delete;
};

// ---- Address-based module cache types ----

static constexpr size_t MAX_MODULE_CACHE_SIZE = 4096;

struct CodeAddrRevKey {
  evmc_address Addr;
  evmc_revision Rev;
};

struct CodeAddrRevHash {
  size_t operator()(const CodeAddrRevKey &K) const {
    uint64_t H;
    std::memcpy(&H, K.Addr.bytes + 12, sizeof(H));
    return H ^ (static_cast<size_t>(K.Rev) * 2654435761u);
  }
};

struct CodeAddrRevEqual {
  bool operator()(const CodeAddrRevKey &A, const CodeAddrRevKey &B) const {
    return A.Rev == B.Rev &&
           std::memcmp(A.Addr.bytes, B.Addr.bytes, sizeof(A.Addr.bytes)) == 0;
  }
};

/// Validate that the cached module's code matches the provided code.
/// Note: This relies on the host guaranteeing that deployed code at a given
/// address is immutable. We only check the head and tail (up to 256 bytes each)
/// as a defense-in-depth measure against accidental cache corruption.
/// For fully untrusted environments where hosts might reuse addresses for
/// different bytecode, a full CRC/hash check should be implemented instead.
bool validateCodeMatch(const uint8_t *Code, size_t CodeSize,
                       const EVMModule *Mod) {
  if (CodeSize != Mod->CodeSize)
    return false;
  if (CodeSize == 0)
    return true;
  auto *ModCode = reinterpret_cast<const uint8_t *>(Mod->Code);
  size_t HeadLen = std::min(CodeSize, static_cast<size_t>(256));
  if (std::memcmp(Code, ModCode, HeadLen) != 0)
    return false;
  if (CodeSize > 256) {
    size_t TailLen = std::min(CodeSize, static_cast<size_t>(256));
    size_t TailOffset = CodeSize - TailLen;
    if (std::memcmp(Code + TailOffset, ModCode + TailOffset, TailLen) != 0)
      return false;
  }
  return true;
}

bool parseBoolEnvValue(const char *Value, bool &ParsedValue) {
  if (std::strcmp(Value, "1") == 0 || std::strcmp(Value, "true") == 0 ||
      std::strcmp(Value, "TRUE") == 0) {
    ParsedValue = true;
    return true;
  }
  if (std::strcmp(Value, "0") == 0 || std::strcmp(Value, "false") == 0 ||
      std::strcmp(Value, "FALSE") == 0) {
    ParsedValue = false;
    return true;
  }
  return false;
}

// VM interface for DTVM
struct DTVM : evmc_vm {
  DTVM();
  ~DTVM() {
    // Drain the JIT compile thread pool first: wait for all in-flight
    // compilation tasks to finish before unloading modules they reference.
    CompilePool.reset();
    if (CachedMainInst && Iso) {
      Iso->deleteEVMInstance(CachedMainInst);
      CachedMainInst = nullptr;
    }

    // Clean up cached instance for depth > 0
    if (CacheInsts.size() > 0 && Iso) {
      for (auto It : CacheInsts) {
        Iso->deleteEVMInstance(It);
      }
    }

    // Unload all address-cached modules
    if (RT) {
      for (auto &P : AddrCache) {
        if (!RT->unloadEVMModule(P.second.first)) {
          ZEN_LOG_ERROR("failed to unload EVM module");
        }
      }
    }
    if (Iso) {
      RT->deleteManagedIsolation(Iso);
    }
  }
  RuntimeConfig Config = {.Format = InputFormat::EVM,
                          .Mode = RunMode::MultipassMode,
                          .EnableEvmGasMetering = true};
  std::unique_ptr<Runtime> RT;
  std::unique_ptr<::WrappedHost> ExecHost;
  Isolation *Iso = nullptr;

  // ---- Module & instance cache (shared by interpreter and multipass) ----
  // L0: pointer-based inline cache (fastest, 2 integer comparisons)
  const uint8_t *LastCodePtr = nullptr;
  size_t LastCodeSize = 0;
  EVMModule *L0Mod = nullptr;

  // L1: address-based LRU cache (code_address + rev -> module)
  // LRUOrder tracks access recency: front = most recent, back = least recent.
  // AddrCache maps key -> (module, iterator into LRUOrder) for O(1) lookup
  // and O(1) LRU maintenance via std::list::splice.
  using LRUList = std::list<CodeAddrRevKey>;
  LRUList LRUOrder;
  std::unordered_map<CodeAddrRevKey, std::pair<EVMModule *, LRUList::iterator>,
                     CodeAddrRevHash, CodeAddrRevEqual>
      AddrCache;

  uint64_t ModCounter = 0;
  // Cached EVMInstance to avoid alloc/free (~33KB) on every call
  EVMInstance *CachedMainInst = nullptr;
  // Cached InterpreterExecContext (interpreter mode only)
  std::unique_ptr<zen::evm::InterpreterExecContext> CachedCtx;
  // Instance pool for depth > 0
  std::vector<EVMInstance *> CacheInsts;

  // ---- Profile-guided JIT state ----
  std::unordered_map<std::string, ContractProfile> ProfileStore;
  CallRingBuffer RingBuffer{profile::RING_BUFFER_CAPACITY};
  // Thread pool for background JIT compilation (lazily initialized).
  std::unique_ptr<JITCompilePool> CompilePool;

  bool isModuleInUse(const EVMModule *Mod) const {
    if (CachedMainInst && CachedMainInst->getModule() == Mod)
      return true;
    for (const auto *Inst : CacheInsts) {
      if (Inst && Inst->getModule() == Mod)
        return true;
    }
    return false;
  }
};

ModuleGuard::~ModuleGuard() {
  if (ShouldUnload && Mod && VM && VM->RT) {
    if (!VM->RT->unloadEVMModule(Mod)) {
      ZEN_LOG_ERROR("failed to unload transient EVM module");
    }
  }
}

/// The implementation of the evmc_vm::destroy() method.
void destroy(evmc_vm *VMInstance) { delete static_cast<DTVM *>(VMInstance); }

/// The implementation of the evmc_vm::get_capabilities() method.
evmc_capabilities_flagset get_capabilities(evmc_vm * /*instance*/) {
  return EVMC_CAPABILITY_EVM1;
}

/// VM options.
///
/// The implementation of the evmc_vm::set_option() method.
/// VMs are allowed to omit this method implementation.
enum evmc_set_option_result set_option(evmc_vm *VMInstance, const char *Name,
                                       const char *Value) {
  auto *VM = static_cast<DTVM *>(VMInstance);
  if (std::strcmp(Name, "mode") == 0) {
    if (std::strcmp(Value, "interpreter") == 0) {
      VM->Config.Mode = RunMode::InterpMode;
      return EVMC_SET_OPTION_SUCCESS;
    } else if (std::strcmp(Value, "multipass") == 0) {
      VM->Config.Mode = RunMode::MultipassMode;
      return EVMC_SET_OPTION_SUCCESS;
    } else {
      return EVMC_SET_OPTION_INVALID_VALUE;
    }
  } else if (std::strcmp(Name, "enable_gas_metering") == 0) {
    if (std::strcmp(Value, "true") == 0) {
      VM->Config.EnableEvmGasMetering = true;
      return EVMC_SET_OPTION_SUCCESS;
    } else if (std::strcmp(Value, "false") == 0) {
      VM->Config.EnableEvmGasMetering = false;
      return EVMC_SET_OPTION_SUCCESS;
    } else {
      return EVMC_SET_OPTION_INVALID_VALUE;
    }
#ifdef ZEN_ENABLE_MULTIPASS_JIT
  } else if (std::strcmp(Name, "num_jit_compile_threads") == 0) {
    int Parsed = std::atoi(Value);
    if (Parsed > 0 && Parsed <= 256) {
      VM->Config.NumJITCompileThreads = static_cast<uint32_t>(Parsed);
      return EVMC_SET_OPTION_SUCCESS;
    }
    return EVMC_SET_OPTION_INVALID_VALUE;
  } else if (std::strcmp(Name, "profile_guided_jit") == 0) {
    bool Parsed = false;
    if (parseBoolEnvValue(Value, Parsed)) {
      VM->Config.EnableProfileGuidedJIT = Parsed;
      return EVMC_SET_OPTION_SUCCESS;
    }
    return EVMC_SET_OPTION_INVALID_VALUE;
#endif
  }
  return EVMC_SET_OPTION_INVALID_NAME;
}

/// Ensure RT and Iso are initialized. Returns false on failure.
bool ensureRuntimeAndIsolation(DTVM *VM) {
  if (!VM->RT) {
    VM->RT = Runtime::newEVMRuntime(VM->Config, VM->ExecHost.get());
    if (!VM->RT)
      return false;
  }
  if (!VM->Iso) {
    VM->Iso = VM->RT->createManagedIsolation();
    if (!VM->Iso)
      return false;
  }
  return true;
}

/// Lazily initialize the JIT compile thread pool.
JITCompilePool &getOrCreateCompilePool(DTVM *VM) {
  if (!VM->CompilePool) {
    VM->CompilePool =
        std::make_unique<JITCompilePool>(VM->Config.NumJITCompileThreads);
  }
  return *VM->CompilePool;
}

bool shouldUsePersistentModuleCache(const evmc_message *Msg) {
  // CREATE/CREATE2 initcode must not be cached: the same address can receive
  // different initcode across transactions, and initcode is one-shot.
  // Regular calls (CALL/DELEGATECALL/STATICCALL/CALLCODE) at any depth are
  // safe to cache: EVM guarantees that deployed code at a given address is
  // immutable. The module is keyed by (code_address, revision) and a
  // defense-in-depth head/tail validation is performed before reuse. Each
  // nested call gets its own EVMInstance so reentrancy is safe.
  return Msg != nullptr && Msg->kind != EVMC_CREATE &&
         Msg->kind != EVMC_CREATE2;
}

bool shouldRetryModuleLoadWithFastRA(const DTVM *VM, const Error &Err) {
  return VM->Config.Mode == RunMode::MultipassMode &&
         !VM->Config.DisableMultipassGreedyRA &&
         Err.getPhase() == ErrorPhase::Compilation &&
         Err.getSubphase() == ErrorSubphase::RegAlloc;
}

zen::common::MayBe<EVMModule *>
loadEVMModuleWithRegAllocRetry(DTVM *VM, const std::string &ModName,
                               const uint8_t *Code, size_t CodeSize,
                               evmc_revision Rev) {
  auto ModRet = VM->RT->loadEVMModule(ModName, Code, CodeSize, Rev);
  if (ModRet || !shouldRetryModuleLoadWithFastRA(VM, ModRet.getError())) {
    return ModRet;
  }

  RuntimeConfig RetryConfig = VM->Config;
  RetryConfig.DisableMultipassGreedyRA = true;
  ScopedConfig Retry(VM->RT.get(), RetryConfig);
  return VM->RT->loadEVMModule(ModName, Code, CodeSize, Rev);
}

EVMModule *loadTransientModule(DTVM *VM, const uint8_t *Code, size_t CodeSize,
                               evmc_revision Rev) {
  std::string ModName = "tmp_mod_" + std::to_string(VM->ModCounter++);
  auto ModRet =
      loadEVMModuleWithRegAllocRetry(VM, ModName, Code, CodeSize, Rev);
  if (!ModRet)
    return nullptr;
  return *ModRet;
}

/// Find or load a cached EVMModule using two-level cache:
///   L0 (code pointer+size) -> L1 (address map) -> Cold load.
/// Shared by both interpreter and multipass paths.
/// Returns nullptr on failure.
EVMModule *findModuleCached(DTVM *VM, const uint8_t *Code, size_t CodeSize,
                            evmc_revision Rev, const evmc_message *Msg,
                            bool &IsTransient) {
  if (!shouldUsePersistentModuleCache(Msg)) {
    IsTransient = true;
    return loadTransientModule(VM, Code, CodeSize, Rev);
  }

  IsTransient = false;

  // L0 disabled: pointer comparison is unsafe when callers reuse addresses
  // for different bytecode (e.g. test frameworks, repeated allocations).
  // Fall through to L1 address-based lookup with content validation.

  EVMModule *Mod = nullptr;

  // L1: Address-based LRU cache lookup
  CodeAddrRevKey AddrKey{Msg->code_address, Rev};
  auto It = VM->AddrCache.find(AddrKey);
  if (It != VM->AddrCache.end() &&
      validateCodeMatch(Code, CodeSize, It->second.first)) {
    Mod = It->second.first;
    // LRU touch: move to front (most recently used)
    VM->LRUOrder.splice(VM->LRUOrder.begin(), VM->LRUOrder, It->second.second);
  } else {
    // Cold path: full module load
    // If validation failed for an existing entry, evict the stale module
    if (It != VM->AddrCache.end()) {
      EVMModule *OldMod = It->second.first;
      if (VM->L0Mod == OldMod && Msg->depth == 0)
        VM->L0Mod = nullptr;
      VM->RT->unloadEVMModule(OldMod);
      VM->LRUOrder.erase(It->second.second);
      VM->AddrCache.erase(It);
    }

    // LRU eviction: if cache is at capacity, evict least recently used
    while (VM->AddrCache.size() >= MAX_MODULE_CACHE_SIZE &&
           !VM->LRUOrder.empty()) {
      auto &VictimKey = VM->LRUOrder.back();
      auto VictimIt = VM->AddrCache.find(VictimKey);
      if (VictimIt != VM->AddrCache.end()) {
        EVMModule *VictimMod = VictimIt->second.first;
        if (VM->isModuleInUse(VictimMod))
          break; // never evict a module referenced by an active instance
        if (VM->L0Mod == VictimMod)
          VM->L0Mod = nullptr;
        VM->RT->unloadEVMModule(VictimMod);
        VM->AddrCache.erase(VictimIt);
      }
      VM->LRUOrder.pop_back();
    }

    std::string ModName = "mod_" + std::to_string(VM->ModCounter++);
    auto ModRet =
        loadEVMModuleWithRegAllocRetry(VM, ModName, Code, CodeSize, Rev);
    if (!ModRet)
      return nullptr;
    Mod = *ModRet;

    VM->LRUOrder.push_front(AddrKey);
    VM->AddrCache[AddrKey] = {Mod, VM->LRUOrder.begin()};
  }

  // Update L0 cache members. Even though L0 lookup is disabled, we maintain
  // these state variables for two reasons:
  // 1. Eviction tracking: If a stale L1 entry is replaced, we need to
  // invalidate
  //    L0Mod if it pointed to the old module (done in the eviction path
  //    above).
  // 2. Future extensibility: It keeps the door open for re-enabling L0 later
  //    with a safer validation scheme (e.g., pointer + size + hash).
  VM->LastCodePtr = Code;
  VM->LastCodeSize = CodeSize;
  VM->L0Mod = Mod;
  return Mod;
}

/// Get or create an EVMInstance for the given module.
/// For top-level calls (Depth == 0), reuses a single cached main instance
/// when possible; for nested calls (Depth > 0), uses per-depth cached
/// instances stored in VM->CacheInsts, creating them lazily as needed.
/// The lifetime of all returned instances is managed by the DTVM object;
/// callers must not delete the returned pointer.
EVMInstance *getOrCreateInstance(DTVM *VM, EVMModule *Mod, evmc_revision Rev,
                                 int32_t Depth) {
  // if depth > 0, use cached instance
  if (Depth > 0) {
    EVMInstance *TempInst = nullptr;
    if (VM->CacheInsts.size() < static_cast<size_t>(Depth)) {
      auto InstRet = VM->Iso->createEVMInstance(*Mod, 0);
      if (!InstRet)
        return nullptr;
      TempInst = *InstRet;
      VM->CacheInsts.push_back(TempInst);
    } else {
      size_t Idx = Depth - 1;
      TempInst = VM->CacheInsts[Idx];
    }
    TempInst->resetForNewCall(Rev, *Mod);
    return TempInst;
  }

  // if depth == 0, reuse cached main instance
  EVMInstance *TheInst = VM->CachedMainInst;
  // Create new instance if cache is empty or module mismatch
  if (!TheInst || TheInst->getModule() != Mod) {
    if (TheInst) {
      // Reuse existing instance with new module
      TheInst->resetForNewCall(Rev, *Mod);
    } else {
      // Allocate new instance and cache it
      auto InstRet = VM->Iso->createEVMInstance(*Mod, 0);
      if (!InstRet)
        return nullptr;
      TheInst = *InstRet;
      VM->CachedMainInst = TheInst;
    }
  } else {
    // Cache hit: same module, just reset with new revision
    TheInst->resetForNewCall(Rev);
  }

  return TheInst;
}

/// Fast path for interpreter mode: reuse cached instance, call interpreter
/// directly. This avoids per-call EVMInstance alloc/free and bypasses
/// Runtime::callEVMMain overhead.
evmc_result executeInterpreterFastPath(DTVM *VM,
                                       const evmc_host_interface *Host,
                                       evmc_host_context *Context,
                                       evmc_revision Rev,
                                       const evmc_message *Msg,
                                       const uint8_t *Code, size_t CodeSize) {
  // RAII guard for host context save/restore (exception safety)
  HostContextScope HostScope(VM->ExecHost.get(), Host, Context);

  // Ensure runtime and isolation exist
  if (!ensureRuntimeAndIsolation(VM)) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  // Module lookup: L1 address-based cache -> Cold load
  bool IsTransientMod = false;
  EVMModule *Mod =
      findModuleCached(VM, Code, CodeSize, Rev, Msg, IsTransientMod);
  if (!Mod) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }
  ModuleGuard ModGuard(VM, Mod, IsTransientMod);

  // Instance reuse (shared only for cacheable top-level calls)
  EVMInstance *TheInst = getOrCreateInstance(VM, Mod, Rev, Msg->depth);
  if (!TheInst) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  // Trigger bytecodeCache build if not yet done (lazy, cached on module)
  (void)Mod->getBytecodeCache();

  // Call interpreter directly, bypassing Runtime::callEVMMain overhead
  evmc_message MsgWithCode = *Msg;
  MsgWithCode.code = reinterpret_cast<uint8_t *>(Mod->Code);
  MsgWithCode.code_size = Mod->CodeSize;
  TheInst->setExeResult(evmc::Result{EVMC_SUCCESS, 0, 0});
  TheInst->pushMessage(&MsgWithCode);

  const bool ReuseCachedInstance = !IsTransientMod && Msg->depth == 0;

  // For nested calls, create a new InterpreterExecContext
  // For cacheable top-level calls, reuse cached context
  std::unique_ptr<zen::evm::InterpreterExecContext> TempCtx;
  zen::evm::InterpreterExecContext *CtxPtr = nullptr;
  if (!ReuseCachedInstance) {
    // Nested call or transient module: create temporary context
    TempCtx = std::make_unique<zen::evm::InterpreterExecContext>(TheInst);
    CtxPtr = TempCtx.get();
  } else {
    // Top-level call: reuse cached context
    if (!VM->CachedCtx) {
      VM->CachedCtx =
          std::make_unique<zen::evm::InterpreterExecContext>(TheInst);
    } else {
      VM->CachedCtx->resetForNewCall(TheInst);
    }
    CtxPtr = VM->CachedCtx.get();
  }

  auto &Ctx = *CtxPtr;
  zen::evm::BaseInterpreter Interpreter(Ctx);
  Ctx.allocTopFrame(&MsgWithCode);
  Interpreter.interpret();

  evmc::Result Result =
      std::move(const_cast<evmc::Result &>(Ctx.getExeResult()));
  Result.gas_left = TheInst->getGas();

  return Result.release_raw();
}

/// Profile-guided JIT: record call and check if JIT should be triggered.
/// Called after execution completes with the result available.
#ifdef ZEN_ENABLE_MULTIPASS_JIT
void updateProfileAndMaybeTriggerJIT(DTVM *VM, const evmc_message *Msg,
                                     const evmc_result &Result,
                                     EVMModule *Mod) {
  std::string ModName = getStableModName(Msg);
  uint64_t GasUsed = static_cast<uint64_t>(Msg->gas - Result.gas_left);

  // 1. Push new record; may evict the oldest record.
  CallRecord NewRecord{ModName, GasUsed};
  auto Evicted = VM->RingBuffer.push(std::move(NewRecord));

  // 2. Process evicted record: decrement its profile counters.
  if (Evicted) {
    auto EvictIt = VM->ProfileStore.find(Evicted->ModName);
    if (EvictIt != VM->ProfileStore.end()) {
      auto &OldProfile = EvictIt->second;
      if (OldProfile.WindowCallCount > 0)
        OldProfile.WindowCallCount--;
      if (OldProfile.WindowGasUsed >= Evicted->GasUsed)
        OldProfile.WindowGasUsed -= Evicted->GasUsed;
      else
        OldProfile.WindowGasUsed = 0;

      // Clean up zero-count profiles that have not been evaluated.
      if (OldProfile.WindowCallCount == 0 && !OldProfile.JITTriggered &&
          !OldProfile.JITRejected) {
        VM->ProfileStore.erase(EvictIt);
      }
    }
  }

  // 3. Skip profile update for contracts already evaluated.
  auto ExistIt = VM->ProfileStore.find(ModName);
  if (ExistIt != VM->ProfileStore.end() &&
      (ExistIt->second.JITTriggered || ExistIt->second.JITRejected)) {
    return;
  }

  // 4. Update current contract profile (increment).
  auto &CurrentProfile = VM->ProfileStore[ModName];
  CurrentProfile.WindowCallCount++;
  CurrentProfile.WindowGasUsed += GasUsed;

  // 5. Check JIT trigger conditions.
  if (CurrentProfile.WindowCallCount < profile::JIT_TRIGGER_CALL_COUNT ||
      CurrentProfile.WindowGasUsed < profile::JIT_TRIGGER_TOTAL_GAS) {
    return;
  }

#ifdef ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
  // Static analysis gate: reject contracts unsuitable for JIT.
  COMPILER::EVMAnalyzer Analyzer(Mod->getRevision());
  Analyzer.analyze(reinterpret_cast<const uint8_t *>(Mod->Code), Mod->CodeSize);
  if (Analyzer.getJITSuitability().ShouldFallback) {
    CurrentProfile.JITRejected = true;
    return;
  }
#endif // ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK

  // Avoid duplicate JIT triggers.
  if ((Mod->JITCompileFuture.valid() &&
       Mod->JITCompileFuture.wait_for(std::chrono::seconds(0)) !=
           std::future_status::ready) ||
      Mod->getJITCode()) {
    CurrentProfile.JITTriggered = true;
    return;
  }

  // Trigger background JIT compilation via thread pool.
  CurrentProfile.JITTriggered = true;
  auto &Pool = getOrCreateCompilePool(VM);
  Mod->JITCompileFuture =
      Pool.submit([Mod]() { zen::action::performEVMJITCompile(*Mod); });
}
#endif // ZEN_ENABLE_MULTIPASS_JIT

#ifdef ZEN_ENABLE_JIT

#ifdef ZEN_ENABLE_VIRTUAL_STACK
/// Virtual stack callback for JIT fast path: invoked with RSP on the virtual
/// stack. Follows the same pattern as callEVMFuncFromVirtualStack in
/// runtime.cpp.
static void callJITFromVirtualStack(zen::utils::VirtualStackInfo *StackInfo) {
  auto *Inst = static_cast<EVMInstance *>(StackInfo->SavedPtr1);
  auto *Msg = static_cast<evmc_message *>(StackInfo->SavedPtr2);
  auto *Result = static_cast<evmc::Result *>(StackInfo->SavedPtr3);
  Inst->getRuntime()->callEVMInJITMode(*Inst, *Msg, *Result);
}
#endif // ZEN_ENABLE_VIRTUAL_STACK

/// Fast path for multipass JIT mode: reuse cached instance, call JIT code
/// directly. This avoids per-call callEVMMain overhead while delegating
/// actual JIT execution to Runtime::callEVMInJITMode (single source of truth
/// for CPU exception handling, error mapping, etc.).
evmc_result executeMultipassFastPath(DTVM *VM, const evmc_host_interface *Host,
                                     evmc_host_context *Context,
                                     evmc_revision Rev, const evmc_message *Msg,
                                     const uint8_t *Code, size_t CodeSize) {
  // RAII guard for host context save/restore (exception safety)
  HostContextScope HostScope(VM->ExecHost.get(), Host, Context);

  // Ensure runtime and isolation exist
  if (!ensureRuntimeAndIsolation(VM)) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  // Module lookup: L1 address-based cache -> Cold load
  bool IsTransientMod = false;
  EVMModule *Mod =
      findModuleCached(VM, Code, CodeSize, Rev, Msg, IsTransientMod);
  if (!Mod) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }
  ModuleGuard ModGuard(VM, Mod, IsTransientMod);

#ifdef ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
  // O(1) flag check replaces per-call O(n) EVMAnalyzer scan.
  // The flag was set once at module creation in EVMModule::newEVMModule().
  if (Mod->ShouldFallbackToInterp) {
    return executeInterpreterFastPath(VM, Host, Context, Rev, Msg, Code,
                                      CodeSize);
  }
#endif // ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK

  // Instance reuse (shared only for cacheable top-level calls)
  EVMInstance *TheInst = getOrCreateInstance(VM, Mod, Rev, Msg->depth);
  if (!TheInst) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  // Setup message with code pointers (same pattern as interpreter fast path)
  evmc_message MsgWithCode = *Msg;
  MsgWithCode.code = reinterpret_cast<uint8_t *>(Mod->Code);
  MsgWithCode.code_size = Mod->CodeSize;
  TheInst->setExeResult(evmc::Result{EVMC_SUCCESS, 0, 0});
  TheInst->pushMessage(&MsgWithCode);

  evmc::Result Result;

#ifdef ZEN_ENABLE_VIRTUAL_STACK
  if (Msg->depth == 0) {
    // depth==0: set up virtual stack for stack overflow protection via guard
    // pages. The virtual stack switches RSP to a separate mmap'd region.
    zen::utils::VirtualStackInfo StackInfo;
    StackInfo.SavedPtr1 = TheInst;
    StackInfo.SavedPtr2 = &MsgWithCode;
    StackInfo.SavedPtr3 = &Result;
    TheInst->pushVirtualStack(&StackInfo);
    StackInfo.runInVirtualStack(&callJITFromVirtualStack);
    TheInst->popVirtualStack();
  } else {
    // depth>0: re-entered via EVMC host callback, already on physical stack
    VM->RT->callEVMInJITMode(*TheInst, MsgWithCode, Result);
  }
#else
  VM->RT->callEVMInJITMode(*TheInst, MsgWithCode, Result);
#endif // ZEN_ENABLE_VIRTUAL_STACK

  Result.gas_left = TheInst->getGas();
  return Result.release_raw();
}
#endif // ZEN_ENABLE_JIT

/// The implementation of the evmc_vm::execute() method.
evmc_result execute(evmc_vm *EVMInstance, const evmc_host_interface *Host,
                    evmc_host_context *Context, enum evmc_revision Rev,
                    const evmc_message *Msg, const uint8_t *Code,
                    size_t CodeSize) {
  auto *VM = static_cast<DTVM *>(EVMInstance);

  // Interpreter mode: use optimized fast path (bypasses callEVMMain)
  if (VM->Config.Mode == RunMode::InterpMode) {
    return executeInterpreterFastPath(VM, Host, Context, Rev, Msg, Code,
                                      CodeSize);
  }

#ifdef ZEN_ENABLE_MULTIPASS_JIT
  // Profile-guided JIT: use interpreter with profiling when JIT not ready,
  // then switch to JIT once compiled.
  if (VM->Config.EnableProfileGuidedJIT) {
    // RAII guard for host context save/restore (exception safety)
    HostContextScope HostScope(VM->ExecHost.get(), Host, Context);

    if (!ensureRuntimeAndIsolation(VM)) {
      return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
    }

    // Module lookup: L1 address-based cache -> Cold load
    bool IsTransientMod = false;
    EVMModule *Mod =
        findModuleCached(VM, Code, CodeSize, Rev, Msg, IsTransientMod);
    if (!Mod) {
      return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
    }
    ModuleGuard ModGuard(VM, Mod, IsTransientMod);

    // Instance reuse (shared only for cacheable top-level calls)
    auto *TheInst = getOrCreateInstance(VM, Mod, Rev, Msg->depth);
    if (!TheInst) {
      return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
    }

    if (!Mod->getJITCode()) {
      // JIT not ready: run interpreter with profiling
      (void)Mod->getBytecodeCache();

      evmc_message MsgWithCode = *Msg;
      MsgWithCode.code = reinterpret_cast<uint8_t *>(Mod->Code);
      MsgWithCode.code_size = Mod->CodeSize;
      TheInst->setExeResult(evmc::Result{EVMC_SUCCESS, 0, 0});
      TheInst->pushMessage(&MsgWithCode);

      const bool ReuseCachedInstance = !IsTransientMod && Msg->depth == 0;

      std::unique_ptr<zen::evm::InterpreterExecContext> TempCtx;
      zen::evm::InterpreterExecContext *CtxPtr = nullptr;
      if (!ReuseCachedInstance) {
        TempCtx = std::make_unique<zen::evm::InterpreterExecContext>(TheInst);
        CtxPtr = TempCtx.get();
      } else {
        if (!VM->CachedCtx) {
          VM->CachedCtx =
              std::make_unique<zen::evm::InterpreterExecContext>(TheInst);
        } else {
          VM->CachedCtx->resetForNewCall(TheInst);
        }
        CtxPtr = VM->CachedCtx.get();
      }

      auto &Ctx = *CtxPtr;
      zen::evm::BaseInterpreter Interpreter(Ctx);
      Ctx.allocTopFrame(&MsgWithCode);
      Interpreter.interpret();

      evmc::Result Result =
          std::move(const_cast<evmc::Result &>(Ctx.getExeResult()));
      Result.gas_left = TheInst->getGas();

      evmc_result RawResult = Result.release_raw();

      if (shouldUsePersistentModuleCache(Msg)) {
        updateProfileAndMaybeTriggerJIT(VM, Msg, RawResult, Mod);
      }

      return RawResult;
    }

    // JIT code ready: execute via callEVMMain, continue profiling
    evmc_message Message = *Msg;
    evmc::Result Result;
    VM->RT->callEVMMain(*TheInst, Message, Result);

    evmc_result RawResult = Result.release_raw();
    if (shouldUsePersistentModuleCache(Msg)) {
      updateProfileAndMaybeTriggerJIT(VM, Msg, RawResult, Mod);
    }
    return RawResult;
  }
#endif // ZEN_ENABLE_MULTIPASS_JIT

#ifdef ZEN_ENABLE_JIT
  // Non-PGJ JIT mode: use optimized fast path
  return executeMultipassFastPath(VM, Host, Context, Rev, Msg, Code, CodeSize);
#else
  return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
#endif // ZEN_ENABLE_JIT
}

/// @cond internal
#if !defined(PROJECT_VERSION)
/// The dummy project version if not provided by the build system.
#define PROJECT_VERSION "0.0.0"
#endif
/// @endcond

DTVM::DTVM()
    : evmc_vm{EVMC_ABI_VERSION, "dtvm",    PROJECT_VERSION,
              ::destroy,        ::execute, ::get_capabilities,
              ::set_option},
      ExecHost(new WrappedHost) {
  if (const char *Mode = std::getenv("DTVM_EVM_MODE"); Mode != nullptr) {
    if (std::strcmp(Mode, "interpreter") == 0) {
      Config.Mode = RunMode::InterpMode;
    } else if (std::strcmp(Mode, "multipass") == 0) {
      Config.Mode = RunMode::MultipassMode;
    } else {
      ZEN_LOG_WARN("ignore invalid DTVM_EVM_MODE=%s", Mode);
    }
  }

  if (const char *EnableGas = std::getenv("DTVM_EVM_ENABLE_GAS_METERING");
      EnableGas != nullptr) {
    bool ParsedEnableGas = false;
    if (parseBoolEnvValue(EnableGas, ParsedEnableGas)) {
      Config.EnableEvmGasMetering = ParsedEnableGas;
    } else {
      ZEN_LOG_WARN("ignore invalid DTVM_EVM_ENABLE_GAS_METERING=%s", EnableGas);
    }
  }
}
} // namespace

extern "C" evmc_vm *evmc_create_dtvmapi() { return new DTVM; }
