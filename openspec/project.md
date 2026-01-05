# Project Context

## Purpose
DTVM (DeTerministic Virtual Machine) is a next-generation blockchain virtual machine that addresses critical performance, determinism, and ecosystem compatibility challenges in blockchain networks. Building upon WebAssembly (Wasm) while maintaining full Ethereum Virtual Machine (EVM) ABI compatibility.

Key goals:
- Deterministic JIT execution with enhanced performance
- EVM ABI compatibility and multi-language ecosystem support  
- TEE-native security and hardware-optimized efficiency
- AI-powered smart contract development through SmartCogent integration

## Tech Stack
- **Core Language**: C++ (primary implementation)
- **Runtime Support**: C, Rust APIs
- **Compilation**: CMake build system
- **JIT Backend**: Customized implementation based on some base data structures from LLVM 15
- **Target Architectures**: x86-64, ARM64
- **Smart Contract Languages**: Solidity, C/C++, Rust, Java, Golang, AssemblyScript
- **Security**: Intel SGX TEE support
- **Testing**: CTest framework, WebAssembly spec tests

## Project Conventions

### Code Style
- Follow modern C++ standards and best practices
- Use `.clang-format` and `.clang-tidy` for code formatting and linting
- Maintain clear separation between runtime modes (interpreter, singlepass, multipass)
- Use descriptive naming for execution modes (FLAT, FLAS, etc.)

### Architecture Patterns
- **Modular Design**: Separate adaptation layers for different instruction sets (Wasm, EVM, RISC-V)
- **Unified IR**: All instruction sets translate to deterministic Middle Intermediate Representation (dMIR)
- **Hybrid Execution**: Support multiple execution modes with dynamic switching
- **Plugin Architecture**: Extensible runtime system for different blockchain environments

### Testing Strategy
- Comprehensive WebAssembly specification tests
- Unit tests for all execution modes (interpreter, singlepass, multipass)
- Cross-platform compatibility testing (x86-64, ARM64)
- Performance benchmarking across different optimization levels (O0~O2)
- TEE environment testing for SGX compatibility

### Git Workflow
- Feature branch workflow with pull requests
- Commit message format following conventional commits
- Automated testing on multiple platforms
- Code review requirements for core runtime changes

## Domain Context
- **Blockchain VM**: Understanding of gas metering, deterministic execution, and consensus requirements
- **WebAssembly**: Deep knowledge of Wasm specification and runtime semantics
- **JIT Compilation**: Lazy compilation strategies and optimization techniques
- **TEE Security**: Trusted execution environment constraints and security models
- **Smart Contracts**: Multi-language contract development and ABI compatibility

## Important Constraints
- **Deterministic Execution**: All operations must be deterministic across platforms and runs
- **Gas Metering**: Accurate resource consumption tracking for blockchain environments
- **Memory Safety**: Strict boundary checks and memory management
- **Cross-Platform**: Consistent behavior across x86-64 and ARM64 architectures
- **TEE Compatibility**: Minimal TCB (Trusted Computing Base) for SGX environments

## External Dependencies
- **LLVM 15**: Required for Lazy-JIT (multipass) compilation mode
- **CMake**: Build system and dependency management
- **WebAssembly Spec Tests**: Official test suite for compliance validation
- **Intel SGX SDK**: For trusted execution environment support
- **Blockchain Networks**: Integration with various blockchain platforms for deployment
