# Forge

**The Native Smart Contract Language and VM of Forge Blockchain**

Forge is a high-performance, safety-first smart contract language and virtual machine designed for the next generation of decentralized applications. Built with Zig, Forge compiles to high-efficiency RISC-V bytecode optimized for PolkaVM.

## Key Features

- **Safety by Construction**: Eliminates entire classes of bugs like reentrancy and overflow at compile time.
- **Linear Asset System**: First-class support for assets with built-in safety rules.
- **Zero-Conflict Parallel Execution**: State-owned architecture allows for massive scalability (up to 1 million TPS).
- **English-Readable Syntax**: Designed to be readable by anyone, emphasizing clarity over cleverness.
- **Isolated Account Namespaces**: Every byte of state is owned and isolated, preventing state leakage.

## Project Structure

- `src/`: The core compiler implementation in Zig.
  - `lexer.zig`, `parser.zig`: Frontend for the Forge language.
  - `checker.zig`: Semantic analysis and type checking.
  - `codegen_polkavm.zig`: Backend targeting PolkaVM/RISC-V.
- `contracts/`: Sample Forge contracts (`.foz`) and their compiled versions.
- `build.zig`: Zig build system configuration.

## Getting Started

### Prerequisites

- [Zig](https://ziglang.org/download/) (latest stable version recommended)

### Building the Compiler

To build the Forge compiler:

```bash
zig build
```

The binary will be available in `zig-out/bin/`.

### Documentation

For more detailed information on the language and how to use it, please refer to the:
👉 [**FORGE_DOCUMENTATION.md**](FORGE_DOCUMENTATION.md)

You can also check the full [FORGE_LANGUAGE_SPEC.md](FORGE_LANGUAGE_SPEC.md) for a technical reference.

## License

This project is part of the Forge Blockchain ecosystem.
