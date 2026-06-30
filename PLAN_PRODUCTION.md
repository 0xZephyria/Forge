# Forge Production Plan

## Complete Implementation Roadmap for a Production-Grade Smart Contract Language

**Target:** ZVM across all tiers (interpreter, threaded, AOT) with complete language coverage.
**Spec:** FORGE_LANGUAGE_SPEC.md (Version 1.0, 3258 lines, 20 parts, ~200 features).
**Current codebase:** ~50,000 lines of Zig across compiler frontend + VM backend.

---

## Phase 0: Current State Assessment

### What Works (✅ Fully Implemented)

#### Frontend (Parser → Type Checker) — 16,000+ lines
- Lexer: 130+ token kinds, all literal types, keywords, duration units, punctuation
- Parser: Recursive-descent Pratt parser, all contract sections, expressions, statements, patterns, annotations, guards
- AST: 38 TypeExpr variants, 20 ExprKind, 30+ StmtKind, all declaration types
- MIR: 56 instruction opcodes, full AST-to-MIR lowering (12 lowerer functions)
- Type Resolver: 31+ ResolvedType variants, generics, capabilities, built-in aliases, subtype relationships
- Semantic Checker: 30+ check functions, all 5 access isolation rules, linear type tracking, authority validation, conservation proofs, gas complexity enforcement, upgrade diffs, global invariants, capability tokens
- Errors: 38 CompileError variants + Rust-style diagnostic infrastructure

#### Codegen — 3,700+ lines
- RISC-V RV64IM backend: actions, views, pures, setup, fallback, receive, upgrade, gas metering, ZephBin v1 output
- EVM bytecode backend: ABI dispatch, storage, calldata, events, selectors
- ABI Generator: Zephyria + EVM JSON
- WASM encoding utilities

#### VM — 10,000+ lines
- Full RV64IM interpreter (all R/I/S/B/U/J types, M-extension, word ops)
- Threaded interpreter with basic block analysis (2-3x speedup)
- 512KB sandboxed memory with dirty tracking
- Gas metering (per-instruction + per-syscall)
- 40+ syscall handlers (storage, assets, events, crypto, cross-contract, environment, authority, oracle, ZK, gas delegation, account lifecycle)
- AOT compiler: transpile ZephBin → C → native .dylib via zig cc
- Multi-tier execution: interpreter → threaded → AOT
- Pluggable HostEnv providers for all external operations
- VM instance pool (128-shard, lock-free, work-stealing)
- Contract loaders (ELF, ZephBin, Forge format)
- ZephBin executable format with action dispatch

### What's Stubbed or Partial (⚠️ Incomplete)

| Area | Status | Issue |
|------|--------|-------|
| BLS_VERIFY syscall | Stub | Returns a0=0 (failure), gas charged |
| EMIT_INDEXED_EVENT | Stub | Calls same handler as EMIT_EVENT, no topic indexing |
| Contract inheritance checker | Stub | Verifies parent exists but doesn't propagate authorities/states |
| Interface conformance checker | Partial | Framework exists, validation logic incomplete |
| Multisig/timelock authority check | Partial | Validation omitted |
| Linear tracking in views | Missing | LinearTracker not wired for view bodies |
| Module resolution | No-op | `use` imports accepted but not resolved |
| Gas refunds | No-op | EIP-3529 refunds explicitly deprecated |
| executeContract function | Unused | Exists but never called (CREATE doesn't use it) |
| AUTHORITY_LIST, ASSET_METADATA, ASSET_APPROVE, ASSET_ALLOWANCE | Not dispatched | Syscall IDs defined but no handlers |
| Code hash getter | Not dispatched | getCodeHash function exists but no dispatch entry |

### What's Missing (❌ Not Implemented)

| Feature | Spec Part | Frontend | RISC-V CG | EVM CG | VM |
|---------|-----------|----------|-----------|--------|----|
| Execution futures | 9.2 | Not parsed | — | — | — |
| Module resolution | 15/16 | No-op | — | — | — |
| Test framework | 17 | Not parsed | — | — | — |
| Deploy manifests | 18 | Not parsed | — | — | — |
| PolkaVM backend | — | — | — | — | — |
| ZK proof codegen | 12 | Parsed | Not emitted | Not emitted | Provider-based |
| Gas sponsorship codegen | 14.3 | Checked | Not emitted | Not emitted | Provider-based |
| `schedule_call` codegen | 10.2 | Present in MIR | Stub | No-op | Provider-based |
| `attempt`/`on_error` | 11.5 | Present in MIR | Incomplete | No-op | No setjmp/longjmp |
| EVM fixed-point scaling | 2.2 | — | N/A | Bug | — |
| SELFDESTRUCT dispatch | — | — | — | — | Status exists, no syscall ID |

---

## Phase 1: Close Gaps with Existing Spec (Weeks 1–3)

### P1.1 — Fix Stubbed Syscalls (Day 1)

**BLS_VERIFY (0x73)**
- **What:** Implement BLS12-381 signature verification using Zig's `std.crypto.signature.bls`
- **ABI:** a1=pubkey_ptr(48B), a2=sig_ptr(96B), a3=msg_ptr, a4=msg_len → a0=1 valid/0 invalid
- **File:** `vm/syscall/dispatch.zig` — replace the stub in the dispatch switch
- **Expected:** Returns a0=1 for valid BLS sig, 0 otherwise

**EMIT_INDEXED_EVENT (0x31)**
- **What:** Proper topic indexing — compute bloom filter bits from indexed fields
- **File:** `vm/syscall/dispatch.zig:emitEvent()` — add a `indexed: bool` parameter or separate handler
- **Expected:** Indexed events are searchable in the event log

### P1.2 — Wire Undispatched Syscalls (Day 1-2)

**Syscall IDs to implement:** `AUTHORITY_LIST (0x23)`, `ASSET_METADATA (0x14)`, `ASSET_APPROVE (0x15)`, `ASSET_ALLOWANCE (0x16)`, `GET_CODE_HASH`

- **AUTHORITY_LIST:** Read a1=addr_ptr(32B), return a0=list of authority IDs (fire-and-forget, provider-based)
- **ASSET_METADATA:** Read a1=asset_id_ptr(32B), write metadata fields to a2 result buffer, provider-based
- **ASSET_APPROVE:** Read a1=asset_id_ptr(32B), a2=spender_ptr(32B), a3=amount_ptr(16B), provider-based
- **ASSET_ALLOWANCE:** Read a1=asset_id_ptr(32B), a2=owner_ptr(32B), a3=spender_ptr(32B), write a4 result, provider-based
- **GET_CODE_HASH:** Wire existing `getCodeHash` function into dispatch switch (0x6D or similar)

**File:** `vm/syscall/dispatch.zig`

### P1.3 — Fix ABI Mismatches (Day 2)

**asset_metadata/approve/allowance:** Add HostEnv provider callbacks, handlers, and wire them.

**`schedule_call` codegen** — `src/codegen.zig:1184`
- Emit: compute target block from `current_block + after`, ABI-encode the deferred call (recipient, calldata, block), call scheduler syscall
- MIR `schedule_call` at `mir.zig:258`: `{ recipient, data, after }` where `after` is block delay

**`attempt_begin`/`attempt_end` exception flow** — `src/codegen.zig:1106`
- Emit: save return stack pointer at attempt_begin (label + SSP snapshot), on error in attempt body → jump to attempt_end's error handler
- At runtime: ECALL sets error status → check if in attempt context → jump to handler or propagate

### P1.4 — Fix Contract Inheritance (Day 2-3)

**File:** `src/checker.zig:1725` (`checkInheritance`)
- **What:** Currently verifies parent exists. Must also:
  1. Merge parent's `has:` fields into child (mark inherited)
  2. Propagate inheritable authorities with correct holder forwarding
  3. Verify child doesn't override immutable parent fields
  4. Track storage layout version across inheritance chain
- **Expected:** `contract Child inherits Parent:` properly inherits state, authorities, and interfaces

### P1.5 — Fix Interface Conformance (Day 3)

**File:** `src/checker.zig:1993`
- **What:** Validate every action/view/event/error in the interface exists in the implementing contract with:
  1. Same function name
  2. Same parameter types (in order)
  3. Same return type
  4. Same event field names and types
- **Expected:** `contract X implements Y:` guarantees full interface adherence

### P1.6 — Fix Linear Tracking in Views (Day 3)

**File:** `src/checker.zig` — wire `LinearTracker` for view bodies
- **What:** Views must NOT contain `send`, `burn`, `move`, `merge`, or `split` statements
- **Expected:** Compile error if a view tries to consume a linear asset

### P1.7 — Implement Module Resolution (Day 4-5)

**File:** `src/types.zig:743` and new `src/module_resolver.zig`
- **What:** Resolve `use path.to.module` to actual files on disk/package:
  1. `standard.*` → built-in standard library (shipped as `.foz` files in known directory)
  2. `path.to.module` → relative file lookup in project/src
  3. Importing file brings all types, constants, interfaces into scope
  4. Cyclic import detection
  5. Namespace collision errors
- **Expected:** Imports actually work and bring symbols into scope

### P1.8 — Implement SELFDESTRUCT Dispatch (Day 5)

**File:** `vm/syscall/dispatch.zig`
- **What:** Add `SELFDESTRUCT` syscall ID (e.g., 0x1A), wire `selfDestructFn` provider
- **ABI:** a1=beneficiary_ptr(32B) → returns `SyscallError.SelfDestruct` which sets `ExecutionStatus.selfDestruct`
- **Expected:** Calling selfdestruct terminates execution and routes to provider

### P1.9 — Fix EVM Fixed-Point Scaling (Day 5)

**File:** `src/codegen_evm.zig:2957`
- **What:** Thread `ResolvedType` through expression codegen so `price9` scales to 9 places, `percent` to 4 places
- **Expected:** `let p is price9 = 1234.567` produces correct EVM representation

---

## Phase 2: VM Production Hardening (Weeks 3–4)

### P2.1 — Memory Page Protection (Week 3)

**File:** `vm/memory/sandbox.zig`
- **What:** Replace region-level permission checks with page-level (4KB page table)
- **Why:** Required for parallel execution guarantee — each account needs per-page isolation
- **Implementation:**
  1. 128-page table (512KB / 4KB) with `rwx` bits per page
  2. Load/store operations check page permissions, not region bounds
  3. Account namespace scope mapped to page range
  4. Cross-account page access → immediate fault
- **Expected:** VM enforces per-account memory isolation at hardware-like granularity

### P2.2 — Dynamic Memory Growth (Week 3)

**File:** `vm/memory/sandbox.zig`
- **What:** Replace fixed 512KB with growable memory (initial=64KB, max=32MB, grow in 4KB pages)
- **Why:** Required for EXPAND_ACCOUNT support and large-state contracts
- **Implementation:**
  1. Sparse page table (mapped pages only consume physical memory)
  2. `expand(account, bytes)` syscall maps new pages
  3. Gas cost proportional to pages mapped: `200 + pages * 5000`
  4. Max 32MB = 8192 pages = far future capacity
- **Expected:** Contracts can grow their data accounts up to 32MB

### P2.3 — Thread Safety & VM Pool Production (Week 3)

**File:** `vm/vm_pool.zig`
- **What:** Production-hardening the VM pool:
  1. Automatic pool warmup on first deploy (pre-create N instances)
  2. Pool health monitoring (leaked instance detection, timeout reclaim)
  3. Adaptive sizing based on load
  4. Pre-emption timeout (force-acquire with deadline)
- **Expected:** Pool handles 10K+ concurrent requests without degradation

### P2.4 — Gas Meter Precision (Week 3-4)

**Files:** `vm/gas/meter.zig`, `vm/gas/table.zig`
- **What:**
  1. Implement EIP-3529-style refund tracking (SSTORE clear refunds)
  2. Per-byte memory expansion gas (already have fixed costs, need dynamic)
  3. Call-depth-based gas overhead
- **Expected:** Gas costs match real execution cost within 10% margin

### P2.5 — Cross-Contract Call Production (Week 4)

**File:** `vm/syscall/dispatch.zig:callContract`
- **What:** Full sub-VM creation for cross-contract calls:
  1. When `callFn` is not set, spawn a sub-VM with isolated memory
  2. Copy calldata into sub-VM's calldata region
  3. Execute sub-VM with gas limit (forward all remaining gas - reserve 1/64)
  4. Copy return data back to parent's return data region
  5. Track call depth to 1024
- **Expected:** Cross-contract calls work without an external provider

### P2.6 — AOT Compiler Tests (Week 4)

**File:** `vm/compiler/aot.zig`, `src/vm_integration_test.zig`
- **What:**
  1. Parametric test: compile every RISC-V instruction to C, verify behavior matches interpreter
  2. Fuzz test: random bytecode → AOT vs interpreter output equivalence
  3. Edge cases: division by zero, overflow, memory boundary, gas exhaustion
- **Expected:** AOT compiler is provably equivalent to interpreter

---

## Phase 3: New Features for Full Language Coverage (Weeks 4–8)

### P3.1 — Execution Futures (Week 4-5)

**Spec ref:** Part 9.2 (Execution Futures)

**Frontend:**
1. New AST node: `ExecutionFuture { at_block, will_write, will_read, for_program, expiry }`
2. Parser: `reserve execution_future { ... }` statement
3. Checker: validate all accounts in `will_write`/`will_read` are declared in `accounts:`
4. MIR: `reserve_future` instruction carrying block number + access set

**VM:**
1. New syscall `RESERVE_FUTURE` (0x83): submit a future reservation
2. New syscall `EXECUTE_FUTURE` (0x84): execute a previously reserved future
3. Scheduler: maintain a future queue indexed by (block, program, account)
4. At reservation: check no write-set conflict with existing futures for that block
5. At execution: verify current_block matches reserved block, prove slot

**Codegen (RISC-V):**
- Emit the RESERVE_FUTURE syscall with encoded future parameters
- ABI: a1=at_block(u64), a2=future_spec_ptr(encoded access list)

### P3.2 — Test Framework (Week 5-6)

**Spec ref:** Part 17 (Testing)

**Frontend:**
1. New AST/Parser for `.foztest` files: `test_suite`, `test`, `test "name"`, `expect`, `expect_error`, `fuzz`, `invariant_test`, `fork_test`
2. Checker: validate test expressions reference declared contracts
3. Test runner module: `src/test_runner.zig`

**VM:**
1. Simulation mode: deploy contracts without persistent state
2. State snapshot/restore for test isolation
3. Time manipulation: `advance_time by N`
4. Fork test support: load mainnet state snapshot

**CLI:**
- `forge test` command: discover `.foztest` files, compile contracts, run tests
- Colored output with pass/fail counts, stack traces on failure
- `forge test --coverage`: gas usage and coverage analysis

### P3.3 — Deploy Manifests (Week 6-7)

**Spec ref:** Part 18 (Deployment)

**Frontend:**
1. New AST/Parser for `.fozdeploy` files: `deploy`, `deploy_suite`, `sequence`, `networks`, `params`, `initial_authorities`, `create_accounts`, `after_deploy`, `verify`
2. Environment variable resolution: `env("VAR_NAME")`

**CLI:**
- `forge deploy deploy.fozdeploy`: compile, resolve params, submit deploy transaction
- `forge deploy --dry-run`: validate without submitting
- `forge deploy --network mainnet`: target specific network

### P3.4 — Standard Library (Week 7-8)

**Spec ref:** Part 16 (Standard Library)

**Deliver:**
```foz
// standard/math.foz —  Safe math and fixed-point arithmetic
// standard/tokens.foz — ERC20-equivalent interface + helpers
// standard/access.foz — RBAC role management
// standard/governance.foz — Voting primitives
// standard/oracle.foz — Price feed helpers
// standard/crypto.foz — Hash, sign, verify helpers
// standard/strings.foz — String manipulation
// standard/arrays.foz — Collection utilities
```

Each is a `.foz` source file implementing the interfaces and helpers described in the spec.

**Standard library build system:**
1. Pre-compile all standard lib files to ZephBin at build time
2. Embed in the `forge` binary as compressed data
3. Resolve `use standard.X` imports against embedded blobs
4. Versioned with semantic versioning (standard lib v1 → v2 migration path)

### P3.5 — ZK Proof Codegen (Week 7-8)

**Spec ref:** Part 12 (ZK & Privacy)

**Frontend:**
1. Already parsed: `#[zk_proof using Plonk]`, `#[private]` annotations, `verify proof against commitment`
2. Already type-checked: private input validation, non-storage constraints
3. Need: circuit IR lowering that connects to VM's ZK_VERIFY syscall

**Codegen (RISC-V):**
- Emit circuit ID + proof pointer → ZK_VERIFY syscall
- Emit commitment check before state changes
- Emit nullifier creation for confidential transfers

**VM:**
- `ZK_VERIFY` syscall already implemented (provider-based)
- Add default Groth16/Plonk verifier using Zig's crypto library (bls12-381 pairings)
- Commitment scheme: Pedersen commitments via BLAKE3 hash

### P3.6 — Gas Sponsorship Codegen (Week 8)

**Spec ref:** Part 14.3 (Gas Sponsorship)

**Frontend:**
1. Already parsed/checked: `#[gas_sponsored_for mine.sponsored_set]`
2. Need: codegen that emits pre-flight check before charging caller's gas

**Codegen (RISC-V):**
- Emit: check if caller is in `mine.sponsored_set`
- If yes: charge contract's gas budget instead of caller's
- If no: charge caller normally

**VM:**
- New syscall `DELEGATE_GAS` (0xB1) already implemented via `delegateGasFn` provider
- Provider checks sponsor whitelist and budget, deducts from sponsor balance

---

## Phase 4: New Generic Language Features (Weeks 8–12)

These extend the language beyond the current spec to make Forge competitive with Solidity, Move, and Rust/Anchor as a general-purpose smart contract DSL.

### P4.1 — Event Indexing & Filtering

**What:** When `EMIT_INDEXED_EVENT` is called, compute a 256-byte bloom filter from indexed fields. The filter is part of the block header, enabling efficient light-client event discovery.

**Implementation:**
1. VM: 256-byte bloom filter per block (in-memory accumulator)
2. On indexed event emit: set bloom bits for each indexed topic
3. On event query: filter by bloom first, then full match
4. Syscall `EMIT_INDEXED_EVENT` gets separate handler from `EMIT_EVENT`

### P4.2 — Contract Upgrades with Storage Migration

**Spec ref:** Part 13 (Upgradability)

**Frontend:** Already parsed and partially checked.
**VM:**
1. New syscall `UPGRADE_CONTRACT` (0x45): replace bytecode of a program account
2. Storage migration: automated layout transformation from `version N` to `version N+1`
3. Migration function execution: runs at upgrade time, not at call time
4. Immutable field enforcement: VM blocks writes to immutable storage slots
5. Upgrade event emission

### P4.3 — Parallel Execution Scheduler

**Spec ref:** Part 9 (Parallel Execution)

**What:** Build the actual parallel scheduler that processes transactions using the signed access lists.

**Implementation:**
1. `AccessList` format: compiled into transaction envelope (signed by sender)
2. Scheduler receives N transactions with access lists
3. Conflict detection in O(N): rotate through lanes, assign non-conflicting tx to lane
4. Each lane = one VM instance from the pool (thread-safe)
5. Post-execution: verify VM's actual writes match declared access list
6. Violation → slashing (economic penalty on validator)

**Integration with existing syscalls:**
- `RESOURCE_LOCK`/`RESOURCE_UNLOCK`: declare write intent ahead of time
- `PARALLEL_HINT`: mark actions as parallel-safe (compiler-verified)

### P4.4 — Account Abstraction

**What:** Not just EOAs signing transactions. Any account (including Program accounts) can initiate transactions through a standardized "sponsored transaction" flow.

**Implementation:**
1. Interface `ISigner { action validate(tx_data); action execute(tx_data); }`
2. A transaction is valid if either:
   a. It carries a BLS signature from a known EOA, OR
   b. It calls `validate()` on a Program account specified as the fee payer
3. Gas is deducted from the account that signed/validated
4. Enables: multisig wallets as contracts, gasless transactions, session keys

### P4.5 — Native Multisig Verification

**Spec ref:** Part 4.5 (Multi-Signature Authorities)

**What:** VM-level M-of-N signature verification without contracts.

**Implementation:**
1. New syscall `MULTISIG_VERIFY`: aggregate BLS signatures from N signers
2. ABI: a1=signers_ptr(32*N bytes), a2=count(u64), a3=threshold(u64), a4=msg_hash(32B), a5=sig_ptr(96B)
3. Uses BLS12-381 aggregate signatures (all N sigs aggregated into one 96B sig)
4. Returns a0=1 if M-of-N threshold met
5. Gas cost: base 5000 + N * 1000

### P4.6 — Storage Proof Verification

**What:** Verify storage proofs from other chains or state roots without a bridge.

**Implementation:**
1. New syscall `VERIFY_MERKLE_PROOF`: verify inclusion in a Merkle-Patricia trie
2. ABI: a1=root_hash(32B), a2=key_ptr(32B), a3=value_ptr(32B), a4=proof_ptr(var), a5=proof_len
3. Supports: Ethereum-like hexary trie, Solana-like Merkle tree, custom
4. Gas cost: `2000 + proof_nodes * 500`
5. Enables trustless bridges and state proofs

### P4.7 — Dynamic Account Resolution

**What:** Deferred account address resolution for cross-chain and runtime-dependent targets.

**Extension to Part 3:**
- `resolve(namespace, seed)` → returns account address determined at runtime
- `resolve(name_service, "alice.forge")` → DNS-like name resolution
- The resolver is a HostEnv provider that can query an external registry

---

## Phase 5: Tooling & Developer Experience (Weeks 10–14)

### P5.1 — LSP Server
- Language Server Protocol implementation for editors
- Features: go-to-definition, hover type info, completions, diagnostics, inline errors
- Reuse checker module, just expose via LSP JSON-RPC

### P5.2 — Debugger
- Source-level debug info in ZephBin format
- Step-through, breakpoints, variable inspection
- CLI debugger (`forge debug token.foz deploy.fozdeploy`)
- Source maps from bytecode offsets back to source positions

### P5.3 — Documentation Generator
- `forge doc` command
- Parses doc comments (///) into HTML/markdown documentation
- Generates contract explorer pages with ABI, events, errors, state

### P5.4 — Fuzz Testing Framework
- Integration with test framework
- `#[fuzz]` annotation on test functions
- Random valid transaction generation based on contract ABI
- Invariant monitoring: check contract-level invariants after each fuzz iteration

### P5.5 — Gas Profiler
- `forge profile token.foz --action transfer`
- Runs action with sample inputs, reports gas breakdown per opcode/syscall
- Identifies gas hotspots and optimization opportunities

### P5.6 — Formal Verification Interface
- Export contract invariants + state machine as SMT-LIB2 formulas
- Integrate with Z3 or similar SMT solver
- Prove: no overflow, no invariant violation, no reentrancy, no unauthorized access

---

## Implementation Priority Matrix

| Feature | Priority | Effort | Impact | Dependency |
|---------|----------|--------|--------|------------|
| BLS_VERIFY syscall | P0 | 1 day | Security | — |
| Module resolution | P0 | 2 days | Compilation | — |
| Contract inheritance | P0 | 2 days | Language completeness | — |
| Interface conformance | P0 | 1 day | Language completeness | — |
| Undispatched syscall handlers | P0 | 1 day | VM completeness | — |
| EVM fixed-point bug | P0 | 1 day | EVM compat | — |
| Linear tracking in views | P0 | 1 day | Safety | — |
| Page-level memory protection | P1 | 5 days | Security | — |
| Dynamic memory growth | P1 | 5 days | Scalability | — |
| Cross-contract sub-VM | P1 | 5 days | Independence | — |
| AOT compiler tests | P1 | 3 days | Reliability | — |
| Execution futures | P1 | 10 days | Performance | Parallel scheduler |
| Test framework | P1 | 10 days | Dev UX | Contract deployer |
| Deploy manifests | P1 | 5 days | Dev UX | Test framework |
| Standard library | P2 | 10 days | Dev UX | Module resolution |
| Gas sponsorship codegen | P2 | 3 days | Feature | — |
| ZK proof codegen | P2 | 5 days | Feature | — |
| Event indexing | P2 | 3 days | Event system | — |
| Contract upgrades VM | P2 | 5 days | Feature | — |
| Parallel scheduler | P3 | 15 days | Performance | Memory protection |
| Account abstraction | P3 | 10 days | Feature | — |
| Native multisig | P3 | 5 days | Security | BLS_VERIFY |
| Storage proof verification | P3 | 5 days | Interop | — |
| Dynamic account resolution | P3 | 3 days | Feature | — |
| LSP server | P4 | 15 days | Dev UX | Module resolution |
| Debugger | P4 | 10 days | Dev UX | Source maps |
| Docs generator | P4 | 5 days | Dev UX | Doc comments |
| Fuzz testing | P4 | 10 days | Testing | Test framework |
| Gas profiler | P4 | 5 days | Optimization | Test framework |
| Formal verification | P5 | 20 days | Security | Invariant format |

---

## File Change Map

### Phase 1 Files
```
vm/syscall/dispatch.zig          — BLS_VERIFY, undispatched handlers, SELFDESTRUCT
vm/gas/table.zig                 — BLS_VERIFY gas
src/checker.zig                  — Inheritance, interface conformance
src/types.zig                    — Module resolution (or new src/module_resolver.zig)
src/codegen.zig                  — schedule_call, attempt_begin/end emission
src/codegen_evm.zig              — Fixed-point scaling bug fix
src/mir.zig                      — No changes needed
```

### Phase 2 Files
```
vm/memory/sandbox.zig            — Page table, dynamic growth
vm/core/executor.zig             — Page-fault-aware memory access
vm/core/decoder.zig              — No changes
vm/syscall/dispatch.zig          — DYNAMIC_EXPAND, expanded memory ops
vm/gas/meter.zig                 — Refund tracking, memory expansion costs
vm/gas/table.zig                 — Memory expansion gas
vm/vm_pool.zig                   — Auto-warmup, health monitoring
vm/loader/contract_loader.zig    — Sub-VM creation for calls
vm/compiler/aot.zig              — No changes needed
src/vm_integration_test.zig      — AOT equivalence tests
```

### Phase 3 Files
```
src/ast.zig                      — ExecutionFuture node
src/parser.zig                   — reserve, execution_future, test suite, deploy manifest
src/checker.zig                  — Future validation, test validation
src/mir.zig                      — reserve_future MirOp
src/codegen.zig                  — Future, ZK, sponsorship codegen
src/codegen_evm.zig              — Future, ZK, sponsorship codegen
src/test_runner.zig              — NEW: test framework
src/deploy_engine.zig            — NEW: deploy manifest engine
src/module_resolver.zig          — NEW (or expand types.zig)
standard/*.foz                   — NEW: 8 standard library files
vm/syscall/dispatch.zig          — RESERVE_FUTURE, EXECUTE_FUTURE, UPGRADE syscalls
vm/core/executor.zig             — Future execution support
```

### Phase 4 Files
```
vm/syscall/dispatch.zig          — MULTISIG_VERIFY, VERIFY_MERKLE_PROOF
vm/core/executor.zig             — Parallel execution lane support
vm/memory/sandbox.zig            — Account-level page isolation
vm/vm_pool.zig                   — Lane assignments
src/ast.zig                      — Account abstraction syntax
src/parser.zig                   — Account abstraction syntax
```

### Phase 5 Files
```
src/lsp.zig                      — NEW: LSP server
src/docgen.zig                   — NEW: documentation generator
src/profiler.zig                 — NEW: gas profiler
src/smt_exporter.zig             — NEW: formal verification export
```

---

## Verification Strategy

Every phase must pass these gates before advancing:

### Gate 1: Build
- `zig build` succeeds with zero errors zero warnings
- All tests pass: `zig build test`

### Gate 2: Feature Tests
- **Phase 1:** All syscall handlers unit-tested (mock provider, verify output);
  Module resolution resolves `use standard.math`; Inheritance checker produces correct errors;
  Interface conformance checker validates all interface methods
- **Phase 2:** Memory protection catches cross-page writes; Dynamic growth succeeds up to 32MB;
  Pool handles 100 concurrent requests; AOT output matches interpreter across 1000+ random programs
- **Phase 3:** Execution future reserves and executes; Test framework produces pass/fail for valid/invalid tests;
  Deploy manifest produces correct deploy transaction; All 8 standard library files compile and resolve
- **Phase 4:** Parallel scheduler assigns lanes correctly; Account abstraction validates/executes; Multisig verifies M-of-N

### Gate 3: Integration Tests
- Full compile-deploy-execute pipeline: `compiler → ZephBin → VM`
- Token contract: deploy, mint, transfer, burn, balance query
- DeFi contract: deploy, add liquidity, swap, remove liquidity
- Cross-contract: deploy two contracts, call one from the other
- Upgrade: deploy V1, migrate to V2, verify state preserved

### Gate 4: Regression
- Every existing test continues to pass (no regressions)
- Performance: interpreter path unchanged (<10% perf impact for new features)
- AOT: unchanged output for existing ZephBin packages

---

## Architectural Decisions

### Decision 1: Standard Library as Compiled ZephBin
Standard library is distributed as `.foz` source AND pre-compiled `.fozbin` blobs.
At build time, the compiler embeds the blobs. At compile time, `use standard.X` resolves
to the embedded bytecode. The source is bundled separately for verification.

### Decision 2: Parallel Scheduler as External Service
The parallel scheduler lives outside the VM core (as a library: `vm/scheduler.zig`).
The VM only enforces per-account memory isolation and signed access list verification.
The scheduler is a separate concern — can be swapped without VM changes.

### Decision 3: AOT as Optional Accelerator
AOT compilation is always optional. The interpreter + threaded executor is the default
path. AOT is only used when `FORGE_NO_AOT` is not set AND `zig cc` is available.
This ensures ZephBin is always the canonical execution format.

### Decision 4: HostEnv Provider Pattern for External Dependencies
All syscalls that interact with the outside world (storage, oracle, ZK, account lifecycle)
use the HostEnv provider pattern. The VM itself has no built-in knowledge of specific
blockchain state — it only knows how to route syscalls. Providers are injected at runtime.

### Decision 5: Execution Futures as VM-Level Primitive
Futures are not just a scheduler hint. They are VM-enforced reservations.
The VM verifies at reservation that the declared access list is conflict-free.
It updates an on-chain future registry. At execution time, it validates the future
was reserved and has not expired. Invalid futures are rejected before execution.

---

## Completion Criteria

The implementation is production-complete when:

1. **All Phase 1-4 features** pass their Gate 2 tests
2. **200+ deterministic tests** pass in the test framework
3. **Full compile-deploy-execute pipeline** works for:
   - ERC20-like token contract
   - AMM/DEX contract
   - Governance/DAO contract
   - NFT marketplace contract
   - Multisig wallet contract
   - Upgradeable proxy contract
4. **ZephBin v1 format** is the stable canonical format
5. **AOT compiler** produces correct output for all valid ZephBin packages
6. **Parallel scheduler** achieves 100K+ TPS on 32-core hardware (synthetic benchmark)
7. **VM pool** handles 5000+ concurrent instances on commodity hardware
8. **Memory isolation** is provable (no cross-account memory access succeeds)
9. **Module resolution** resolves all `use standard.X` imports
10. **Standard library v1** ships with 8+ modules
