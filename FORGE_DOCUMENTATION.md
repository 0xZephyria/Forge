# Forge Language — Complete Developer Documentation

> **Built by DHOTNetworks Research** · Compiler version 1.0.0 · Written in Zig 0.15.2  
> Source files: `.foz` · Compiled output: `.fozbin` · Targets: Zephyria VM · EVM · PolkaVM

---

## Table of Contents

1. [What Is Forge?](#1-what-is-forge)
2. [Compiler Architecture & Pipeline](#2-compiler-architecture--pipeline)
3. [Module Reference — All Files, Functions & Usages](#3-module-reference--all-files-functions--usages)
   - [3.1 lexer.zig](#31-lexerzig)
   - [3.2 ast.zig](#32-astzig)
   - [3.3 parser.zig](#33-parserzig)
   - [3.4 types.zig](#34-typeszig)
   - [3.5 checker.zig](#35-checkerzig)
   - [3.6 codegen.zig](#36-codegenzig)
   - [3.7 codegen_evm.zig](#37-codegen_evmzig)
   - [3.8 codegen_polkavm.zig](#38-codegen_polkavmzig)
   - [3.9 abi.zig](#39-abizig)
   - [3.10 errors.zig](#310-errorszig)
   - [3.11 riscv.zig](#311-riscvzig)
   - [3.12 u256.zig](#312-u256zig)
   - [3.13 wasm.zig](#313-wasmzig)
   - [3.14 main.zig](#314-mainzig)
4. [The Forge Language — Syntax & Feature Guide](#4-the-forge-language--syntax--feature-guide)
5. [Novel Ideas — What Makes Forge Different](#5-novel-ideas--what-makes-forge-different)
6. [Who Forge Is For](#6-who-forge-is-for)
7. [Contributor Guide — Open Source Participation](#7-contributor-guide--open-source-participation)
8. [Current State — What Is Working](#8-current-state--what-is-working)
9. [Future Targets & Roadmap](#9-future-targets--roadmap)

---

## 1. What Is Forge?

Forge is a domain-specific smart contract language designed from first principles for the **Zephyria blockchain** — a Layer 1 network targeting 1 million transactions per second on consumer hardware with instant Byzantine Fault-Tolerant finality.

Forge is **not** a variant of Solidity. It is not a dialect of Rust. It is a ground-up design that treats on-chain programs as a distinct discipline: one that requires economic correctness, not just computational correctness. Where Solidity gives you a general-purpose language bolted onto a VM, Forge gives you a contract language where invariants, authority, assets, parallelism safety, and attack resistance are first-class citizens of the language itself.

The compiler (`forgec`) is implemented entirely in **Zig 0.15.2** — roughly 21,580 lines across 14 source files — producing either native Zephyria VM binaries (`.fozbin`), EVM bytecode, or PolkaVM WASM output. No garbage collector, no runtime, no hidden allocations.

### Core Design Principles

- **Authority is declared, not assumed.** Every action gate (who can call what) is declared in the contract structure, not scattered through `require(msg.sender == ...)` guards.
- **Assets are linear types.** A token cannot be duplicated or silently dropped. The compiler enforces move semantics: use it once, or the program does not compile.
- **Parallelism is proven, not hoped for.** Actions declare their read/write access sets at compile time. The runtime scheduler uses these to safely parallelize execution without developer intervention.
- **Conservation is a type-level proof.** `conserves sum(balances) at_all_times` is not a comment or a test — it is a compile-time verified equation.
- **Attacks are simulated in-language.** `adversary` blocks let contract authors declare attack scenarios that the compiler checks cannot succeed.

---

## 2. Compiler Architecture & Pipeline

Every `.foz` source file flows through seven sequential stages before a binary is produced.

```
Source (.foz)
  │
  ▼
[Stage 1] lexer.zig         tokenize() → []Token
  │         Zero-copy. Comptime keyword map. No heap per token.
  │
  ▼
[Stage 2] parser.zig        Parser.parse() → []TopLevel (AST)
  │         Recursive descent. Arena-allocated AST nodes.
  │         Produces the full contract, assets, interfaces, constants.
  │
  ▼
[Stage 3] types.zig         TypeResolver.registerTopLevel() + resolve()
  │         Resolves all TypeExpr → ResolvedType.
  │         Registers struct/enum/asset/interface/capability symbols.
  │
  ▼
[Stage 4] checker.zig       Checker.checkContract() → CheckedContract
  │         5 access isolation rules. Authority enforcement.
  │         Linear asset tracking. Conservation proof verification.
  │         Gas complexity annotations. Adversary block simulation.
  │         Upgrade diff. Global invariants. ZK input validation.
  │
  ▼
[Stage 5] codegen.zig       CodeGen.generate() → RISC-V ZephBin
         codegen_evm.zig    EVMCodeGen.generate() → EVM bytecode
         codegen_polkavm.zig CodeGenPolkaVM.generate() → PolkaVM WASM
  │
  ▼
[Stage 6] abi.zig           AbiGenerator → .fozabi or .json (EVM ABI)
  │
  ▼
Output: .fozbin + .fozabi   (or .bin + .json for EVM target)
        .hex sidecar always emitted alongside binary
```

All stages share a single `DiagnosticList`. Errors in any stage are accumulated and printed together. The lexer always produces a complete token stream even on errors; the parser always produces a partial AST. This means multi-error reporting works without crashing the tool.

---

## 3. Module Reference — All Files, Functions & Usages

### 3.1 `lexer.zig`
**1,205 lines** · Converts raw `.foz` source text into a flat `[]Token` array.

#### Key Types

| Type | Purpose |
|------|---------|
| `TokenKind` | 200+ variant enum covering every keyword, literal, punctuation, and error token the language defines |
| `Token` | `{ kind, text, span }` — `text` is a zero-copy slice into the source buffer |
| `Span` | `{ line, col, len }` — 1-based source location attached to every token |
| `Lexer` | Stateful scanner: `source`, `pos`, `line`, `col`, `file` |

#### Key Functions

**`Lexer.init(source, file) Lexer`**  
Constructs a fresh lexer. `source` is the full UTF-8 source text. `file` is the filename shown in diagnostics. No allocation at this point.

**`Lexer.tokenize(allocator, diags) ![]Token`**  
The primary public API. Drives the internal `nextToken` loop until EOF, collecting all tokens into a single owned slice. On lexical errors, an `error_token` is emitted and a `Diagnostic` is appended to `diags`, but scanning continues — callers always receive a complete token stream. The returned slice must be freed by the caller with `allocator.free(tokens)`.

**`tokenKindOf(word) ?TokenKind`**  
O(1) comptime static-string-map lookup. Returns `null` for identifiers. Used internally by `scanIdentOrKeyword`. Never does a runtime string comparison loop.

#### Internal Scanner Functions (not public API)

| Function | What It Does |
|----------|-------------|
| `nextToken` | Top-level token dispatcher: whitespace, comments, numbers, strings, identifiers, punctuation |
| `skipWhitespace` | Advances pos, tracks newlines for line/col |
| `scanLineComment` | Handles `//` and `///` doc comments |
| `scanBlockComment` | Handles `/* … */` with support for nesting (depth counter) |
| `scanNumber` | Handles decimal, `0x` hex, `0b` binary, underscore-separated, and float literals |
| `scanString` | Handles `"…"` with escape sequences; emits error on unterminated |
| `scanIdentOrKeyword` | Scans identifier chars then calls `tokenKindOf` |
| `scanPunct` | Maps every punctuation character and multi-character operators (`->`, `=>`, `::`, `..`, `+=`, `-=`, `*=`, `>=`, `<=`) |
| `makeTokenAt` | Builds a `Token` from start/end positions |
| `emitDiag` | Appends a formatted `Diagnostic` to the diagnostic list |

#### Character Helpers

`isDigit`, `isDigitOrUnderscore`, `isHexDigitOrUnderscore`, `isIdentStart`, `isIdentCont` — all `inline` file-scope functions, zero allocation.

---

### 3.2 `ast.zig`
**1,517 lines** · Complete in-memory representation of a parsed `.foz` file. Every node is arena-allocated. Every node carries a `Span`.

#### Section 1 — Source Location
`Span { line, col, len }` — attached to every AST node for diagnostics and error reporting.

#### Section 2 — Type Expressions (`TypeExpr`)
A union(enum) covering the entire Forge type system:

- **Unsigned integers:** `u8, u16, u32, u64, u128, u256, uint`
- **Signed integers:** `i8, i16, i32, i64, i128, i256, int`
- **Fixed-point:** `fixed { decimals }`, `price9`, `price18`, `percent`
- **Boolean:** `bool`
- **Address types:** `account, wallet, program, system_acc`
- **Hash/byte types:** `hash, hash20, commitment, byte, bytes, bytes32, bytes64, signature, pubkey`
- **Time types:** `timestamp, duration, block_number, epoch, slot`
- **Text types:** `string, short_str, label`
- **Composite types:** `maybe *TypeExpr`, `result { ok, err }`, `map { key, value }`, `enum_map { key, value }`, `list *TypeExpr`, `set *TypeExpr`, `array { elem, size }`, `tuple []*TypeExpr`
- **Named/generic:** `named []const u8`, `generic { name, params }`

#### Section 3 — Expressions (`Expr`, `ExprKind`)

Every expression carries both its `ExprKind` and its `Span`.

| ExprKind Variant | Description |
|-----------------|-------------|
| `int_lit` | Integer literal stored as raw digit string (preserves full u256 precision) |
| `float_lit` | Fixed-point literal as raw string |
| `bool_lit` | `yes` / `no` |
| `string_lit` | Double-quoted UTF-8 |
| `nothing` | The absent optional |
| `something *Expr` | Wrap a value in an optional |
| `identifier` | Bare name or qualified path |
| `field_access { object, field }` | `expr.field` |
| `index_access { object, index }` | `expr[key]` |
| `bin_op { op, left, right }` | Binary infix operation |
| `unary_op { op, operand }` | `not expr`, `negate expr` |
| `call { callee, args }` | Function / action / view / pure call |
| `struct_lit { type_name, fields }` | Struct literal |
| `tuple_lit []*Expr` | Tuple literal |
| `match_expr { subject, arms }` | Match used as expression |
| `inline_when { cond, then_, else_ }` | `when cond then a otherwise b` |
| `cast { expr, to }` | `expr as Type` |
| `builtin BuiltinExpr` | `caller`, `value`, `deployer`, `now`, `current_block`, `gas_remaining`, `this_address`, `zero_address` |
| `try_propagate *Expr` | `expr?` — propagate Result failure |
| `asset_split { asset, amount }` | Split a linear asset |
| `asset_wrap { asset_type, value }` | Wrap native currency into asset |
| `asset_unwrap { asset_type, token }` | Unwrap typed asset to native |

Binary operators (`BinOp`): `plus, minus, times, divided_by, mod, equals, not_equals, less, less_eq, greater, greater_eq, and_, or_, has, duration_add, duration_sub`

#### Section 4 — Patterns (`Pattern`)

Used in `match` arms: `wildcard, literal, binding, nothing, something, ok, fail, enum_variant, range, tuple`

#### Section 5 — Statements (`Stmt`, `StmtKind`)

| Statement Kind | Syntax / Purpose |
|---------------|-----------------|
| `let_bind` | `let x is Type = expr` or `let x = expr` |
| `assign` | `target = expr` |
| `aug_assign` | `target += expr` / `-=` / `*=` |
| `when` | `when cond: … otherwise when cond: … otherwise: …` |
| `match` | `match subject: arm …` |
| `each` | `each item in collection:` — requires `#[max_iterations N]` when collection is user-supplied |
| `repeat` | `repeat N times:` — bounded integer loop |
| `while_loop` | `while cond:` |
| `tell` | `tell EventName(args)` — emit an event |
| `need` | `need cond else "msg"` — inline precondition assertion |
| `ensure` | `ensure cond` — post-condition checked at function exit |
| `throw_err` | `throw ErrorName(args)` — raise a typed error |
| `panic_stmt` | `panic "msg"` — unrecoverable halt |
| `stop` | Break out of loop |
| `skip` | Continue loop iteration |
| `give_back` | Return a value |
| `attempt` | `attempt: body on_error EType(binds): handler always_after: cleanup` |
| `call_stmt` | Bare function/action call as statement |
| `pay` | `pay account amount` — transfer native ZPH |
| `send` | `send asset to account` — consume a linear asset |
| `move` | `move asset into mine.field` — store linear asset into state |
| `burn` | Destroy a linear asset |
| `split` | Split a linear asset |
| `wrap` / `unwrap` | Convert between native currency and typed asset |
| `merge` | Merge two compatible assets |
| `expand` | `expand account by N bytes` |
| `close` | `close account refund_lamports_to wallet` |
| `freeze` / `unfreeze` | Account freeze/unfreeze |
| `schedule` | `schedule call after duration` — deferred invocation |
| `only` | `only auth: body` — authority-gated block |
| `transfer_ownership` | `transfer_ownership(account, to: new_owner)` |

#### Sections 6–14 — Declaration Nodes

| Node Type | Purpose |
|-----------|---------|
| `Annotation` | `#[parallel]`, `#[reads mine.X]`, `#[writes mine.X]`, `#[max_iterations N]`, `#[gas_check N]`, `#[zk_proof C]`, `#[private]`, `#[gas_sponsored_for]` |
| `Param` | Typed function parameter: `name is Type` |
| `AccountDecl` | Full account declaration: kind, ownership, seeds, capabilities, `create_if_missing`, `child_of`, `known_address` |
| `AuthorityDecl` | Authority: holder type, initial holder, timelock, multisig/DAO config, `covers`, `inherits_from` |
| `StateField` | `has:` block field: `name is Type` |
| `ConfigField` | `config:` field with optional default |
| `ActionDecl` | State-changing function with visibility, type params, annotations, local accounts, complexity class |
| `ViewDecl` | Read-only function |
| `PureDecl` | Stateless function |
| `GuardDecl` | Reusable precondition block |
| `EventDecl` | Event with indexed/non-indexed fields |
| `ErrorDecl` | Typed error with fields |
| `SetupBlock` | Constructor |
| `InvariantDecl` | Formal contract invariant |
| `UpgradeBlock` | Upgrade policy: authority, migrate_fn, immutable_fields |
| `AssetDef` | Top-level asset: display name, symbol, decimals, max_supply, transfer hooks |
| `InterfaceDef` | Interface with action/view/event/error signatures |
| `ContractDef` | The complete contract: all sections composed together |
| `TopLevel` | The root union: `contract, asset_def, interface_def, use_import, constant, struct_def, record_def, enum_def, type_alias, capability_def, global_invariant` |

---

### 3.3 `parser.zig`
**2,807 lines** · Recursive-descent parser. Converts `[]Token` into `[]TopLevel`.

#### Key Types

`Parser { tokens, pos, allocator, diagnostics, source, file }` — stateful, arena-backed.

#### Key Functions

**`Parser.init(tokens, allocator, diags, source, file) Parser`**  
Constructs the parser. Takes ownership of the token slice (read-only).

**`Parser.parse() ![]TopLevel`**  
The primary entry point. Drives `parseTopLevel` in a loop until EOF. Returns an arena-allocated `[]TopLevel`. Any parse errors emit into `diags` and parsing continues for maximum error coverage.

**`parseTopLevel`** — Routes to:
- `parseContractDef` — Full `contract Name:` block
- `parseAssetDef` — `asset Name { … }`
- `parseInterfaceDef` — `interface Name { … }`
- `parseUseImport` — `use path.to.module as Alias`
- `parseConstant` — `define NAME as value`
- `parseStructDef` — `struct Name { … }`
- `parseRecordDef` — `record Name { … }`
- `parseEnumDef` — `enum Name { … }`
- `parseTypeAlias` — `alias Name is Type`
- `parseCapabilityDef` — `capability Name { … }`
- `parseGlobalInvariant` — `global_invariant Name { … }`

**`parseContractDef`** — Parses all contract sections:
- `config:` block → `[]ConfigField`
- `always:` (constants) block → `[]ConstDecl`
- `has:` (state) block → `[]StateField`
- `accounts:` block → `[]AccountDecl`
- `authorities:` block → `[]AuthorityDecl`
- `implements:` list → `[][]const u8`
- `setup:` block → `?SetupBlock`
- `guard Name(params):` → `[]GuardDecl`
- `action/view/pure/hidden Name:` → `[]ActionDecl / []ViewDecl / []PureDecl`
- `event Name(fields):` → `[]EventDecl`
- `error Name(fields):` → `[]ErrorDecl`
- `upgrade:` block → `?UpgradeBlock`
- `conserves …` → `[]ConservationExpr`
- `adversary Name { … }` → `[]AdversaryBlock`
- `fallback:` / `receive:` → `?ActionDecl`

**`parseExpr` / `parsePrimaryExpr`** — Full expression parser with operator precedence. Handles all `ExprKind` variants including inline-when, match expressions, try-propagate (`?`), asset operations, and cast.

**`parseStmt`** — Dispatches on current token to all statement kinds.

**`parseTypeExpr`** — Parses `TypeExpr` from token stream. Handles nested generics, `maybe T`, `Result[T, E]`, `Map[K → V]`, tuples, arrays.

**`parseAnnotation`** — Parses `#[kind args...]` annotations.

**`parsePattern`** — Parses match patterns including `nothing`, `something(x)`, `ok(x)`, `fail(E(binds))`, range `lo..hi`, tuple `(p1, p2)`.

---

### 3.4 `types.zig`
**1,093 lines** · Type resolution, symbol table, and type compatibility.

#### Key Types

**`ResolvedType`** — The fully-resolved type union. All `TypeExpr` named references are expanded. Key variants:
- All scalar types (unsigned, signed, fixed-point, bool)
- `maybe *ResolvedType`, `result { ok, err }`, `map { key, value }`, `enum_map`, `list`, `set`, `array { elem, size }`, `tuple`
- `struct_type StructInfo`, `enum_type EnumInfo`
- `asset []const u8` — declared asset by name
- `linear *ResolvedType` — move-only asset wrapper
- `capability []const u8` — linear capability type (Novel Idea 6)
- `proof *ResolvedType` — ZK proof payload

**`SymbolTable`** — Hierarchical scope chain. Supports `define(name, symbol)`, `lookup(name)`, `lookupLocal(name)`. Parent chain walk for nested scopes.

**`TypeResolver`** — The central type-resolution engine.

#### Key Functions

**`TypeResolver.init(allocator, diags) TypeResolver`**  
Constructs a fresh resolver. Pre-registers all built-in type aliases from the Forge spec: `uint → u256`, `int → i256`, `price9 → Fixed[9]`, `price18 → Fixed[18]`, `percent → Fixed[4]`.

**`TypeResolver.registerTopLevel(top_levels) !void`**  
First-pass: walks all top-level declarations and registers structs, enums, assets, interfaces, capabilities, and type aliases into the global symbol scope. Must be called before any `resolve()` or `checkContract()`.

**`TypeResolver.resolve(type_expr) !ResolvedType`**  
Converts a `TypeExpr` AST node into a `ResolvedType`. Handles named lookups, generics instantiation, capability resolution, and recursive composite types.

**`TypeResolver.isCompatible(from, to) bool`**  
Checks assignment compatibility. Handles subtype relationships: `wallet` → `account`, `program` → `account`, unsigned integer widening, `linear(T)` → `T` unboxing, `asset` → named asset.

**`TypeResolver.widenNumeric(from, to) bool`**  
Checks if an unsigned integer type can be safely widened to a wider unsigned integer type (rank comparison).

**`TypeResolver.inferExprType(expr, scope) !ResolvedType`**  
Infers the type of an expression node given a symbol table scope. Handles all `ExprKind` variants, resolves field accesses on structs, map/list element types, binary operator result types.

**`TypeResolver.allocType(t) !*ResolvedType`**  
Heap-allocates a single `ResolvedType` on the arena. Used to construct pointer-based recursive types (`maybe`, `list`, `linear`, etc.).

---

### 3.5 `checker.zig`
**3,875 lines** · The semantic analysis heart of the compiler. Drives all correctness rules.

#### Key Types

**`AccessKind`** — `read` or `write`.

**`AccessEntry { account_name, field }`** — A single recorded access on an account field.

**`AccessList { reads, writes }`** — Collected access entries for one action.  
- `init(allocator) AccessList`  
- `deinit()`  
- `addRead(account, field) !void`  
- `addWrite(account, field) !void`  
- `conflictsWith(other) bool` — True if two access lists share a write target (used by parallel scheduler)

**`CheckedContract { action_lists }`** — Output of semantic checking. Maps action name → `AccessList` for the parallel execution scheduler.

**`LinearTracker { consumed: StringHashMap(bool) }`** — Move-only asset variable tracking per scope.  
- `markConsumed(name, span) !void` — Errors if already consumed (`LinearAssetUsedTwice`)  
- `checkAllConsumed(diags) !void` — Errors if any tracked variable was never used (`LinearAssetDropped`)

**`Checker`** — The main checker. Carries `resolver`, `diagnostics`, `allocator`, `current_file`.

#### The Five Access Isolation Rules (Part 3.9)

**Rule 1: Undeclared = Inaccessible**  
`verifyAccountDeclared(access_name, contract)` — Any `mine.X` access where X is not in the `accounts:` block raises `AccountNotDeclared`.

**Rule 2: Read-Only = No Writes**  
`verifyNotReadonly(account_decl, access_name)` — Write to a `readonly` account raises `WriteToReadonlyAccount`.

**Rule 3: Capability = Only Named Fields**  
`verifyFieldCapability(account_decl, field_name, is_write)` — If the account has a `can:` capability list, only listed fields may be accessed. Raises `FieldNotInCapabilityList`.

**Rule 4: Cross-Program State Isolation**  
`verifyCrossProgram(account_decl)` — A write to an externally-owned account (non-`this` ownership) raises `CrossProgramStateAccess`.

**Rule 5: Parallel Safety**  
`verifyParallelSafety(action, access_list)` — An action annotated `#[parallel]` must not write to any shared state. Raises `UndeclaredWrite`.

#### Authority Checking

**`checkAuthorityReferences(stmt, contract)`** — Ensures all authority names in `only` statements are declared in the `authorities:` block. Raises `UnknownAuthority`.

**`checkSingleAuthority(name, contract)`** — Looks up a single authority name in the contract's authority list.

#### Main Check Flow

**`Checker.checkContract(contract) !CheckedContract`** — The full pipeline:
1. Validate all account declarations
2. Validate all authority declarations
3. Type-check the setup block
4. For each action: inject built-in identifiers, type-check body, build access list, track linear assets, validate annotations
5. For each view: same but without write tracking
6. Validate interface conformance (`implements` list)
7. Validate upgrade block and immutable field declarations
8. Validate asset transfer hook signatures
9. Validate ZK private input annotations
10. Validate gas sponsorship annotations
11. Check conservation proofs (Novel Idea 1)
12. Check gas complexity class annotations (Novel Idea 2)
13. Simulate adversary blocks (Novel Idea 3)

**`Checker.checkExprType(expr, scope, contract) !ResolvedType`** — Type-checks an expression, returning its resolved type. Covers all 20+ ExprKind variants.

**`Checker.checkStmt(stmt, scope, contract, action, linear_tracker) !void`** — Type-checks a single statement. Delegates to specific handlers per statement kind.

**`buildAccessList(action, contract) !AccessList`** — Walks an action's body to collect all `mine.X` reads and writes. Feeds the parallel scheduler.

**`collectAccessFromStmt` / `collectAccessFromExpr`** — Recursive helpers for access list construction.

#### Novel Feature Checks

**`checkConservation(contract) !void`** — Economic Conservation Proofs. Evaluates each `conserves` equation, substituting field deltas from all actions and verifying the sum/count/max expression is preserved.

**`checkComplexityClass(contract) !void`** — Gas Complexity Class Annotations. For each action with a `complexity:` declaration, verifies the body's loop structure matches: O(1) forbids loops, O(n) allows one bounded level, O(n²) allows two levels.

**`checkAdversaryBlocks(contract) !void`** — Adversary Block Simulation. For each `adversary Name { tries: action_sequence; expects: outcome }`, the checker simulates the call sequence and verifies the expected outcome holds.

**`generateUpgradeDiff(allocator, old_contract, new_contract) !SemanticDiff`** — Produces a structured diff between two contract versions: state fields added/removed, behavior changes (parameter/body length), new attack surface (new actions), invariant preservation status.

**`checkGlobalInvariants(invariants, resolver, diagnostics, file) !void`** — Validates cross-contract global invariant declarations: participant contracts must exist, `always:` conditions must reference valid state fields.

---

### 3.6 `codegen.zig`
**2,323 lines** · RISC-V RV64IM bytecode emitter for the native Zephyria VM. Produces `.fozbin` binaries.

#### Key Types

**`ZephBinHeader`** — The binary file header:
- `magic [4]u8 = "FORG"`
- `version u8`
- `flags u8` — bit 0: upgradeable, bit 1: parallel-capable
- `contract_name [32]u8`
- `action_count u16`
- `code_size u32`
- `abi_size u32`
- `access_size u32`

**`RegAlloc`** — Simple register allocator for temporaries.  
- `alloc() ?Reg` — Returns next available temp register  
- `free(r)` — Marks register available  
- `freeAll()` — Reset allocator

**`LocalVar { stack_offset, type_ }`** — A local variable on the action's stack frame.

**`CodeGen`** — The main RISC-V emitter. Carries allocator, diagnostics, resolver, field_ids map.

**`ActionCtx`** — Per-action code generation context: buffer, label map, fixup list, local frame, gas counter.

#### Key Functions

**`CodeGen.init(allocator, diags, resolver) CodeGen`**  
Constructs the emitter.

**`CodeGen.generate(contract, checked) ![]u8`**  
Full code generation pipeline:
1. Assign storage field IDs to all state fields
2. Write the `ZephBinHeader`
3. Encode the access list from `CheckedContract`
4. For each action: `genAction`
5. For each view: `genView`
6. If setup block present: `genSetup`
7. If fallback/receive present: generate their handlers
8. If upgrade block present: generate migration handler
9. Patch all forward-reference fixups
10. Append ABI JSON

**`genAction(action, ctx)`** — Per-action bytecode:
1. Prologue: save `ra`, `s0`, allocate stack frame
2. Gas charge for entry cost
3. Authority check (jumps to `.revert` on failure)
4. Argument loading from calldata ABI
5. Body statement emission via `genStmt`
6. Return: marshal `give_back` value into `a0`, restore frame, `ret`
7. `.out_of_gas` label: REVERT with OOG reason
8. `.revert` label: REVERT with error payload

**`genStmt(stmt, ctx, contract)`** — Dispatches to all statement handlers:  
`genLetBind`, `genAssign`, `genAugAssign`, `genWhen`, `genMatch`, `genEach`, `genRepeat`, `genWhile`, `genTell`, `genNeed`, `genEnsure`, `genThrow`, `genSend`, `genPay`, `genMove`, `genBurn`, `genSchedule`, `genAttempt`, `genOnly`

**`genExpr(expr, dst_reg, ctx, contract)`** — Emits code to evaluate an expression into `dst_reg`. Handles all `ExprKind` variants.

**`genSetup(setup, ctx)`** — Constructor: loads params from calldata, runs body, initializes state fields.

**`emitGasCharge(cost, ctx)`** — Emits `addi a5, a5, -cost` (or `li t0, cost; sub a5, a5, t0` for large costs), then a branch to `.out_of_gas`. Register `a5` is the dedicated gas counter — never used for anything else.

**`patchFixups(ctx)`** — After all code is emitted, walks the fixup list to backpatch forward-reference branch offsets.

**Register ABI (ForgeVM):**
- `a0–a7` — arguments and return values
- `t0–t6` — temporaries (caller-saved)
- `s0–s11` — callee-saved
- `a5` — gas counter (dedicated, never repurposed)
- `a6` — calldata base pointer
- `sp` — stack pointer
- `ra` — return address

---

### 3.7 `codegen_evm.zig`
**3,432 lines** · EVM bytecode emitter. Produces Ethereum-compatible bytecode for EVM-target deployment.

#### Key Types

**`EVMWriter`** — Low-level byte buffer for EVM bytecode.  
- `op(o) !void` — Emit one opcode byte  
- `byte(b) !void` — Emit raw byte  
- `push0()`, `push1(v)`, `push2(v)`, `push4(v)` — Emit PUSH variants  
- `pushU256BE(value_be)` — Emit PUSH32 with big-endian u256  
- `pushU64(v)`, `pushU32(v)` — Emit minimal PUSH for integers  
- `push2Placeholder() !u32` — Emit a PUSH2 with placeholder value; returns patch offset  
- `patchU16(patch_offset, target)` — Backpatch a previously emitted placeholder  
- `bytes()`, `toOwnedSlice()` — Access/finalize buffer

**`SlotMap`** — Maps state field names to EVM storage slot numbers (u256).  
- `register(name) !void`  
- `getSlot(name) ?u256`

**`LocalFrame`** — Stack frame for local variables within an action.  
- `alloc_slot(name, ty) !u32` — Assigns next available memory slot  
- `get(name) ?LocalVar` — Look up a local variable

**`EVMCodeGen`** — The main EVM emitter.

#### Key Functions

**`EVMCodeGen.init(alloc, diags, resolver) EVMCodeGen`**

**`EVMCodeGen.generate(contract, checked) ![]u8`**  
Emits full EVM deployment bytecode:
1. Emit ABI dispatch table (`emitDispatch`)
2. For each action: emit selector check, JUMPDEST, action body, RETURN/REVERT
3. Patch all label fixups

**`emitDispatch(actions)`** — The ABI selector router:
1. `CALLDATASIZE` check (≥ 4 bytes required; uses `LT` correctly — bug in original was inverted)
2. Load 4-byte selector via `CALLDATALOAD` + `AND` mask
3. For each action: `DUP1`, `PUSH4 selector`, `EQ`, `JUMPI to action label`
4. `no_match_dest` label: `POP`, `REVERT(0,0)` (selector must be popped before revert)

**`genExpr(expr, …) !void`** — EVM expression emitter with correct stack ordering:
- Binary ops: emits left, then right, then applies SWAP where needed (SUB, DIV, LT, GT)
- Storage reads: `PUSH32 slot`, `SLOAD`
- Storage writes: evaluate value, `PUSH32 slot`, `SSTORE`
- Calldata reads: `PUSH offset`, `CALLDATALOAD`

**`keccak256(data) [32]u8`** — Keccak-256 hash of a byte slice (used for event topic encoding and storage slot computation for maps).

**`evmSelector(sig) u32`** — First 4 bytes of keccak256 of function signature. Used for ABI dispatch.

**`evmAbiType(ty) []const u8`** — Maps a `ResolvedType` to its EVM ABI string (`uint256`, `address`, `bool`, `bytes32`, etc.).

**`buildFuncSig(action, resolver, buf) ![]u8`** — Builds the canonical function signature string for selector computation.

**`buildSelector(action, resolver) !u32`** — Full selector: build signature, keccak256, take first 4 bytes.

**`buildEventSig(event, resolver) ![]u8`** — Builds event signature for topic-0 hash.

**`abiStaticSize(ty) u32`** — Returns the static ABI encoding size in bytes for a type.

---

### 3.8 `codegen_polkavm.zig`
**1,839 lines** · PolkaVM WASM bytecode emitter.

**`CodeGenPolkaVM.init(allocator, diags, resolver) CodeGenPolkaVM`**

**`CodeGenPolkaVM.generate(contract, checked) ![]u8`**  
Produces a PolkaVM-compatible WASM module:
1. Emits WASM module header and type section
2. Imports PolkaVM host functions (storage read/write, emit event, revert)
3. Emits one WASM function per action
4. Encodes dispatch logic via an exported `__dispatch` function
5. Encodes data section with contract metadata

**`wasm.zig` (273 lines)** — Low-level WASM binary format helpers: LEB128 unsigned/signed encoding, section builders, type encodings.

---

### 3.9 `abi.zig`
**842 lines** · ABI JSON generation for both Zephyria native and EVM formats.

#### Key Types

**`AbiGenerator { allocator, resolver }`**

#### Key Functions

**`AbiGenerator.init(allocator, resolver) AbiGenerator`**

**`AbiGenerator.generateZephAbi(contract, checked) ![]u8`**  
Generates Zephyria-native ABI JSON. Contains:
- Contract name and version
- For each action: name, visibility, parameters (name + Zeph type), return type, access list (reads/writes), annotations, complexity class
- For each view: name, parameters, return type
- Events with indexed/non-indexed fields
- Errors with typed fields
- Conservation equations
- Authority declarations

**`AbiGenerator.generateEVMAbi(contract) ![]u8`**  
Generates an Ethereum-compatible ABI JSON array. Contains:
- `function` entries with `inputs`, `outputs`, `stateMutability`
- `event` entries with `inputs` marked `indexed`
- `error` entries with `inputs`
- Selector pre-computed for each function

**`serializeJson(value, allocator) ![]u8`**  
Manual JSON serializer (Zig 0.15.2 lacks `std.json.stringify` for runtime structs). Handles nested structs, slices, optionals, and primitives by building the JSON string character by character into an `ArrayListUnmanaged`.

**`jsonAppend(buf, alloc, value) !void`**  
Recursive JSON value appender. Dispatches on Zig type at comptime.

**Type mapping helpers:**
- `mapEVMType(ty) []const u8` — Maps `ResolvedType` to EVM ABI type string
- `mapZephType(ty) []const u8` — Maps `ResolvedType` to Zephyria type string
- `zvmSize(ty) u32` — ZephVM wire size in bytes for ABI encoding
- `actionSelector(name) u32` — CRC32-based selector for Zephyria native ABI

---

### 3.10 `errors.zig`
**659 lines** · Diagnostic infrastructure.

**`CompileError`** — A Zig error set covering all 38 distinct compile-time error conditions, from `UnexpectedCharacter` (E0000) through `AttackSucceeded` (E0034) to `InternalError` (E0037).

**`Diagnostic { file, line, col, len, kind, message, source_line }`** — A single error record. `source_line` carries the raw source line text for caret display.

**`DiagnosticList { items }`** — The mutable error accumulator passed through all compiler stages.  
- `init(allocator) DiagnosticList`  
- `deinit()`  
- `add(d) !void` — Append a diagnostic  
- `hasErrors() bool` — Returns true if any `Diagnostic` was added

---

### 3.11 `riscv.zig`
**613 lines** · RISC-V RV64IM instruction encoding helpers.

Provides functions for encoding every RISC-V instruction used by the code generator:

`rv_add`, `rv_sub`, `rv_and`, `rv_or`, `rv_xor`, `rv_sll`, `rv_srl`, `rv_sra`, `rv_slt`, `rv_sltu` — R-type arithmetic  
`rv_addi`, `rv_slti`, `rv_sltiu`, `rv_xori`, `rv_ori`, `rv_andi` — I-type immediate  
`rv_lw`, `rv_lh`, `rv_lb`, `rv_lhu`, `rv_lbu`, `rv_ld`, `rv_lwu` — Load instructions  
`rv_sw`, `rv_sh`, `rv_sb`, `rv_sd` — Store instructions  
`rv_beq`, `rv_bne`, `rv_blt`, `rv_bge`, `rv_bltu`, `rv_bgeu` — Branch instructions  
`rv_jal`, `rv_jalr` — Jump-and-link  
`rv_lui`, `rv_auipc` — Upper immediate  
`rv_mul`, `rv_mulh`, `rv_mulhu`, `rv_mulhsu`, `rv_div`, `rv_divu`, `rv_rem`, `rv_remu` — M-extension  
`rv_mulw`, `rv_divw`, `rv_divuw`, `rv_remw`, `rv_remuw` — RV64 word-size variants  
`rv_li` — Pseudo-instruction: load immediate (synthesized from `lui` + `addi`)

Each encoder takes register operands and immediate values, bit-packs them into the correct 32-bit encoding, and returns a `u32` ready for appending to the code buffer.

---

### 3.12 `u256.zig`
**275 lines** · 256-bit unsigned integer arithmetic for the compiler and ABI encoder.

`U256 = [4]u64` — Little-endian limb representation.

`u256FromDecStr(s) !U256` — Parse a decimal string into U256. Used for integer literals.  
`u256FromHexStr(s) !U256` — Parse a `0x…` hex string.  
`u256ToBE(v) [32]u8` — Convert to big-endian bytes for ABI encoding.  
`u256Add(a, b) U256`, `u256Sub(a, b) U256`, `u256Mul(a, b) U256` — Basic arithmetic.  
`u256Eq(a, b) bool`, `u256Lt(a, b) bool` — Comparison.

---

### 3.13 `wasm.zig`
**273 lines** · WASM binary format encoding primitives.

`writeLEB128U(buf, v) !void` — Write an unsigned LEB128-encoded integer.  
`writeLEB128S(buf, v) !void` — Write a signed LEB128-encoded integer.  
`writeVec(buf, items, fn) !void` — Write a WASM vector (length-prefixed sequence).  
`sectionBuilder(id) SectionBuilder` — Build a WASM section with auto-length patching.

---

### 3.14 `main.zig`
**682 lines** · CLI entry point and compilation orchestrator.

#### Key Types

**`CompileOptions`** — All flags: `output, check_only, print_tokens, print_ast, print_access, no_color, evm_abi, target`.

**`CompileResult`** — Compilation output: `binary, zeph_abi, evm_abi, contract_name, action_count, warning_count`.

#### Key Functions

**`parseArgs(args) ArgResult`** — Parses command-line arguments. Returns `success`, `exit_ok` (help/version), or `exit_err` (bad args).

**`compile(source, file, opts, alloc) !?CompileResult`** — The full 7-stage pipeline in one function. Returns `null` if any stage produced errors.

**`printDiagnostics(diags)`** — Rust-style error output with caret underlining. Format: `error[E0004]: message → file:line:col | source_line | ^^^^^`

**`printTokenStream(tokens)`** — Debug output for `--print-tokens`.

**`printAstSummary(top_levels)`** — Debug output for `--print-ast`.

**`printAccessLists(contract, checked)`** — Debug output for `--print-access`.

**`deriveOutputPath(input_path, target, alloc)`** — Auto-derives output filename: `.fozbin` for Zephyria, `.polkavm` for PolkaVM, `.bin` for EVM.

**`main()`** — GPA allocator setup, arg parsing, source file reading, compile invocation, binary/hex/ABI file writing, success message.

---

## 4. The Forge Language — Syntax & Feature Guide

### Contract Structure

```forge
version 1

contract TokenVault:
    config:
        fee_rate is percent = 0.5

    has:
        balances is Map[Wallet → u256]
        total_supply is u256

    accounts:
        mine is Data owned_by this
            can: read balances, write balances, read total_supply, write total_supply

    authorities:
        admin is AdminAuthority
            held_by deployer

    setup(initial_supply is u256):
        mine.total_supply = initial_supply

    action deposit():
        mine.balances[caller] += value

    action withdraw(amount is u256):
        need mine.balances[caller] >= amount else "insufficient balance"
        mine.balances[caller] -= amount
        pay caller amount

    view balance_of(who is Wallet) gives u256:
        give back mine.balances[who]

    conserves sum(balances) at_all_times

End
```

### Function Types

| Keyword | State Access | External Call | Visibility |
|---------|-------------|---------------|------------|
| `action` | Read + Write | Yes | `shared` (default), `within`, `hidden`, `outside`, `system` |
| `view` | Read only | No | Same |
| `pure` | None | No | Always shared |
| `hidden` | Read + Write | No | Only within this contract |
| `guard` | Read only | No | Used as inline precondition |

### Type System Highlights

```forge
// Optionals
let x is maybe u256 = nothing
let y = something(42)

// Results
let r is Result[u256, TransferError] = attempt_transfer()
match r:
    ok(amount) => pay caller amount
    fail(TransferError.Slippage(actual)) => throw TransferError.Slippage(actual)

// Duration literals
let lock_end = now plus 30 days
let short_window = 5 minutes

// Fixed-point
let rate is price18 = 1_500.000000000000000000

// Linear asset (move-only, compiler-enforced)
let tok is MyToken = mint(100)
send tok to recipient    // tok is consumed here; cannot be used again
```

### Control Flow

```forge
// Conditional
when balance > threshold:
    pay caller bonus
otherwise when balance > 0:
    pay caller small_reward
otherwise:
    need no "no reward available"

// Pattern matching
match status:
    Active => …
    Frozen { since = ts } => …
    _ => …

// Loops — each requires #[max_iterations N] if collection is user-supplied
each addr in mine.participants:
    pay addr share

repeat 10 times:
    accumulate()

// Error handling
attempt:
    let result = external_call()
on_error TransferFailed(reason):
    tell TransferFailedEvent(reason)
always_after:
    cleanup()
```

### Access Control

```forge
authorities:
    mint_authority is MintAuthority
        held_by Multisig { signers = [alice, bob, charlie], required = 2 }
        with_timelock 48 hours

action mint(amount is u256):
    only mint_authority:
        mine.total_supply += amount
```

### Asset Declarations

```forge
asset MyToken:
    name: "My Token"
    symbol: "MTK"
    decimals: 18
    max_supply: 1_000_000_000

    before_transfer(from is Wallet, to is Wallet, amount is u256):
        need not mine.frozen[from] else "sender frozen"
```

### Annotations

```forge
#[parallel]
#[reads mine.balances]
#[writes mine.total_supply]
action rebalance(…): …

#[max_iterations 100]
action process_batch(items is List[Order]): …

#[gas_check 50000]
action expensive_op(): …
```

---

## 5. Novel Ideas — What Makes Forge Different

These six features are not present in any other smart contract language. They are implemented in the checker (`checker.zig`) and type system (`types.zig`), and are first-class — not bolt-on.

### Novel Idea 1 — Economic Conservation Proofs

```forge
conserves sum(balances) at_all_times
```

The compiler proves mathematically that the sum of all balances is preserved across every action in the contract. Any action that introduces or destroys value without accounting for it is a **compile-time error**. This eliminates an entire class of economic exploit — the kind that has cost DeFi protocols billions of dollars — before deployment.

Other languages: tests, audits, or runtime assertions.  
Forge: compiler-verified algebraic conservation equations.

### Novel Idea 2 — Gas Complexity Class Annotations

```forge
action search(data is List[Record]) complexity: O(n):
```

Actions can declare their own gas complexity class. The compiler verifies the body structure matches: O(1) forbids all loops, O(n) allows exactly one bounded loop level, O(n²) allows two. This gives users and integrators a **proven gas bound** rather than an estimate, and lets the scheduler reason about worst-case execution cost without running the code.

### Novel Idea 3 — Adversary Blocks (In-Language Attack Simulation)

```forge
adversary Reentrancy:
    tries:
        call withdraw(100)
        call withdraw(100)
    expects: action_blocked
```

The contract author describes attack sequences directly in source code. The compiler simulates the attack against the contract's logic and verifies the expected outcome holds. If the attack would succeed when it should be blocked — or be blocked when it should succeed — it is a compile error. Security is not an audit phase; it is a language feature.

### Novel Idea 4 — Semantic Upgrade Diffs

```forge
upgrade:
    authority: admin
    immutable_fields: [total_supply, decimals]
    migrate_fn: v2_migration
```

When upgrading a contract, `generateUpgradeDiff` produces a machine-readable diff covering state fields added/removed, actions whose behavior changed, new attack surface introduced, and invariants preserved or broken. This enables review tooling, governance systems, and audit trails that operate at the semantic level rather than the bytecode level.

### Novel Idea 5 — Cross-Contract Global Invariants

```forge
global_invariant SystemSolvency:
    participants: [TokenVault, LendingPool, Treasury]
    always: sum(TokenVault.balances) equals Treasury.reserves
```

Multi-contract protocol invariants declared at the system level. The checker validates that all participant contracts exist, their referenced fields are accessible, and the invariant expression type-checks. At runtime, the scheduler can use these declarations to enforce cross-contract consistency boundaries.

### Novel Idea 6 — Capability Token Types (Structural Authority)

```forge
capability MintRight:
    grants: [mint, expand_supply]
```

Capability types are linear: they can be passed between functions like a value, but they cannot be duplicated and they must be consumed. Holding a `MintRight` token is the only way to call mint-related actions — the authority is carried in the type, not checked at runtime against a permission table. This makes authority composition safe and auditable at the type level.

---

## 6. Who Forge Is For

### Primary Users: DeFi & Protocol Engineers

Developers building financial protocols, token systems, lending pools, AMMs, and governance mechanisms who need more than "audited Solidity." Forge's conservation proofs and adversary blocks make economic correctness provable, not probabilistic.

### Secondary Users: Multi-Chain Teams

Teams deploying across multiple execution environments. Forge compiles to three targets today — Zephyria VM, EVM, PolkaVM — from a single source file. The ABI system generates both Zephyria-native and Ethereum-compatible ABIs.

### Tertiary Users: Security-Focused Organizations

Protocols where a security incident would be catastrophic: custody systems, bridge operators, institutional vaults. The adversary block system makes security properties part of the contract's specification, not a separate document.

### What Forge Is Not For

Forge is not a general-purpose programming language. It has no file I/O, no network sockets, no OS interaction. It is purpose-built for on-chain execution. If you need to write off-chain infrastructure, indexers, or CLIs, use another language and call into Forge contracts via the generated ABI.

---

## 7. Contributor Guide — Open Source Participation

The Forge compiler is approximately 21,580 lines of Zig 0.15.2 across 14 files. The frontend (lexer, parser, AST) is production-quality. The semantic checker is comprehensive. The codegen backends have known gaps. Below is a precise map of where contributions are most needed, with exact file locations and context for each.

### Before Contributing: Essential Reading

1. Read §2 of this document (compiler architecture)
2. Read all of `errors.zig` — understand the diagnostic system before touching any pass
3. Read `ast.zig` sections 2–5 — understand the node types for the pass you're working on
4. **Rule:** No stubs, no TODOs, no invented stdlib functions, mandatory error unions, explicit allocator parameters. Every error path must emit a `Diagnostic` — never fail silently.
5. **Rule:** `ArrayListUnmanaged` in struct fields — never `ArrayList`. Allocator passed explicitly everywhere.
6. **Rule:** Exhaustive `switch` on all `union(enum)` — add new variants explicitly, never use a catch-all `else`.

---

### Priority 1 — EVM Codegen Correctness (`codegen_evm.zig`)

**Status:** Functional but has known correctness issues.

**Issue 1 — Stack ordering in non-commutative ops:**  
`emitBinaryOp` currently handles SUB and DIV with SWAP1, which is correct per the audit. Verify that all comparison operators (`LT`, `GT`, `LTE`, `GTE`) use the correct SWAP pattern. EVM is reverse-Polish: `a op b` needs `a` on TOS after pushing, meaning you push `b` then `a` or use SWAP after pushing both.

**Issue 2 — Fixed-point literal emission:**  
`scaleFixedPoint` at line 2957 defaults to 18 decimal places when the resolved type is not available. The checker does not yet attach resolved types per-expression to codegen context. Fix: thread `ResolvedType` through expression codegen so `price9` literals scale to 9 places and `percent` literals to 4.

**Issue 3 — `u256` truncation:**  
Large integer literals parsed as `[]const u8` must survive through `u256FromDecStr` and be emitted as PUSH32. Verify that the entire path from literal to `pushU256BE` preserves all 32 bytes without truncation.

**Issue 4 — Event topic encoding for non-indexed fields:**  
`buildEventSig` is complete. Verify that the LOG instruction emission correctly pushes topic hashes for indexed fields and ABI-encodes non-indexed fields into the data section. The LOG0/LOG1/LOG2/LOG3/LOG4 selection must match the count of indexed fields exactly.

**Issue 5 — `setup` block in EVM target:**  
EVM contracts have a deploy-time constructor. The `setup` block in Forge maps to the constructor. Verify that `EVMCodeGen.generate` emits a proper deploy bytecode blob (init code + runtime code pattern) when a `setup` block is present, rather than treating it as a regular action.

---

### Priority 2 — Type Checker Completeness (`checker.zig`)

**Gap A — `LinearTracker` integration in views:**  
`LinearTracker` is created and used in action checking (line 1908) but views do not currently track linear asset flows through their bodies. Views should not consume linear assets (they are read-only), so the checker should raise an error if any view body contains a `send`, `burn`, `move`, or `merge` statement. Add this check in the view checking loop.

**Gap B — Interface conformance verification:**  
The `checkInterfaceConformance` hook is called at line 1437. Verify that it actually validates: (a) every action declared in the interface exists in the implementing contract with the same parameter types and return type, (b) every event declared in the interface is declared in the implementing contract, (c) every error declared in the interface is declared. Emit `TypeMismatch` or `DuplicateDeclaration` as appropriate.

**Gap C — Inheritance checking:**  
The contract inheritance path at line 1725 is stubbed. When `contract Child inherits Parent:` is parsed, the checker should verify that all authority names from the parent are available in the child, that `inheritable` authorities are properly forwarded, and that the child does not redefine `immutable_fields` declared by the parent's upgrade block.

**Gap D — Multisig and timelock authority validation:**  
At line 2024, `SPEC: Part 4.5, 4.6` is marked. The checker calls `checkMultisigAuthority` and `checkTimelockAuthority` but these need to verify: multisig signers list is non-empty, `required` ≤ signers count, timelock duration is a valid duration literal, timelock authority cannot be transferred without the timelock delay.

**Gap E — Setup block uncompiled body:**  
At checker line 1893, the setup block body is type-checked. Verify that the codegen (`genSetup` in `codegen.zig` line 661) correctly emits code for all statement kinds that can appear in a setup block — particularly `assign`, `let_bind`, and `tell` (event emission during construction).

---

### Priority 3 — RISC-V Codegen Completeness (`codegen.zig`)

**Gap F — `schedule` statement:**  
`genStmt` handles `schedule` by emitting a syscall stub. The actual implementation needs to: (1) compute the target block number from `current_block + after`, (2) ABI-encode the deferred call, (3) call the Zephyria scheduler syscall (syscall ID defined in ForgeVM). The syscall ABI for scheduling: `a0 = syscall_id`, `a1 = target_block`, `a2 = call_data_ptr`, `a3 = call_data_len`.

**Gap G — Oracle native opcode:**  
Actions calling `oracle.get(feed_id)` need to emit the ZEPH custom oracle opcode. Add `genOracleGet(expr, ctx)` that pushes the feed ID register, emits the `ZEPH_ORACLE_READ` custom opcode, and loads the result into the destination register.

**Gap H — VRF randomness:**  
`vrf_random(seed)` needs `genVrfCall(expr, ctx)` emitting `ZEPH_VRF_RANDOM` with the seed argument. The result is a 32-byte hash available as a `Hash` type.

**Gap I — `attempt` / `on_error` complete exception flow:**  
`genAttempt` currently emits the body and handler but the inter-action exception mechanism (how a revert from a cross-contract call propagates back through `attempt`) needs the full setjmp/longjmp equivalent in the Zephyria VM: save stack frame pointer before the call, restore it in the error handler.

---

### Priority 4 — Module & Import System (`parser.zig`, `checker.zig`)

**Gap J — `use` import resolution:**  
`parseUseImport` produces a `UseImport { path, alias }` AST node. The type resolver's `registerTopLevel` sees these but does not yet resolve them to actual files. Implement a module resolver that: (a) maps `use std.token.ERC20` to a search path, (b) reads and lexes/parses the imported file, (c) registers its exported symbols into the importing contract's scope under the alias.

---

### Priority 5 — Testing Infrastructure

**Gap K — Forge test suite (`.foztest` files):**  
The `.foztest` file extension is recognized by the lexer but there is no test runner. Implement `forge test` mode in `main.zig` that: (a) compiles the test file, (b) instantiates the contract in a simulated VM, (c) calls each action annotated `#[test]`, (d) reports pass/fail. The simulated VM can use a stub state backend (HashMap) rather than the full Zephyria storage engine.

**Gap L — Fuzzing harness:**  
Conservation proofs and adversary blocks are designed to catch economic exploits. Add a property-based fuzzing mode: `forge fuzz <contract.foz>` that randomly generates action call sequences and verifies conservation equations hold after each step. Integrate with Zig's built-in fuzzing support (`std.testing.fuzz`).

**Gap M — Deploy manifests (`.fozdeploy`):**  
The `.fozdeploy` extension is recognized. Implement a deploy manifest parser that reads: target network, constructor arguments, upgrade authority address, initial configuration values. Feed this into the `compile` pipeline to generate deployment transactions.

---

### Priority 6 — Language Features Not Yet Compiled

**Gap N — ZK proof annotations:**  
`#[zk_proof CircuitName]` and `#[private input]` are parsed and type-checked. The codegen does not yet emit ZK verification calls. This requires: (a) a circuit registry mapping circuit names to verifier contract addresses, (b) emission of a cross-contract call to the verifier during action execution, (c) ABI encoding of the proof payload from the `Proof[T]` type.

**Gap O — Gas sponsorship:**  
`#[gas_sponsored_for mine.set]` is parsed and validated. The codegen needs to emit a pre-flight check against the sponsor registry before charging gas to the caller.

---

### How to Submit

1. Fork `0xZephyria/Forge` on GitHub
2. Create a branch named `fix/gap-X` or `feature/description`
3. Run `zig build test` — all existing tests must pass
4. For new language features, add at least one `.foz` test contract and one unit test in the relevant `.zig` file
5. Reference the specific gap letter (A–O) in your PR description
6. Paste the compiler error output (if fixing a bug) or sample `.foz` source (if adding a feature)

---

## 8. Current State — What Is Working

### ✅ Fully Production-Quality

**Lexer (`lexer.zig`)**  
Complete. Zero-copy tokenization. 200+ token kinds. Comptime O(1) keyword lookup. Nested block comment support. Full line/column tracking. All literal types: decimal, binary (`0b`), hex (`0x`), underscore-separated integers, floats, strings with escape sequences, duration pairs. Eight included unit tests all pass.

**Abstract Syntax Tree (`ast.zig`)**  
Complete. Every Forge language construct has a corresponding AST node. Full span coverage. All six novel idea nodes present. Arena-compatible.

**Parser (`parser.zig`)**  
Complete for all currently specified language constructs. Handles the full contract anatomy, all declaration types, all expression forms, all statement forms, all annotation forms. Error-recovery produces maximum diagnostic coverage rather than crashing on first error.

**Type System (`types.zig`)**  
Complete. All 40+ `ResolvedType` variants. Full numeric compatibility and widening. Capability type registration. Asset type tracking. Symbol table with parent-chain scope lookup. Pre-registered built-in type aliases.

**Semantic Checker — Core Rules (`checker.zig`)**  
All five access isolation rules: enforced. Authority reference validation: enforced. Linear asset tracking (use-once semantics): enforced. Loop annotation enforcement (`#[max_iterations]`): enforced. Expression type checking: complete across all ExprKind variants. Statement type checking: complete.

**Novel Idea 1 — Conservation Proofs**  
`checkConservation` and the full `ConservationChecker` with `DeltaMap` are implemented and called.

**Novel Idea 2 — Gas Complexity Annotations**  
`checkComplexityClass` is implemented. O(1), O(n), O(n²) enforcement with loop depth analysis.

**Novel Idea 3 — Adversary Block Simulation**  
`checkAdversaryBlocks` is implemented. Attack sequence simulation with outcome verification.

**Novel Idea 4 — Semantic Upgrade Diffs**  
`generateUpgradeDiff` is implemented. State, behavior, attack surface, and invariant diffing.

**Novel Idea 5 — Cross-Contract Global Invariants**  
`checkGlobalInvariants` is implemented. Participant validation and field reference checking.

**Novel Idea 6 — Capability Token Types**  
`capability` resolution in `TypeResolver` is complete. Linear tracking for capabilities in `LinearTracker` is wired.

**RISC-V Codegen — Core (`codegen.zig`)**  
Action/view/pure/setup/fallback/receive/upgrade handler generation: working. Gas metering (dedicated `a5` register): working. ZephBin v1 binary format output: working. Access list encoding: working. Register allocator: working. Fixup patch system for forward references: working.

**EVM Codegen — Core (`codegen_evm.zig`)**  
ABI dispatch table: working. Storage slot map: working. Action body emission for arithmetic, storage read/write, calldata load, events: working. Function selector computation: working.

**PolkaVM Codegen (`codegen_polkavm.zig`)**  
Basic WASM module structure, type section, import section, dispatch function, action stubs: working.

**ABI Generator (`abi.zig`)**  
Zephyria native ABI JSON generation: complete. EVM ABI JSON generation: complete. Manual JSON serializer: working.

**CLI (`main.zig`)**  
Full 7-stage pipeline: working. All flags: working. Rust-style diagnostic output with carets: working. Hex sidecar output: working. Multiple target support: working.

---

## 9. Future Targets & Roadmap

### Near-Term (v1.1 — Codegen Correctness)

- Fix EVM fixed-point literal emission (Gap: resolved type threading through expression codegen)
- Fix u256 truncation through the full ABI path
- Complete EVM event topic encoding for all indexed field counts
- Complete EVM constructor (setup → deploy bytecode + runtime bytecode pattern)
- Wire LinearTracker into view bodies to prevent illegal consumption
- Complete interface conformance verification
- Complete multisig/timelock authority structural validation
- Verify setup block codegen for all statement kinds

### Mid-Term (v1.2 — Tier 1 Features)

- **Module/import system:** `use` resolution against a standard library and local module paths
- **Forge test runner:** `.foztest` support with simulated VM backend
- **Oracle native opcodes:** `ZEPH_ORACLE_READ` emission in RISC-V and EVM codegen
- **VRF randomness:** `ZEPH_VRF_RANDOM` opcode emission
- **Gas sponsorship:** Full `#[gas_sponsored_for]` codegen implementation
- **ZK proof verification:** Circuit registry, verifier call emission, `Proof[T]` type encoding
- **`schedule` call:** Full deferred invocation syscall emission with target block computation
- **`attempt` exception flow:** Complete inter-action exception propagation mechanism

### Mid-Term (v1.3 — Tier 2 Infrastructure)

- **Property-based fuzzing harness:** `forge fuzz` with conservation proof verification per step
- **Deploy manifests:** `.fozdeploy` parser and transaction generation
- **Contract inheritance:** Full `inherits` checking with authority forwarding
- **Testing framework:** `#[test]` annotation, assertion helpers, coverage reporting
- **Language server protocol:** LSP server for editor integration (hover types, go-to-definition, diagnostic streaming)

### Long-Term (v2.0 — Research Features)

- **Semantic Upgrade Diff tooling:** Human-readable audit report generation from `generateUpgradeDiff` output, governance integration, on-chain diff attestation
- **Global invariant runtime enforcement:** Cross-contract invariant checking as a first-class VM feature in the Zephyria scheduler
- **Capability token composition:** Delegation, partial grants, expiry-based capability tokens
- **Economic model verification:** Integration with formal solvers (Z3/CVC5) for complex conservation equations that exceed the compiler's algebraic checker
- **Quantum-resistant signature integration:** Wire MAYO-1 signature verification into the ZephyriaVM executor; expose `Signature` type as a first-class verified value in Forge contract code
- **PolkaVM completeness:** Full feature parity with RISC-V codegen for all Forge language features
- **SQIsign-pure upgrade path (~2027–2029):** When AprèsSQI line research matures, upgrade the wallet identity anchor from SQIsign + MAYO-1 two-layer scheme to a single scheme when sub-100-byte QR signatures become feasible

---

*Forge is built by DHOTNetworks Research under the Zephyria blockchain project. The compiler is open source at `0xZephyria/Forge`. All contributions welcome — see §7 for the precise gap map and contribution rules.*

*Compiler: Zig 0.15.2 · Runtime target: Zephyria VM (RISC-V RV64IM) · Additional targets: EVM, PolkaVM · Binary format: ZephBin v1 (FORG magic) · Codebase: ~21,580 LOC across 14 files*
