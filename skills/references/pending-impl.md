# Pending Implementation Reference
# All Forge Tier 1/2/3 gaps + Novel Ideas with exact file/function hook points

---

## TIER 1 — Zero Implementation (implement these first)

### 1. Fallback / Receive Handlers (Spec §5.13)
**Status**: Not in lexer, parser, or codegen. Completely absent.

**Hook points**:
- `lexer.zig`: Add `.kw_fallback` and `.kw_receive` to `KEYWORDS` table
- `ast.zig`: Add `fallback: ?FallbackDecl` and `receive: ?ReceiveDecl` to `ContractDef`
  ```zig
  pub const FallbackDecl = struct {
      span: Span,
      body: []Stmt,
  };
  pub const ReceiveDecl = struct {
      span:       Span,
      body:       []Stmt,
      accepts_value: bool = true,  // always true for receive
  };
  ```
- `parser.zig`: In `parseContractBody()`, after parsing actions, check for `fallback:` and `receive:` blocks
- `checker.zig`: `checkFallbackDecl()` — no params, no return, no authority guard
- `codegen.zig` (RISC-V): Emit fallback at selector `0x00000000`; receive at zero-length calldata
- `codegen_evm.zig`: CALLDATASIZE == 0 → JUMPI to receive handler; no-match selector → JUMP to fallback

### 2. VRF / Randomness (Spec §14.4)
**Status**: Not in lexer, types, or any codegen.

**Hook points**:
- `lexer.zig`: Add `vrf_random` to `KEYWORDS`
- `ast.zig`: Add to `Expr` union: `vrf_call: VrfCall` where `VrfCall = struct { block_ref: *Expr, addr: *Expr }`
- `types.zig`: `vrf_random(block, address)` returns `Hash` (32-byte unpredictable value)
- `checker.zig`: In `checkExpr(.vrf_call)` — block_ref must be `BlockNumber`, addr must be `Account`
- `codegen.zig`: Emit custom ECALL opcode `SYSCALL_VRF = 0x100` with args in a0, a1
- `codegen_evm.zig`: Cannot do true VRF on EVM — emit `blockhash(block_ref) XOR keccak256(addr)` as approximation; emit warning diagnostic

### 3. Oracle Native Opcodes (Spec §14.1)
**Status**: `Oracle[T]` account type exists; `oracle()` builtin not in any backend.

**Hook points**:
- `lexer.zig`: `oracle` already a keyword? If not, add it
- `ast.zig`: Add `oracle_read: OracleRead` to `Expr` — `OracleRead = struct { account: *Expr }`
- `checker.zig`: Verify oracle account is declared `readonly` in `accounts:` block; return type = oracle's inner type
- `codegen.zig` (RISC-V): Emit `SYSCALL_ORACLE_READ = 0x101` with oracle account address in a0
- `codegen_evm.zig`: Emit Chainlink-compatible call to oracle address: `STATICCALL` to `latestRoundData()` selector `0x feaf968c`

### 4. Gas Sponsorship (Spec §14.6)
**Status**: `#[gas_sponsored_for expr]` in AST `AnnotationKind`. Checker and codegen ignore it.

**Hook points**:
- `checker.zig`: In `checkAction()`, when annotation is `.gas_sponsored_for`:
  - Verify the expr is an `Account` type
  - Verify the account is declared in `accounts:` block
  - Add `gas_payer` field to `AccessListBuilder`
- `codegen.zig` (RISC-V): Emit `SYSCALL_DELEGATE_GAS = 0x102` before action prologue
  - a0 = gas_payer account address
  - This delegates gas deduction to the payer's account
- `abi.zig`: Mark action in ABI JSON as `gas_sponsored: true` with payer type

### 5. Multi-sig / Timelock Authority Enforcement (Spec §§4.5–4.6)
**Status**: Checker only calls `verifyAuthorityExists()`. No depth. `with_timelock` silently ignored.

**Hook points**:
- `ast.zig`: Add to `AuthorityDecl`:
  ```zig
  multisig: ?MultisigConfig,
  dao_config: ?DaoConfig,
  timelock_ms: ?u64,  // resolved from DurationLit at parse time
  ```
- `checker.zig`: New function `checkAuthorityEnforcement()`:
  - For timelock: when action body contains `upgrade_program` or other destructive ops with `only` guard pointing to timelocked authority, verify a queued state field exists in `has:` block and that the timelock check stmt is present
  - For multisig: verify action has approval accumulation logic (approvals set, count check)
  - Emit `E.TIMELOCK_UNMET` if `only timelocked_auth` is used but no timelock enforcement in body
- `codegen.zig`: For timelocked authority check, emit:
  - Load queued_action timestamp from storage
  - Load `current_timestamp` from SYSCALL
  - Emit SUB + BLT → jump to revert if timelock not expired

### 6. Asset Transfer Hooks (Spec §8.5)
**Status**: `before_transfer`/`after_transfer` in `AssetDef` AST. Codegen emits nothing.

**Hook points**:
- `codegen.zig`: In `emitAssetTransfer()`:
  ```zig
  // Before dispatching the actual transfer instruction:
  if (asset_def.before_transfer) |hook| {
      try self.emitFunctionCall(hook.name, &[_]Expr{ from_expr, to_expr, amount_expr });
  }
  // ... emit transfer ...
  if (asset_def.after_transfer) |hook| {
      try self.emitFunctionCall(hook.name, &[_]Expr{ from_expr, to_expr, amount_expr });
  }
  ```
- `checker.zig`: Add `checkAssetHookSignature()` — hook must be `hidden action name(from is Account, to is Account, amount is u256)`

### 7. ZK / Privacy (Spec §12)
**Status**: `#[zk_proof]` in AST. No checker or codegen.

**Hook points**:
- `ast.zig`: Add `Proof_t: *ResolvedType` to `ResolvedType` union
- `types.zig`: Resolve `Proof<T>` generic → `.proof_t = inner_type`
- `checker.zig`:
  - `#[private]` param: verify it is never written to persistent storage (mine.*) — emit `E.ACCESS_VIOLATION`
  - `verify proof against commitment`: new `Stmt` variant `verify_proof: VerifyProof` with `proof`, `commitment`, `public_inputs` fields
  - Return type of ZK action: always `bool` (proof valid or not)
- `codegen.zig` (RISC-V): Emit `SYSCALL_ZK_VERIFY = 0x103` with proof bytes ptr in a0, commitment in a1, public inputs ptr in a2
- `codegen_evm.zig`: Cannot verify ZK natively — emit `STATICCALL` to verifier precompile address (configured per deployment)

### 8. Upgrade / Storage Migration (Spec §13)
**Status**: `UpgradeBlock` parsed; flag bit emitted. Migration bytecode = nothing.

**Hook points**:
- `ast.zig`: Verify `UpgradeBlock` has:
  ```zig
  pub const UpgradeBlock = struct {
      span:              Span,
      storage_version:   u32,
      prev_version_hash: ?[32]u8,
      immutable_fields:  [][]const u8,
      migration_fn:      ?[]Stmt,
      extensible_fields: []ExtensibleField,
  };
  ```
- `checker.zig`: `checkUpgradeBlock()`:
  - `immutable_fields`: verify each name exists in `state_fields`; they must never appear on LHS of assignment in any action
  - `from_version`/`to_version` guards: verify they reference `storage_version` field
  - `migration_fn` body: type-check as hidden action (no external calls allowed)
- `codegen.zig`: Emit migration function as a special entry point with selector `0xDEAD0001`; VM calls it automatically when upgrading
- Novel: Semantic upgrade diff — in `main.zig` compile entry point, when `UpgradeBlock` present with `prev_version_hash`:
  - Load previous ABI from cache
  - Diff state_fields, action signatures, conservation proofs
  - Emit `SemDiff` struct to `.fozdeploy` output

---

## TIER 2 — Infrastructure Gaps

### 9. Module / Import Resolution (Spec §15)
**Status**: `parseUse()` produces `TopLevel.use_import`. No file loading, no stdlib.

**Hook points**:
- `checker.zig` `pass2_resolveImports()`:
  ```zig
  fn pass2_resolveImports(self: *Checker, program: []TopLevel) !void {
      for (program) |tl| {
          switch (tl) {
              .use_import => |ui| try self.loadModule(ui.path, ui.span),
              else => {},
          }
      }
  }

  fn loadModule(self: *Checker, path: []const u8, span: Span) !void {
      // "standard.tokens" → look up in stdlib table
      // "myprotocol.utils" → resolve to ./myprotocol/utils.foz
      if (std.mem.startsWith(u8, path, "standard.")) {
          const builtin = STDLIB.get(path) orelse {
              self.diag.err(E.UNRESOLVED_IMPORT,
                  try std.fmt.allocPrint(self.allocator, "unknown stdlib module '{s}'", .{path}),
                  span);
              return;
          };
          // Merge exported types + interfaces into type_table
          for (builtin.exports) |exp| try self.type_table.put(self.allocator, exp.name, exp.typ);
      } else {
          // Local import: read file from disk
          const file_path = try modulePathToFilePath(self.allocator, path);
          const source = try std.fs.cwd().readFileAlloc(self.allocator, file_path, 1024 * 1024);
          defer self.allocator.free(source);
          // Parse + check the imported file
          var sub_diag = DiagEngine{ .allocator = self.allocator, .filepath = file_path };
          const sub_tokens = try Lexer.init(self.allocator, source).tokenize();
          const sub_ast = try Parser.init(self.allocator, sub_tokens, &sub_diag).parse();
          try self.pass1_collectTypes(sub_ast);
          try self.modules.put(self.allocator, path, Module{ .ast = sub_ast, .path = file_path });
      }
  }
  ```
- Circular import detection: maintain a `resolving: std.StringHashMapUnmanaged(void)` set in Checker; add on enter, remove on exit, error if already present

### 10. Testing Framework (Spec §16)
**Hook points**:
- New file: `src/compiler/test_runner.zig`
- `lexer.zig`: Add `fuzz`, `simulation`, `simulate`, `transactions`, `invariant` keywords
- `ast.zig`: Add top-level variants:
  ```zig
  test_block:  TestBlock,      // from .foztest files
  fuzz_block:  FuzzBlock,
  sim_block:   SimBlock,
  ```
- `test_runner.zig`: 
  - `runTest(block: TestBlock, vm: *Vm) !TestResult`
  - `runFuzz(block: FuzzBlock, vm: *Vm, iterations: u32) !FuzzResult`
  - `runSim(block: SimBlock, vm: *Vm) !SimResult`
- Cheatcodes (Forge-flavored): `warp(ts)`, `roll(n)`, `deal(addr, amount)`, `prank(addr)`, `expect_revert("msg")`, `expect_event(EventName)`

### 11. Deploy Manifests (.fozdeploy)
**Hook points**:
- New file: `src/compiler/deploy_parser.zig`
- New file: `src/compiler/deploy_runner.zig`
- `ast.zig`: Add `DeployManifest` and `DeploySuite` AST nodes
- Grammar: `deploy ContractName:` followed by `networks`, `optimize`, `params`, `initial_authorities`, `create_accounts`, `after_deploy`, `verify` sections
- `deploy_runner.zig`: Resolves param expressions, builds deploy transaction, broadcasts via RPC

---

## TIER 3 — Codegen Completeness

| Feature | RISC-V hook | EVM hook | PolkaVM hook |
|---|---|---|---|
| `schedule call after N` | `codegen.zig: emitScheduleCall()` → SYSCALL_SCHEDULE=0x104 | `codegen_evm.zig`: no native support → emit event for off-chain scheduler | same as EVM |
| Asset hook dispatch | `codegen.zig: emitAssetOp()` → inject before_/after_ calls | same pattern | same pattern |
| Upgrade migration | `codegen.zig`: special entry 0xDEAD0001 | same | same |
| ZK proof verify | SYSCALL_ZK_VERIFY=0x103 | STATICCALL to verifier precompile | CALL to ink! ZK pallet |
| Oracle native call | SYSCALL_ORACLE_READ=0x101 | STATICCALL 0xfeaf968c | CALL to substrate oracle pallet |
| VRF random | SYSCALL_VRF=0x100 | blockhash XOR approximation | substrate randomness pallet |
| Fallback handler | emit at selector 0x00000000 | CALLDATASIZE==0 branch | same |
| Governance authority | SYSCALL_GOV_CHECK=0x105 | not supported (emit warning) | substrate governance call |

---

## NOVEL IDEAS — Implementation Hooks

### Novel 1: Economic Conservation Proofs
- `ast.zig`: Add `conserves: []ConservationExpr` to `ContractDef`
- `ConservationExpr` = `{ aggregator: enum{sum,count,max}, field_path: []const u8, op: ConservationOp, rhs: Expr, span: Span }`
- `checker.zig` pass 4: `checkAllConservation()` → delta analysis (see `compiler-passes.md`)
- Error code: `E.CONSERVATION_FAIL = "E0007"`

### Novel 2: Gas Complexity Classes
- `ast.zig`: Add `complexity_class: ?ComplexityClass` to `ActionDecl`
- `ComplexityClass = union(enum) { constant, linear: BoundExpr, quadratic: BoundExpr }`
- `BoundExpr = struct { max: u64, param_name: ?[]const u8 }`
- `checker.zig`: `checkComplexityClass()` (see `compiler-passes.md`)
- `abi.zig`: Include `"complexity": "O(1)"` in ABI JSON for the action
- Error code: `E.COMPLEXITY_EXCEEDED = "E0008"`

### Novel 3: Adversary Blocks
- `ast.zig`: Add `adversary: []AdversaryBlock` to `ContractDef`
  ```zig
  pub const AdversaryBlock = struct {
      span:    Span,
      attacks: []AttackSpec,
  };
  pub const AttackSpec = struct {
      name:    []const u8,
      span:    Span,
      calls:   []AttackCall,
      expects: AdversaryOutcome,
  };
  pub const AdversaryOutcome = enum { conservation_violated, action_blocked, invariant_broken };
  ```
- `checker.zig` pass 5: `checkAdversaryBlocks()`:
  - For `conservation_violated`: run conservation delta for the attack call sequence → if delta is valid, attack succeeds → emit `E.ATTACK_SUCCEEDED`
  - For `action_blocked`: verify the called action has authority guard or reentrancy protection → if neither, emit `E.ATTACK_SUCCEEDED`
  - If attack is correctly blocked: emit note "attack '{s}' correctly blocked ✓"
- Error code: `E.ATTACK_SUCCEEDED = "E0009"`

### Novel 4: Semantic Upgrade Diffs
- `main.zig` compile entry: When `UpgradeBlock` has `prev_version_hash`:
  - Load `prev_abi.json` from cache keyed by hash
  - Compute diff: new_state_fields \ old_state_fields = added; vice versa = removed
  - For each action: compare param list + return type → behavior_changed set
  - Run conservation checker against old + new state shapes
  - Write `SEMANTIC_DIFF` block to `.fozdeploy` output
  ```zig
  pub const SemDiff = struct {
      state_added:          [][]const u8,
      state_removed:        [][]const u8,
      behavior_changed:     []ActionDiff,
      new_attack_surface:   [][]const u8,    // new public actions
      invariants_preserved: [][]const u8,
      invariants_broken:    [][]const u8,    // if any → block upgrade on-chain
  };
  ```

### Novel 5: Cross-Contract Global Invariants
- New top-level `.fozi` construct: `global invariant Name:`
- `ast.zig`: Add `GlobalInvariantDef`:
  ```zig
  pub const GlobalInvariantDef = struct {
      name:         []const u8,
      span:         Span,
      participants: [][]const u8,       // contract names
      always_expr:  Expr,               // boolean expression across contracts
      on_violation: []Stmt,
  };
  ```
- `checker.zig`: `checkGlobalInvariant()`:
  - Verify participant contracts exist in type_table
  - Verify field references (e.g. `CollateralVault.mine.total_collateral_usd`) resolve via declared `view` functions
  - Emit `GlobalInvariantDescriptor` into `.fozabi` output
- `zephbin_loader.zig`: Include `GlobalInvariantDescriptor` in ZephBin access section
- VM: After each transaction, load all applicable descriptors; evaluate `always_expr` against touched accounts; revert if false

### Novel 6: Capability Token Types (Linear Authority)
- `lexer.zig`: Add `capability` keyword (may already exist — verify)
- `ast.zig`: Add top-level `CapabilityDef`:
  ```zig
  pub const CapabilityDef = struct {
      name:   []const u8,
      span:   Span,
      fields: []Param,       // for_account, max_amount, expires_at, delegatable
  };
  ```
- `types.zig`: `ResolvedType.capability: *CapabilityDef` — ALWAYS linear
  - `isLinear(rt) = rt == .capability`
- `checker.zig`:
  - `LinearTracker.introduce(cap_name)` when a capability param or let-binding is created
  - `LinearTracker.consume(cap_name, span)` when passed to an action accepting `TransferCap<T>`
  - Emit `E.LINEAR_DROP` if consumed twice
  - Emit `W0001` (warning) if never consumed
- `codegen.zig` (RISC-V): Capabilities are stack-allocated structs + `consumed: bool` field at offset 0
  - On consume: set `consumed = true` at offset 0, then check it wasn't already true (→ revert with linear violation)
