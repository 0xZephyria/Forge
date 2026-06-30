---
name: zig-blockchain
description: >
  Production-grade Zig 0.15.2 code for the Forge compiler codebase and Zephyria blockchain
  runtime — specifically writing, extending, debugging, or auditing the compiler pipeline
  (lexer, parser, AST, type checker, codegen, ABI) and the ZephyriaVM execution engine.
  Use this skill whenever the user mentions: Forge compiler, forgec, lexer.zig, parser.zig,
  ast.zig, checker.zig, codegen.zig, codegen_evm.zig, codegen_polkavm.zig, types.zig,
  abi.zig, diagnostics.zig, zephbin_loader.zig, executor.zig, sandbox.zig, gas/meter.zig,
  gas/table.zig, Zephyria blockchain, ForgeVM, RISC-V codegen, EVM codegen, PolkaVM codegen,
  smart contract compiler in Zig, or any Forge language feature implementation (actions,
  authorities, accounts, events, guards, conserves, adversary blocks, capability types).
  Trigger even for partial tasks: "add a keyword", "fix codegen for X", "implement checker
  for Y", "write the AST node for Z". Never skip this skill when Forge + compiler appear together.
---

# Forge Compiler Skill — Zig 0.15.2 Production Reference

> **Agent directive**: Read ALL of §1–§10 before touching any file.
> Then load only the reference file(s) matched to your specific task.
> Never hallucinate stdlib APIs. Never leave stubs or TODOs.

---

## §1 — Compiler Pipeline & Source Map

```
forgec pipeline (in order):
  Source (.foz / .fozi / .foztest / .fozdeploy)
    → lexer.zig           tokenize() → []Token  [TokenKind enum]
    → parser.zig          recursive-descent → []TopLevel (AST nodes)
    → ast.zig             ALL AST node type definitions
    → types.zig           ResolvedType + resolve() pass
    → checker.zig         semantic analysis, access-list proof, authority enforcement
    → diagnostics.zig     Diagnostic + DiagEngine (errors/warnings/notes)
    → codegen.zig         backend dispatch → selects RISC-V / EVM / PolkaVM
    → codegen_evm.zig     EVM bytecode emitter
    → codegen_polkavm.zig PolkaVM WASM emitter
    → abi.zig             ABI JSON encoder + 4-byte selector computation
    → zephbin_loader.zig  ZephBin v1 binary format writer/reader

ZephyriaVM (shared with Forge toolchain):
    → executor.zig        main execution loop (RISC-V RV64IM interpreter)
    → decoder.zig         instruction decode + dispatch table
    → sandbox.zig         memory isolation + syscall gate
    → gas/meter.zig       GasTracker — charge / refund / remaining
    → gas/table.zig       opcode → base gas cost table
    → contract_loader.zig load .fozbin into VM memory map
```

**Project root**: `src/compiler/` for forgec; `src/vm/` for ZephyriaVM.
**Codebase size**: ~18,569 LOC across 13 compiler files + VM files.
**Language**: Zig 0.15.2 exclusively. No Rust. No C++ (C interop only where needed).

---

## §2 — Zig 0.15.2 Absolute Laws

These rules govern every line in this codebase. Violations cause compile failure.

```zig
// ── Error unions: always explicit return type ──────────────────────
fn tokenize(self: *Lexer) ![]Token { ... }
fn checkAction(self: *Checker, a: ActionDecl) ParseError!void { ... }

// ── Allocator threading: NEVER global ─────────────────────────────
pub const Lexer = struct {
    allocator: std.mem.Allocator,
    source:    []const u8,
    pos:       usize = 0,
    line:      u32   = 1,
    pub fn init(allocator: std.mem.Allocator, source: []const u8) Lexer {
        return .{ .allocator = allocator, .source = source };
    }
};

// ── ArrayListUnmanaged in embedded structs ────────────────────────
// CORRECT:
tokens: std.ArrayListUnmanaged(Token) = .{},
try self.tokens.append(allocator, tok);
self.tokens.deinit(allocator);

// WRONG: std.ArrayList in struct fields (requires stored allocator copy)

// ── comptime keyword lookup table ─────────────────────────────────
const KEYWORDS = std.StaticStringMap(TokenKind).initComptime(.{
    .{ "action",   .kw_action   },
    .{ "view",     .kw_view     },
    .{ "when",     .kw_when     },
    .{ "give",     .kw_give     },
    .{ "back",     .kw_back     },
    // ... full list in references/forge-syntax.md
});
pub fn identOrKeyword(word: []const u8) TokenKind {
    return KEYWORDS.get(word) orelse .ident;
}

// ── Tagged unions: exhaustive switch, NO unreachable else ─────────
const Stmt = union(enum) { let_bind: LetBind, assign: Assign, tell: TellStmt };
switch (stmt) {
    .let_bind => |b| try self.checkLetBind(b),
    .assign   => |a| try self.checkAssign(a),
    .tell     => |t| try self.checkTell(t),
    // NO else here — add new variants explicitly
}

// ── Spans on every AST node ───────────────────────────────────────
pub const Span   = struct { start: u32, end: u32 };
pub const Token  = struct { kind: TokenKind, span: Span };

// ── defer for all cleanup ─────────────────────────────────────────
var map = std.StringHashMap(ResolvedType).init(allocator);
defer map.deinit();

// ── Arena for AST nodes (long-lived); GPA for compiler runtime ────
var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
defer arena.deinit();
const ast_alloc = arena.allocator();
// Individual passes use arena; tests use std.testing.allocator
```

---

## §3 — Canonical AST Node Types (ast.zig)

```zig
pub const TopLevel = union(enum) {
    contract_def:   ContractDef,
    asset_def:      AssetDef,
    interface_def:  InterfaceDef,
    use_import:     UseImport,
    define_const:   DefineConst,
    global_inv:     GlobalInvariantDef,  // novel: cross-contract invariant
    capability_def: CapabilityDef,       // novel: linear capability type
};

pub const ContractDef = struct {
    name:           []const u8,
    span:           Span,
    accounts:       []AccountDecl,
    authorities:    []AuthorityDecl,
    implements:     [][]const u8,
    config:         []ConfigField,
    constants:      []ConstantDecl,     // always: block
    state_fields:   []StateField,       // has: block
    namespaces:     [][]const u8,       // namespace declarations
    setup:          ?SetupBlock,
    guards:         []GuardDecl,
    actions:        []ActionDecl,
    views:          []ViewDecl,
    pures:          []PureDecl,
    hidden_fns:     []HiddenDecl,
    events:         []EventDecl,
    errors:         []ErrorDecl,
    upgrade:        ?UpgradeBlock,
    conserves:      []ConservationExpr, // novel: conservation proofs
    adversary:      []AdversaryBlock,   // novel: adversary simulation
};

pub const ActionDecl = struct {
    name:             []const u8,
    span:             Span,
    params:           []Param,
    return_type:      ?TypeExpr,
    annotations:      []Annotation,       // #[parallel], #[reads …], #[writes …]
    access_modifier:  enum { none, shared, hidden, accepts_value },
    authority_guard:  ?AuthorityGuard,    // only X
    guards_applied:   [][]const u8,
    body:             []Stmt,
    complexity_class: ?ComplexityClass,   // novel: O(1)/O(n)
    accounts_local:   []AccountDecl,      // accounts: inside action body
};

pub const Stmt = union(enum) {
    let_bind:         LetBind,            // let x is T = expr
    assign:           Assign,             // lhs = rhs
    aug_assign:       AugAssign,          // lhs += rhs  (op: .add/.sub/.mul)
    when:             WhenStmt,
    match:            MatchStmt,
    each:             EachStmt,           // each item in collection:
    repeat:           RepeatStmt,         // repeat N times:
    while_loop:       WhileStmt,
    tell:             TellStmt,           // tell EventName(args...)
    need:             NeedStmt,           // need cond else "msg" | ErrorType(...)
    ensure:           EnsureStmt,         // post-condition (checked at exit)
    throw_err:        ThrowStmt,          // throw ErrorName(args)
    panic_stmt:       PanicStmt,
    stop:             void,               // break/early-return (no value)
    skip:             void,               // continue loop iteration
    give_back:        GiveBack,           // return value
    attempt:          AttemptStmt,        // try/catch for external calls
    call_stmt:        CallExpr,
    send_asset:       SendAsset,          // send amount to recipient
    pay_native:       PayNative,          // pay wallet amount [from vault]
    schedule_call:    ScheduleCall,       // schedule call after N blocks
    only_stmt:        OnlyStmt,           // only authority_name
    guard_stmt:       GuardApply,         // guard guard_name(args)
    freeze_acct:      FreezeStmt,
    unfreeze_acct:    UnfreezeStmt,
    close_acct:       CloseStmt,
    expand_acct:      ExpandStmt,
    transfer_own:     TransferOwnership,
    upgrade_prog:     UpgradeProg,
};

pub const Expr = union(enum) {
    integer_lit:    u256,
    fixed_lit:      FixedLit,            // 1234.567 → { mantissa, decimals }
    bool_lit:       bool,
    string_lit:     []const u8,
    duration_lit:   DurationLit,         // 7 days → { value_ms, unit }
    nothing:        void,                // nothing (empty optional)
    something:      *Expr,               // something(x)
    ident:          []const u8,
    field_access:   FieldAccess,         // mine.balances or obj.field
    index_access:   IndexAccess,         // map[key]
    binary_op:      BinaryOp,            // a plus b, a equals b, a and b
    unary_op:       UnaryOp,             // not x, -x
    call:           CallExpr,            // fn(args)
    cast:           CastExpr,            // expr as Type
    result_ok:      *Expr,               // ok(x)
    result_fail:    *Expr,               // fail(x)
    when_expr:      WhenExpr,            // when cond then a otherwise b
    sha3_call:      *Expr,               // sha3(expr)
    blake3_call:    *Expr,               // blake3(expr)
    now_call:       void,                // now()
    current_block:  void,                // current_block()
    caller_ref:     void,                // caller
    value_ref:      void,                // value (native token received)
    this_address:   void,                // this.address
    deployer_ref:   void,                // deployer
    zero_address:   void,                // zero_address
    unwrap:         *Expr,               // expr.unwrap
    exists_check:   *Expr,               // expr exists
    type_check:     TypeCheck,           // expr is Type / expr is something
    has_check:      HasCheck,            // collection has element
    authority_ref:  AuthorityRef,        // authorities.mint_authority.holder
};

pub const AccountDecl = struct {
    name:        []const u8,
    span:        Span,
    kind:        AccountKind,           // Data / Vault / Asset / Oracle / Wallet / Program
    owned_by:    ?OwnershipExpr,        // owned_by this | owned_by params.user
    seeded_by:   []SeedElement,         // seeded_by ["key", params.user]
    child_of:    ?[]const u8,           // child_of parent_account
    readonly:    bool,
    global:      bool,
    at_address:  ?Expr,                 // at known.ZephUsdOracle
    can_fields:  []CanField,            // can: read balance, write amount
    create_if_missing: bool,
    capacity:    ?u64,                  // size N bytes
};

pub const AuthorityDecl = struct {
    name:       []const u8,
    span:       Span,
    kind:       AuthorityKind,
    holder:     HolderKind,             // Wallet / Program / Multisig / DAO
    initial:    InitialHolder,          // deployer / nobody / params.X / known.X
    timelock:   ?DurationLit,           // with_timelock 7 days
    covers:     [][]const u8,           // covers [fee_auth, pause_auth]
    inheritable: bool,
    inherits_from: ?[]const u8,         // inherits from Parent.authority_name
};
```

---

## §4 — Type System (types.zig)

```zig
pub const ResolvedType = union(enum) {
    // Unsigned integers
    u8:void, u16:void, u32:void, u64:void, u128:void, u256:void, uint:void,
    // Signed integers
    i8:void, i16:void, i32:void, i64:void, i128:void, i256:void, int:void,
    // Bool
    bool:void,
    // Fixed-point: { decimals: u8 }
    fixed: u8,
    price9:void, price18:void, percent:void,
    // Address subtypes (all 32 bytes on-chain)
    account:void, wallet:void, program:void, system:void,
    // Hash / crypto
    hash:void, hash20:void, commitment:void,
    bytes:void, bytes32:void, bytes64:void,
    signature:void,   // 96 bytes BLS12-381
    public_key:void,  // 48 bytes BLS12-381
    // Time
    timestamp:void, duration:void, block_number:void, epoch:void, slot:void,
    // Strings
    string:void, short_str:void, label:void,
    // Compound
    optional:  *ResolvedType,
    result:    ResultType,            // { ok: *RT, err: *RT }
    map:       MapType,               // { key: *RT, value: *RT }
    enum_map:  MapType,
    list:      *ResolvedType,
    set:       *ResolvedType,
    array:     ArrayType,             // { elem: *RT, size: u64 }
    tuple:     []ResolvedType,
    // User-defined
    struct_t:  *StructDef,
    record_t:  *RecordDef,
    enum_t:    *EnumDef,
    // Account types
    asset_acct: AssetTypeRef,         // Asset[T] — T is resolved asset name
    vault_acct: AssetTypeRef,         // Vault[T]
    data_acct:  void,
    oracle_acct: *ResolvedType,       // Oracle[price18] → stores inner type
    // Novel
    capability: *CapabilityDef,       // LINEAR — consumed once only
    proof_t:    *ResolvedType,        // Proof<T> for ZK
    // Meta
    alias:      *ResolvedType,
    generic:    GenericType,
    unresolved: []const u8,           // error sentinel: type name not found
};

// Subtype relationships (checked in checker.zig):
// wallet  <: account
// program <: account
// system  <: account
// price9 and price18 are compatible fixed types
// uint is alias for u256 — identical in IR
// int is alias for i256

pub fn isNumeric(t: ResolvedType) bool {
    return switch (t) {
        .u8,.u16,.u32,.u64,.u128,.u256,.uint,
        .i8,.i16,.i32,.i64,.i128,.i256,.int => true,
        .fixed,.price9,.price18,.percent => true,
        else => false,
    };
}

pub fn isAddress(t: ResolvedType) bool {
    return switch (t) {
        .account,.wallet,.program,.system => true,
        else => false,
    };
}

pub fn isLinear(t: ResolvedType) bool {
    return switch (t) { .capability => true, else => false };
}

pub fn assignCompatible(dst: ResolvedType, src: ResolvedType) bool {
    if (std.meta.eql(dst, src)) return true;
    // wallet/program/system can be assigned to account
    if (dst == .account and isAddress(src)) return true;
    // uint == u256
    if ((dst == .uint and src == .u256) or (dst == .u256 and src == .uint)) return true;
    return false;
}
```

---

## §5 — Diagnostic System (diagnostics.zig)

```zig
pub const Severity  = enum { err, warning, note, hint };

pub const Diagnostic = struct {
    severity: Severity,
    code:     []const u8,    // "E0001"
    message:  []const u8,
    span:     Span,
    filepath: []const u8,
    labels:   []Label,       // secondary source spans
    notes:    [][]const u8,

    pub const Label = struct { span: Span, message: []const u8 };
};

pub const DiagEngine = struct {
    allocator:   std.mem.Allocator,
    diagnostics: std.ArrayListUnmanaged(Diagnostic) = .{},
    filepath:    []const u8,

    pub fn err(self: *DiagEngine, code: []const u8, msg: []const u8, span: Span) void {
        self.push(.err, code, msg, span);
    }
    pub fn warn(self: *DiagEngine, code: []const u8, msg: []const u8, span: Span) void {
        self.push(.warning, code, msg, span);
    }
    pub fn note(self: *DiagEngine, msg: []const u8, span: Span) void {
        self.push(.note, "N0000", msg, span);
    }
    fn push(self: *DiagEngine, sev: Severity, code: []const u8, msg: []const u8, span: Span) void {
        self.diagnostics.append(self.allocator, .{
            .severity = sev, .code = code, .message = msg,
            .span = span, .filepath = self.filepath,
            .labels = &.{}, .notes = &.{},
        }) catch {};
    }
    pub fn hasErrors(self: *const DiagEngine) bool {
        for (self.diagnostics.items) |d| if (d.severity == .err) return true;
        return false;
    }
    pub fn render(self: *const DiagEngine, writer: anytype) !void {
        for (self.diagnostics.items) |d| {
            const sev = switch (d.severity) {
                .err     => "error",
                .warning => "warning",
                .note    => "note",
                .hint    => "hint",
            };
            try writer.print("{s}: [{s}] {s}\n  --> {s}:{}\n",
                .{ sev, d.code, d.message, d.filepath, d.span.start });
        }
    }
};

// Standard error codes used across the codebase:
pub const E = struct {
    pub const UNDEFINED_SYMBOL    = "E0001";
    pub const TYPE_MISMATCH       = "E0002";
    pub const AUTHORITY_VIOLATION = "E0003";
    pub const ACCESS_VIOLATION    = "E0004";
    pub const REENTRANCY          = "E0005";
    pub const OVERFLOW_RISK       = "E0006";
    pub const CONSERVATION_FAIL   = "E0007"; // novel
    pub const COMPLEXITY_EXCEEDED = "E0008"; // novel
    pub const ATTACK_SUCCEEDED    = "E0009"; // novel
    pub const LINEAR_DROP         = "E0010"; // capability linearity
    pub const UNRESOLVED_IMPORT   = "E0011";
    pub const INVARIANT_BREAK     = "E0012";
    pub const MISSING_RETURN      = "E0013";
    pub const UNDEFINED_ACCOUNT   = "E0014";
    pub const WRITE_TO_READONLY   = "E0015";
    pub const PARALLEL_CONFLICT   = "E0016";
    pub const TIMELOCK_UNMET      = "E0017";
    pub const MULTISIG_QUORUM     = "E0018";
    pub const DUPLICATE_AUTHORITY = "E0019";
    pub const UNCONSTRAINED_LOOP  = "E0020";
};
```

---

## §6 — Forge Language Syntax (Critical Rules)

### File structure order (enforced by parser):
```
version 1                          // MUST be first line
use ...                            // imports
define NAME as VALUE               // top-level constants
asset ... { }                      // asset definitions
interface ... { }                  // interfaces
contract Name:                     // contracts (last)
```

### Contract section order (parser enforces this sequence):
```
accounts:      // external account declarations
authorities:   // permission slots
implements     // interface names (no colon)
config:        // immutable deploy-time params
always:        // compile-time constants
has:           // mutable on-chain state
setup():       // constructor
guard name:    // reusable precondition blocks
action / view / pure / hidden action
event / error  // declarations
upgrade:       // upgrade block
conserves:     // novel: conservation proofs
adversary tries: // novel: attack specs
```

### Variable access patterns:
```zeph
mine.field               // this contract's state (has: block)
mine.field[key]          // map lookup → returns maybe Type
mine.field[key] or 0     // with default
params.user              // action parameter named 'user'
caller                   // built-in: transaction signer
value                    // built-in: native token sent (requires accepts_value)
this.address             // built-in: this contract's address
deployer                 // built-in: who deployed (setup only)
now()                    // built-in: current timestamp in ms
current_block()          // built-in: block number
```

### Operator keywords → IR opcodes:
```
plus         → ADD     (overflow checked)
minus        → SUB     (underflow checked)
times        → MUL     (overflow checked)
divided by   → DIV     (div-by-zero checked)
mod          → MOD
equals       → EQ
is not       → NEQ
>=           → GTE
<=           → LTE
>            → GT
<            → LT
and          → AND (short-circuit)
or           → OR  (short-circuit)
not          → NOT
```

### Duration literals → compile-time u64 milliseconds:
```zig
// In types.zig / lexer.zig resolution:
pub fn resolveDuration(lit: DurationLit) u64 {
    const ms_per: u64 = switch (lit.unit) {
        .millisecond => 1,
        .second      => 1_000,
        .minute      => 60_000,
        .hour        => 3_600_000,
        .day         => 86_400_000,
        .week        => 604_800_000,
        .month       => 2_592_000_000,
        .year        => 31_536_000_000,
    };
    return lit.value * ms_per;
}
```

---

## §7 — Checker Passes (checker.zig)

The checker runs these passes in order. Each is a separate function:

```zig
pub const Checker = struct {
    arena:         std.heap.ArenaAllocator,
    diag:          *DiagEngine,
    scope_stack:   std.ArrayListUnmanaged(Scope) = .{},
    type_table:    std.StringHashMap(ResolvedType),
    // Current contract context:
    cur_contract:  ?*const ContractDef = null,
    access_list:   AccessListBuilder,
    linear_tracker: LinearTracker,

    pub fn run(self: *Checker, program: []TopLevel) !void {
        try self.pass1_collectTypes(program);     // build type_table
        try self.pass2_resolveImports(program);   // load use_import modules
        for (program) |tl| try self.pass3_checkTopLevel(tl);
        try self.pass4_conservation(program);     // novel: symbolic delta
        try self.pass5_adversary(program);        // novel: attack simulation
    }
};

// Checker functions — these must ALL be implemented:
// checkContractDef()     sets cur_contract, checks each subsection in order
// checkAccountDecl()     validates kind + owned_by + seeded_by; adds to scope
// checkAuthorityDecl()   validates kind; checks covers/inherits references
// checkAction()          authority guard → guards → body stmts → access list verify
// checkView()            no state writes allowed; give_back type matches declared
// checkPure()            no state reads or writes; no side effects
// checkStmt()            dispatches to per-statement checkers
// checkLetBind()         infer or verify type; add to scope; linear tracking
// checkAssign()          lvalue must be writable in access list; type compatible
// checkAugAssign()       same as assign + numeric type required
// checkNeedStmt()        operand must be bool; else clause is string or ErrorDecl ref
// checkTellStmt()        event name must exist in contract; arg count+types match
// checkOnlyStmt()        authority name must be declared; holder type must match caller
// checkGuardApply()      guard name must exist; param types match
// checkEachStmt()        collection must be List/Set/Map; body checked in new scope
// checkRepeatStmt()      count must be u-integer or literal; body ok
// checkAttemptStmt()     on_error branches reference declared error types
// checkSendAsset()       asset type matches vault; amount is numeric
// checkPayNative()       amount is u256/uint; recipient is wallet/account
// checkScheduleCall()    target action must exist; delay is Duration
// checkConservation()    symbolic delta analysis on sum/count/max aggregators
// checkComplexity()      loop nesting vs declared O(1)/O(n); bounded iteration
// checkAdversaryBlocks() symbolic attack execution; expects outcome vs actual
// checkLinearUsage()     LinearTracker: capability consumed exactly once
// checkAccessList()      #[reads]/[writes] annotations vs actual accesses
// checkParallelAnnot()   body touches only per-caller scoped state; no global writes
```

---

## §8 — Codegen Patterns

### RISC-V codegen (codegen.zig / decoder.zig)

```zig
pub const CodegenCtx = struct {
    buf:       std.ArrayListUnmanaged(u8) = .{},
    labels:    std.StringHashMapUnmanaged(u32) = .{},
    fixups:    std.ArrayListUnmanaged(Fixup) = .{},
    gas_table: *const GasTable,
    allocator: std.mem.Allocator,

    pub fn emit(self: *CodegenCtx, instr: u32) !void {
        const bytes: [4]u8 = @bitCast(instr);
        try self.buf.appendSlice(self.allocator, &bytes);
    }

    pub fn emitGasCharge(self: *CodegenCtx, cost: u64) !void {
        // a5 = gas counter (dedicated register, never clobbered)
        // Pattern: addi a5, a5, -cost ; blt a5, zero, .out_of_gas
        if (cost <= 2047) {
            try self.emit(rv_addi(.a5, .a5, -@as(i12, @intCast(cost))));
        } else {
            try self.emit(rv_li(.t0, cost));
            try self.emit(rv_sub(.a5, .a5, .t0));
        }
        try self.emitBranchOutOfGas();
    }

    pub fn patchFixups(self: *CodegenCtx) !void {
        for (self.fixups.items) |f| {
            const target = self.labels.get(f.label) orelse return error.UndefinedLabel;
            const offset: i32 = @as(i32, @intCast(target)) - @as(i32, @intCast(f.site));
            const old: u32 = @bitCast(self.buf.items[f.site..f.site+4][0..4].*);
            self.buf.items[f.site..f.site+4][0..4].* = @bitCast(patchBranchOffset(old, offset));
        }
    }
};

// Register ABI for ForgeVM:
// a0-a7  = args + return values (a0 = first arg / return)
// t0-t6  = temporaries (caller-saved)
// s0-s11 = callee-saved
// a5     = gas counter (DEDICATED — never use for anything else)
// a6     = calldata base pointer
// sp     = stack pointer
// ra     = return address

// Forge action → RISC-V layout:
// 1. Prologue: addi sp, sp, -frame; sd ra, offset(sp); sd s0, offset(sp)
// 2. Gas charge for action entry cost
// 3. Authority check → jump to .revert if fail
// 4. Guard blocks (inline need conditions)
// 5. Statement emission
// 6. Return: marshals give_back value into a0; ld ra; ld s0; addi sp; ret
// 7. .out_of_gas label: emit REVERT with OOG reason
// 8. .revert label: emit REVERT with error reason
```

### EVM codegen (codegen_evm.zig)

```zig
// Critical bugs that MUST be fixed (from audit):
// 1. LT condition was INVERTED in calldatasize check → fixed: use GT not LT
// 2. Stack ordering in binary ops: Forge a op b → EVM pushes b THEN a
//    (EVM is reverse-polish: TOS = left operand after push sequence)
// 3. no_match_dest label was never emitted → causes infinite loop on unknown selector
// 4. Stack cleanliness on dispatch exhaustion: must pop selector before REVERT
// 5. Event topics: indexed fields push topic hash, non-indexed go to data

// ABI dispatch pattern (correct):
pub fn emitDispatch(self: *EvmCtx, actions: []ActionDecl) !void {
    // CALLDATASIZE check: need >= 4 bytes
    try self.emit(.CALLDATASIZE);
    try self.emitPush(u256, 4);
    try self.emit(.LT);               // LT: stack top < 4?
    try self.emitJumpiToRevert();     // if true (too small), revert
    // Load selector
    try self.emitPush(u256, 0);
    try self.emit(.CALLDATALOAD);
    try self.emitPush(u256, 0xFFFFFFFF_00000000_00000000_00000000 <<
                             (256 - 32));
    try self.emit(.AND);
    // Dispatch table
    for (actions) |action| {
        try self.emit(.DUP1);         // duplicate selector
        try self.emitPush(u256, computeSelector(action));
        try self.emit(.EQ);
        try self.emitJumpiToLabel(action.name);
    }
    // no_match: pop selector, revert
    try self.emitLabel("no_match_dest");  // MUST emit this label
    try self.emit(.POP);              // clear selector off stack
    try self.emitRevert(0, 0);
    // Action implementations follow
}

// Binary op stack order:
pub fn emitBinaryOp(self: *EvmCtx, op: BinaryOp) !void {
    try self.emitExpr(op.left);   // push left
    try self.emitExpr(op.right);  // push right  ← EVM TOS = right
    // EVM: ADD pops right (TOS) then left (TOS-1) → result = left + right ✓
    // But for SUB/DIV: EVM does TOS - (TOS-1), so we want left on TOS
    switch (op.kind) {
        .add  => try self.emit(.ADD),
        .sub  => {
            // swap so left is on TOS for subtraction
            try self.emit(.SWAP1);
            try self.emit(.SUB);
        },
        .mul  => try self.emit(.MUL),
        .div  => {
            try self.emit(.SWAP1);
            try self.emit(.DIV);
        },
        .eq   => try self.emit(.EQ),
        .neq  => { try self.emit(.EQ); try self.emit(.ISZERO); },
        .lt   => { try self.emit(.SWAP1); try self.emit(.GT); }, // a < b = b > a
        .gt   => { try self.emit(.SWAP1); try self.emit(.LT); }, // a > b = b < a
        .lte  => { try self.emit(.GT); try self.emit(.ISZERO); },
        .gte  => { try self.emit(.LT); try self.emit(.ISZERO); },
        .and_op => try self.emit(.AND),
        .or_op  => try self.emit(.OR),
    }
}
```

---

## §9 — ZephBin v1 Format

```zig
// zephbin_loader.zig
pub const MAGIC = [4]u8{ 'F', 'O', 'Z', 'B' };

pub const Header = extern struct {
    magic:         [4]u8  = MAGIC,
    version:       u8     = 1,
    flags:         u8,           // 0x01=upgradeable, 0x02=parallel, 0x04=zk
    _pad:          [2]u8  = .{0, 0},
    checksum:      [32]u8,       // BLAKE3 of all bytes after header
    code_offset:   u32,
    code_size:     u32,
    abi_offset:    u32,
    abi_size:      u32,
    data_offset:   u32,          // initial storage image
    data_size:     u32,
    access_offset: u32,          // signed access list descriptor
    access_size:   u32,
};

pub fn write(ctx: *CodegenCtx, abi_json: []const u8) ![]u8 {
    const code = ctx.buf.items;
    var out = std.ArrayList(u8).init(ctx.allocator);
    defer out.deinit();
    const header_size: u32 = @sizeOf(Header);
    var hdr = Header{
        .flags        = ctx.flags,
        .checksum     = undefined,
        .code_offset  = header_size,
        .code_size    = @intCast(code.len),
        .abi_offset   = header_size + @as(u32, @intCast(code.len)),
        .abi_size     = @intCast(abi_json.len),
        .data_offset  = 0,
        .data_size    = 0,
        .access_offset = 0,
        .access_size   = 0,
    };
    // Compute checksum over code + abi
    var h: [32]u8 = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(code);
    hasher.update(abi_json);
    hasher.final(&h);
    hdr.checksum = h;
    try out.appendSlice(std.mem.asBytes(&hdr));
    try out.appendSlice(code);
    try out.appendSlice(abi_json);
    return out.toOwnedSlice();
}
```

---

## §10 — Production Checklist

- [ ] `ArrayListUnmanaged` not `ArrayList` in struct fields
- [ ] Every error path emits a `Diagnostic` — never silent
- [ ] Every AST node has a `Span` field
- [ ] Allocator passed everywhere — no implicit arena escape
- [ ] `defer deinit` for every HashMap/ArrayList created locally
- [ ] Keyword lookup is `StaticStringMap.initComptime` — never runtime strcmp
- [ ] Exhaustive switch on all `union(enum)` — add new variants, don't use `else`
- [ ] Forward refs use `Fixup` list + `patchFixups()` — never inline
- [ ] Gas charged BEFORE every opcode emit in codegen
- [ ] `LinearTracker` updated at every capability consume/produce
- [ ] `AccessListBuilder` updated at every mine.X read/write in checker
- [ ] New keywords: added to lexer `KEYWORDS` table AND parser expect sets
- [ ] EVM binary ops: check stack order (swap before SUB/DIV)
- [ ] EVM dispatch: `no_match_dest` label always emitted; selector popped before revert

---

## §11 — Reference Files (load on demand)

| File | Load when |
|------|-----------|
| `references/forge-syntax.md` | Lexer/parser work; all keywords, operators, grammar rules |
| `references/compiler-passes.md` | checker.zig passes; type resolution; access list; linear tracking |
| `references/codegen-backends.md` | RISC-V, EVM, PolkaVM emitter patterns; ABI encoding; selector computation |
| `references/pending-impl.md` | Implementing any Tier 1/2/3 pending feature or novel idea — includes exact hook points per file |
| `references/vm-runtime.md` | executor.zig, decoder.zig, sandbox.zig, gas/ internals; ZephyriaVM execution model |
