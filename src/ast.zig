// ============================================================================
// Forge Compiler — Abstract Syntax Tree
// ============================================================================
//
// Complete in-memory representation of a parsed .foz source file.
// The parser produces this tree; the type-checker and code-generator consume it.
//
// SPEC REFERENCE:
//   Part 2  — All Types
//   Part 3  — Accounts
//   Part 4  — Authorities
//   Part 5  — Contract Anatomy
//   Part 6  — Control Flow
//   Part 7  — Access Control
//   Part 8  — Native Assets
//   Part 9  — Parallel Execution
//   Part 10 — Cross-Contract Communication
//   Part 15 — Interfaces
//
// This is a library file. No main() function is present.

const std = @import("std");
pub const errors = @import("errors.zig");
pub const CompileError = errors.CompileError;

// ============================================================================
// SECTION 1 — Source Location
// ============================================================================

/// Source span carried by every AST node for error reporting.
/// All positions are 1-based.
pub const Span = struct {
    /// 1-based line number in the source file.
    line: u32,
    /// 1-based UTF-8 column number (byte offset within line).
    col:  u32,
    /// Byte length of the node's textual representation.
    len:  u32,
};

// ============================================================================
// SECTION 2 — Type Expressions (Part 2.1 – 2.14)
// ============================================================================

/// Represents any ZEPH type expression in source code.
///
/// Heap-allocated children (pointer fields) are owned by the arena passed to
/// the parser; free with `freeAll` at the end of the compilation pipeline.
pub const TypeExpr = union(enum) {
    // ── Unsigned integers ─────────────────────────────────────────────────
    u8, u16, u32, u64, u128, u256,
    /// `uint` — alias for `u256`, default for all token math.
    uint,

    // ── Signed integers ───────────────────────────────────────────────────
    i8, i16, i32, i64, i128, i256,
    /// `int` — alias for `i256`.
    int,

    // ── Fixed-point numbers ───────────────────────────────────────────────
    /// `Fixed[N]` — fixed-point with N decimal places (6 ≤ N ≤ 18).
    fixed: struct { decimals: u8 },
    /// `price9`  — alias for `Fixed[9]`.
    price9,
    /// `price18` — alias for `Fixed[18]`.
    price18,
    /// `percent` — alias for `Fixed[4]`.
    percent,

    // ── Boolean ───────────────────────────────────────────────────────────
    bool,

    // ── Address types ─────────────────────────────────────────────────────
    /// `Account` — any 32-byte on-chain account address.
    account,
    /// `Wallet`  — user-controlled account (sub-type of Account).
    wallet,
    /// `Program` — contract/program account (sub-type of Account).
    program,
    /// `System`  — system-level account (sub-type of Account).
    system_acc,

    // ── Hash / byte types ─────────────────────────────────────────────────
    /// `Hash`      — 32-byte SHA3-256 output.
    hash,
    /// `Hash20`    — 20-byte legacy hash.
    hash20,
    /// `Commitment`— 32-byte hiding commitment.
    commitment,
    /// `byte`      — single byte.
    byte,
    /// `Bytes`     — variable-length byte array.
    bytes,
    /// `Bytes32`   — exactly 32 bytes.
    bytes32,
    /// `Bytes64`   — exactly 64 bytes.
    bytes64,
    /// `Signature` — 96-byte BLS12-381 signature.
    signature,
    /// `PublicKey` — 48-byte BLS12-381 public key.
    pubkey,

    // ── Time types ────────────────────────────────────────────────────────
    /// `Timestamp`   — unix timestamp in milliseconds (u64).
    timestamp,
    /// `Duration`    — time interval in milliseconds (u64).
    duration,
    /// `BlockNumber` — block height (u64).
    block_number,
    /// `Epoch`       — consensus epoch number (u64).
    epoch,
    /// `Slot`        — slot number within an epoch (u32).
    slot,

    // ── Text types ────────────────────────────────────────────────────────
    /// `String`    — UTF-8 text stored in contract state.
    string,
    /// `ShortStr`  — up to 31 bytes, packed into one storage slot.
    short_str,
    /// `Label`     — compile-time-only string (events, errors, docs).
    label,

    // ── Composite types ───────────────────────────────────────────────────
    /// `maybe Type` — an optional value.
    maybe: *TypeExpr,
    /// `Result[OkType, ErrType]`.
    result: struct { ok: *TypeExpr, err: *TypeExpr },
    /// `Map[KeyType → ValueType]`.
    map: struct { key: *TypeExpr, value: *TypeExpr },
    /// `EnumMap[KeyType → ValueType]` — iterable map.
    enum_map: struct { key: *TypeExpr, value: *TypeExpr },
    /// `List[Type]`.
    list: *TypeExpr,
    /// `Set[Type]`.
    set: *TypeExpr,
    /// `Array[Type, Size]` — compile-time fixed length.
    array: struct { elem: *TypeExpr, size: u64 },
    /// Unnamed tuple: `(TypeA, TypeB, ...)`.
    tuple: []*TypeExpr,

    // ── Named / generic types ─────────────────────────────────────────────
    /// A user-declared struct, enum, alias, asset, or interface name.
    named: []const u8,
    /// A generic instantiation: `Name[T1, T2, ...]`.
    generic: struct { name: []const u8, params: []*TypeExpr },

    // ── Source location ────────────────────────────────────────────────────
    /// Attached span, stored as a tagged variant to keep the union flat.
    /// The parser attaches this to every `TypeExpr` via a wrapping struct;
    /// when the TypeExpr is embedded in `Expr` or a declaration, the outer
    /// node's `.span` is authoritative.
    span: Span,
};

// ============================================================================
// SECTION 3 — Expressions
// ============================================================================

/// An expression: carries both its kind and its source span.
pub const Expr = struct {
    kind: ExprKind,
    span: Span,
};

/// Every expression kind the ZEPH language can form.
pub const ExprKind = union(enum) {
    // ── Literals ──────────────────────────────────────────────────────────
    /// Integer or `u256` literal — stored as the raw digit string from source
    /// to preserve precision (e.g. `"115792089237316195..."``).
    int_lit:    []const u8,
    /// Fixed-point / float literal (e.g. `"1_234.567890"`).
    float_lit:  []const u8,
    /// `yes` or `no` boolean literal.
    bool_lit:   bool,
    /// A double-quoted UTF-8 string literal.
    string_lit: []const u8,
    /// The `nothing` keyword (empty optional).
    nothing,
    /// `something(expr)` — wrapping a value in an optional.
    something:  *Expr,

    // ── Name resolution ───────────────────────────────────────────────────
    /// A bare identifier or qualified name (e.g. `x`, `mine`, `params.user`).
    identifier: []const u8,

    // ── Access ────────────────────────────────────────────────────────────
    /// `expr.field` — field access.
    field_access: struct { object: *Expr, field: []const u8 },
    /// `expr[key]`  — index/map access.
    index_access: struct { object: *Expr, index: *Expr },

    // ── Operators ─────────────────────────────────────────────────────────
    /// Binary infix operation (`a plus b`, `x equals y`, etc.).
    bin_op: struct { op: BinOp, left: *Expr, right: *Expr },
    /// Unary prefix operation (`not x`, `negate x`).
    unary_op: struct { op: UnaryOp, operand: *Expr },

    // ── Calls ─────────────────────────────────────────────────────────────
    /// Function / action / view / pure call with positional or named args.
    call: struct { callee: *Expr, args: []Argument },

    // ── Construction ──────────────────────────────────────────────────────
    /// Struct literal: `TypeName { field = val, ... }`.
    struct_lit: struct { type_name: []const u8, fields: []FieldInit },
    /// Tuple literal: `(a, b, c)`.
    tuple_lit:  []*Expr,

    // ── Pattern matching ──────────────────────────────────────────────────
    /// `match subject: arm1 arm2 ...` used as an expression (e.g. in let).
    match_expr: struct { subject: *Expr, arms: []MatchArm },

    // ── Conditional expression ────────────────────────────────────────────
    /// Inline conditional: `when cond then a otherwise b`.
    inline_when: struct { cond: *Expr, then_: *Expr, else_: *Expr },

    // ── Type cast ─────────────────────────────────────────────────────────
    /// `expr as TypeName` — explicit type conversion.
    cast: struct { expr: *Expr, to: TypeExpr },

    // ── Built-in context values ───────────────────────────────────────────
    /// One of the implicitly-available builtins from the execution environment.
    builtin: BuiltinExpr,

    // ── Result propagation ────────────────────────────────────────────────
    /// `expr?` — propagate a `Result` failure to the caller.
    try_propagate: *Expr,

    // ── Asset operations (Part 8) ─────────────────────────────────────────
    /// `asset.split(amount)` — split a linear asset into two parts.
    asset_split: struct { asset: *Expr, amount: *Expr },
    /// `AssetType.wrap(value)` — wrap native currency into a typed asset.
    asset_wrap: struct { asset_type: []const u8, value: *Expr },
    /// `AssetType.unwrap(token)` — unwrap a typed asset to native currency.
    asset_unwrap: struct { asset_type: []const u8, token: *Expr },
};

/// A function/action call argument — may be positional or named.
pub const Argument = struct {
    /// If `null`, this is a positional argument; otherwise it is named.
    name:  ?[]const u8,
    value: *Expr,
    span:  Span,
};

/// One field initialiser inside a struct literal: `fieldName = expr`.
pub const FieldInit = struct {
    name:  []const u8,
    value: *Expr,
    span:  Span,
};

// ── Binary operators ─────────────────────────────────────────────────────────

/// All binary infix operators available in ZEPH expressions.
pub const BinOp = enum {
    /// `a plus b`
    plus,
    /// `a minus b`
    minus,
    /// `a times b`
    times,
    /// `a divided by b`
    divided_by,
    /// `a mod b`
    mod,
    /// `a equals b`
    equals,
    /// `a is not b` (not-equal)
    not_equals,
    /// `a less b` (`<`)
    less,
    /// `a less or equal b` (`<=`)
    less_eq,
    /// `a greater b` (`>`)
    greater,
    /// `a greater or equal b` (`>=`)
    greater_eq,
    /// `a and b`
    and_,
    /// `a or b`
    or_,
    /// `collection has element` — membership test.
    has,
    /// `a plus b` for Duration arithmetic: `now() plus 7 days`.
    duration_add,
    /// `a minus b` for Duration arithmetic.
    duration_sub,
};

/// Unary prefix operators.
pub const UnaryOp = enum {
    /// `not expr` — logical negation.
    not_,
    /// `negate expr` — arithmetic negation.
    negate,
};

/// Built-in context values available inside any ZEPH action/view.
pub const BuiltinExpr = enum {
    /// `caller`        — the account that signed this transaction.
    caller,
    /// `value`         — the native token amount attached to this call.
    value,
    /// `deployer`      — the account that initially deployed this contract.
    deployer,
    /// `this.address`  — the program's own on-chain address.
    this_address,
    /// `zero_address`  — the all-zero address (used as a null sentinel).
    zero_address,
    /// `now()`         — current block timestamp in milliseconds.
    now,
    /// `current_block()` — current block number.
    current_block,
    /// `gas_remaining()` — gas units remaining for this transaction.
    gas_remaining,
};

// ============================================================================
// SECTION 4 — Patterns (for match arms)
// ============================================================================

/// Pattern used in a `match` arm or destructuring assignment.
pub const Pattern = union(enum) {
    /// `_` — matches anything, binds nothing.
    wildcard,
    /// A literal value (`42`, `yes`, `"hello"`, `nothing`).
    literal:  *Expr,
    /// A named binding (`x`) — matches anything, binds to the given name.
    binding:  []const u8,
    /// `nothing` — matches the absent optional.
    nothing,
    /// `something(binding)` — matches a present optional, binds inner value.
    something: []const u8,
    /// `ok(binding)` — matches the success arm of a Result.
    ok:        []const u8,
    /// `fail(binding)` or `fail(ErrorVariant(bindings))`.
    fail:      PatternFail,
    /// `EnumType.Variant` or `EnumType.Variant { field = binding, ... }`.
    enum_variant: PackedEnumVariant,
    /// Range pattern: `lo .. hi` (inclusive).
    range:    struct { lo: *Expr, hi: *Expr },
    /// Tuple pattern: `(p1, p2, ...)`.
    tuple:    []Pattern,
};

/// Data carried in a `fail(...)` pattern.
pub const PatternFail = struct {
    /// Optional concrete error variant name; `null` means catch-all `fail(x)`.
    variant:  ?[]const u8,
    /// Variable name(s) bound to the error's fields.
    bindings: [][]const u8,
};

/// An enum variant pattern, optionally with field bindings.
pub const PackedEnumVariant = struct {
    type_name:    []const u8,
    variant_name: []const u8,
    /// Named bindings for variant fields, e.g. `{ price = p }`.
    field_bindings: []FieldBinding,
};

/// A single named field binding inside a pattern.
pub const FieldBinding = struct {
    field:   []const u8,
    binding: []const u8,
};

/// A single arm of a `match` statement or `match` expression.
pub const MatchArm = struct {
    pattern: Pattern,
    /// Arm body — one or more statements.
    body:    []Stmt,
    span:    Span,
};

// ============================================================================
// SECTION 5 — Statements
// ============================================================================

/// A statement node: one executable step in a function/action body.
pub const Stmt = struct {
    kind: StmtKind,
    span: Span,
};

/// Every statement form available in ZEPH (Parts 5 and 6).
pub const StmtKind = union(enum) {
    // ── Bindings ──────────────────────────────────────────────────────────
    /// `let x is Type = expr`  or  `let x = expr` (type inferred).
    let_bind:   LetBind,
    /// `target = expr` — simple assignment.
    assign:     Assign,
    /// `target += expr` / `-=` / `*=` / … — augmented assignment.
    aug_assign: AugAssign,

    // ── Control flow ──────────────────────────────────────────────────────
    /// `when cond: … otherwise when cond: … otherwise: …`
    when:       WhenStmt,
    /// `match subject: arm …`
    match:      MatchStmt,
    /// `each (k, v) in collection: …`
    each:       EachLoop,
    /// `repeat N times: …`
    repeat:     RepeatLoop,
    /// `while cond: …`
    while_:     WhileLoop,

    // ── Assertions ────────────────────────────────────────────────────────
    /// `need cond else "message"` or `need cond else TypedError(…)`.
    need:       NeedStmt,
    /// `ensure cond else "message"` — post-condition check.
    ensure:     EnsureStmt,
    /// `panic "message"` — unconditional abort.
    panic:      PanicStmt,

    // ── Early exit ────────────────────────────────────────────────────────
    /// `give back expr` — return a value.
    give_back:  *Expr,
    /// `stop` — break out of a loop.
    stop,
    /// `skip` — continue to next loop iteration.
    skip,

    // ── Events & errors ───────────────────────────────────────────────────
    /// `tell EventName(args…)` — emit an event.
    tell:       TellStmt,
    /// `throw ErrorType(args…)`.
    throw:      ThrowStmt,
    /// `attempt: … on_error E: … always_after: …`
    attempt:    AttemptStmt,

    // ── Expression statement ──────────────────────────────────────────────
    /// A bare call expression used as a statement (return value discarded).
    call_stmt:  *Expr,

    // ── State mutation ────────────────────────────────────────────────────
    /// `remove mine.map[key]` — delete a map entry.
    remove:     *Expr,
    /// `pay account amount` — transfer native currency.
    pay:        PayStmt,
    /// `send asset to account` — transfer a linear asset.
    send:       SendStmt,
    /// `move asset into mine.field` — store a linear asset in state.
    move_asset: MoveStmt,

    // ── Account lifecycle ─────────────────────────────────────────────────
    /// `expand account by N bytes` — grow account storage.
    expand:     ExpandStmt,
    /// `close account refund_lamports_to wallet` — destroy an account.
    close:      CloseStmt,
    /// `freeze account` — prevent all transfers from/to an account.
    freeze:     FreezeStmt,
    /// `unfreeze account`.
    unfreeze:   UnfreezeStmt,

    // ── Cross-contract ────────────────────────────────────────────────────
    /// `schedule call after duration` — deferred cross-program call.
    schedule:   ScheduleStmt,

    // ── Access control ────────────────────────────────────────────────────
    /// `guard guardName` — apply a named guard at this point.
    guard_apply: []const u8,
    /// `only authorityName` / `only [a, b, c]` / `only auth1 or auth2`.
    only:       OnlyStmt,

    // ── Ownership ────────────────────────────────────────────────────────
    /// `transfer_ownership(account, to: new_owner)`.
    transfer_ownership: TransferOwnershipStmt,
};

// ── Statement sub-structs ────────────────────────────────────────────────────

/// `let x is Type = expr` or `let x = expr`.
pub const LetBind = struct {
    /// The name being introduced.
    name:         []const u8,
    /// Optional declared type.  `null` means inferred.
    declared_type: ?TypeExpr,
    /// The initialiser expression.
    init:         *Expr,
    /// `readonly` / `let` immutability.
    mutable:      bool,
    span:         Span,
};

/// `target = value`.
pub const Assign = struct {
    target: *Expr,
    value:  *Expr,
};

/// The augmented-assignment operator.
pub const AugOp = enum {
    /// `+=`
    add,
    /// `-=`
    sub,
    /// `*=`  (`times=`)
    mul,
    /// `/=`  (`divided_by=`)
    div,
    /// `%=`
    mod,
};

/// `target op= value`.
pub const AugAssign = struct {
    target: *Expr,
    op:     AugOp,
    value:  *Expr,
};

/// `when cond: body … [otherwise when cond: body …] [otherwise: body]`.
pub const WhenStmt = struct {
    /// The primary condition.
    cond:       *Expr,
    /// Statements for the true branch.
    then_body:  []Stmt,
    /// Zero or more `otherwise when` branches.
    else_ifs:   []ElseIf,
    /// Optional final `otherwise:` branch.
    else_body:  ?[]Stmt,
};

/// A single `otherwise when cond: body` clause.
pub const ElseIf = struct {
    cond: *Expr,
    body: []Stmt,
    span: Span,
};

/// `match subject: arm …`
pub const MatchStmt = struct {
    subject: *Expr,
    arms:    []MatchArm,
};

/// `each item in collection: body`  or  `each (k, v) in collection: body`.
pub const EachLoop = struct {
    /// Variable(s) bound per iteration.  Single name or destructure tuple.
    binding:    EachBinding,
    /// The collection expression.
    collection: *Expr,
    /// Optional `#[max_iterations N]` annotation.
    max_iters:  ?u64,
    body:       []Stmt,
};

/// Binding form used in `each`.
pub const EachBinding = union(enum) {
    /// Single variable: `each x in …`
    single: []const u8,
    /// Tuple destructure: `each (k, v) in …`  or  `each (i, x) in …indexed`
    pair:   struct { first: []const u8, second: []const u8 },
};

/// `repeat N times: body`
pub const RepeatLoop = struct {
    count:     *Expr,
    max_iters: ?u64,
    body:      []Stmt,
};

/// `while cond: body`
pub const WhileLoop = struct {
    cond:      *Expr,
    max_iters: ?u64,
    body:      []Stmt,
};

/// `need cond else <else_clause>`
pub const NeedStmt = struct {
    cond:  *Expr,
    else_: NeedElse,
    span:  Span,
};

/// The failure branch of a `need` or `ensure` statement.
pub const NeedElse = union(enum) {
    /// `else "string message"` — simple string abort.
    string_msg: []const u8,
    /// `else ErrorType(args…)` — typed error constructor.
    typed_error: TypedErrorCall,
};

/// A typed error thrown in `need X else ErrorType(a, b)` or `throw ErrorType(a, b)`.
pub const TypedErrorCall = struct {
    error_type: []const u8,
    args:       []Argument,
    span:       Span,
};

/// `ensure cond else <else_clause>` — post-condition assertion.
pub const EnsureStmt = struct {
    cond:  *Expr,
    else_: NeedElse,
    span:  Span,
};

/// `panic "message"` — unconditional runtime abort.
pub const PanicStmt = struct {
    message: []const u8,
};

/// `tell EventName(args…)` — emit a contract event.
pub const TellStmt = struct {
    event_name: []const u8,
    args:       []Argument,
    span:       Span,
};

/// `throw ErrorType(args…)`.
pub const ThrowStmt = struct {
    error_call: TypedErrorCall,
};

/// `attempt: body on_error EType(binds): handler … [always_after: cleanup]`
pub const AttemptStmt = struct {
    body:        []Stmt,
    on_error:    []OnErrorClause,
    /// Optional `always_after:` cleanup block (runs regardless of success/failure).
    always_body: ?[]Stmt,
};

/// A single `on_error ErrorType(bindings): handler` clause.
pub const OnErrorClause = struct {
    /// `null` = catch-all `on_error _:`
    error_type: ?[]const u8,
    /// Bound variable names from the error fields.
    bindings:   [][]const u8,
    body:       []Stmt,
    span:       Span,
};

/// `pay account amount` — transfer native ZPH.
pub const PayStmt = struct {
    recipient: *Expr,
    amount:    *Expr,
};

/// `send asset to account` — consume a linear asset by transferring it.
pub const SendStmt = struct {
    asset:     *Expr,
    recipient: *Expr,
};

/// `move asset into mine.field` — store a linear asset into contract state.
pub const MoveStmt = struct {
    asset: *Expr,
    dest:  *Expr,
};

/// `expand account by N bytes`.
pub const ExpandStmt = struct {
    account: *Expr,
    bytes:   *Expr,
};

/// `close account refund_lamports_to wallet`.
pub const CloseStmt = struct {
    account:   *Expr,
    refund_to: *Expr,
};

/// `freeze account`.
pub const FreezeStmt = struct {
    account: *Expr,
};

/// `unfreeze account`.
pub const UnfreezeStmt = struct {
    account: *Expr,
};

/// `schedule call after duration` — deferred invocation (Part 10.2).
pub const ScheduleStmt = struct {
    /// The call expression to be scheduled.
    call:  *Expr,
    after: *Expr,
    span:  Span,
};

/// `only auth` / `only auth1 or auth2` / `only [addr, addr]`.
pub const OnlyStmt = struct {
    requirement: OnlyRequirement,
    span:        Span,
};

/// The subject of an `only` guard.
pub const OnlyRequirement = union(enum) {
    /// `only admin_authority` — single named authority.
    authority: []const u8,
    /// `only auth1 or auth2` — either authority accepts.
    either:    struct { left: []const u8, right: []const u8 },
    /// `only [addr1, addr2, addr3]` — hardcoded address allowlist.
    address_list: [][]const u8,
    /// `only authority.any_signer` — any signer of a multisig authority.
    any_signer: []const u8,
};

/// `transfer_ownership(account, to: new_owner)`.
pub const TransferOwnershipStmt = struct {
    account:   *Expr,
    new_owner: *Expr,
    span:      Span,
};

// ============================================================================
// SECTION 6 — Annotations (Parts 9 and 14)
// ============================================================================

/// Every recognized `#[...]` action annotation in ZEPH.
pub const AnnotationKind = enum {
    /// `#[parallel]` — declare this action safe to execute in parallel.
    parallel,
    /// `#[reads mine.field]` — explicit read claim (overrides inference).
    reads,
    /// `#[writes mine.field]` — explicit write claim.
    writes,
    /// `#[max_iterations N]` — bound on any loop in this action.
    max_iterations,
    /// `#[gas_check N]` — assert at most N gas units consumed.
    gas_check,
    /// `#[zk_proof CircuitName]` — ZK circuit reference (Part 12).
    zk_proof,
    /// `#[private input_name]` — marks an input as a ZK private input.
    private,
    /// `#[gas_sponsored_for mine.set]` — sponsor gas for accounts in set.
    gas_sponsored_for,
};

/// A parsed `#[kind args...]` annotation attached to an action/view/pure.
pub const Annotation = struct {
    kind: AnnotationKind,
    /// The raw argument list (e.g. the field access expression or an integer).
    args: []*Expr,
    span: Span,
};

// ============================================================================
// SECTION 7 — Shared Declarations
// ============================================================================

/// A typed function / action parameter: `name is Type`.
pub const Param = struct {
    name:         []const u8,
    declared_type: TypeExpr,
    /// `true` when annotated with `#[private]` (ZK input).
    is_private:   bool,
    span:         Span,
};

// ============================================================================
// SECTION 8 — Account Declarations (Part 3)
// ============================================================================

/// The built-in ZEPH account kinds that can appear in an `accounts:` block.
pub const AccountKind = enum {
    data,
    vault,
    asset,
    oracle,
    wallet,
    program,
    system,
};

/// Ownership declaration: `owned_by this` / `owned_by params.user` / etc.
pub const AccountOwnership = union(enum) {
    /// `owned_by this` — by the current contract.
    this,
    /// `owned_by params.X` — by an account passed as a transaction parameter.
    param: []const u8,
    /// `owned_by ProgramName` — by a named program account.
    named: []const u8,
    /// `global` — not owned by us; referenced globally.
    global,
};

/// A single capability clause inside `can: read field / write field / …`
pub const CapabilityClause = struct {
    /// `read` or `write` or `debit` or `credit`.
    access: CapabilityAccess,
    /// `null` means `all_fields`.
    fields: ?[][]const u8,
};

/// The access mode in a capability clause.
pub const CapabilityAccess = enum {
    read,
    write,
    debit,
    credit,
};

/// A seed component: string literal, address, or expression.
pub const SeedComponent = union(enum) {
    string_lit: []const u8,
    param_ref:  []const u8,
    expr:       *Expr,
};

/// A full account declaration inside an `accounts:` block.
pub const AccountDecl = struct {
    /// The local name used inside this contract (e.g. `mine`, `user_vault`).
    name:              []const u8,
    /// Built-in kind (Data, Vault, Asset, …).
    kind:              AccountKind,
    /// Optional generic type parameter (e.g. the token type for a Vault).
    type_param:        ?TypeExpr,
    /// Ownership model.
    ownership:         AccountOwnership,
    /// PDA seed components for derived accounts.
    seeds:             []SeedComponent,
    /// `readonly` — compiler prevents any write to this account.
    readonly:          bool,
    /// Declared capability list (what fields may be read/written).
    capabilities:      []CapabilityClause,
    /// `create_if_missing` — VM creates this account if absent.
    create_if_missing: bool,
    /// `initial_size N bytes` — storage pre-allocated at creation.
    initial_size:      ?u64,
    /// `at known.X` — a statically-known globally-deployed account address.
    known_address:     ?[]const u8,
    /// `child_of accountName` — parent-child relationship.
    child_of:          ?[]const u8,
    span:              Span,
};

// ============================================================================
// SECTION 9 — Authority Declarations (Part 4)
// ============================================================================

/// The holder type for an authority.
pub const AuthorityHolderKind = enum {
    wallet,
    program,
    multisig,
    dao,
    nobody,
};

/// Configuration for a multisig authority (`held_by Multisig { … }`).
pub const MultisigConfig = struct {
    signers:     []*Expr,
    required:    u32,
    time_window: ?*Expr,
};

/// Configuration for a DAO authority (`held_by DAO { … }`).
pub const DaoConfig = struct {
    governance_program: []const u8,
    proposal_threshold: ?*Expr,
    quorum:             ?*Expr,
};

/// A single authority declaration inside an `authorities:` block.
pub const AuthorityDecl = struct {
    /// The local name (e.g. `mint_authority`).
    name:           []const u8,
    /// The authority kind (e.g. `MintAuthority`).
    kind:           []const u8,
    /// The holder type enum.
    holder_type:    AuthorityHolderKind,
    /// Initial holder: an expression, `deployer`, `nobody`, etc.
    initial_holder: ?*Expr,
    /// Optional timelock duration.
    timelock:       ?*Expr,
    /// Present when `held_by Multisig { … }`.
    multisig_cfg:   ?MultisigConfig,
    /// Present when `held_by DAO { … }`.
    dao_cfg:        ?DaoConfig,
    /// List of action names this authority covers (`covers: [a, b]`).
    covers:         [][]const u8,
    /// `inherits_from parentAuthority`.
    inherits_from:  ?[]const u8,
    /// `inheritable` — sub-contracts can inherit this authority.
    inheritable:    bool,
    span:           Span,
};

// ============================================================================
// SECTION 10 — Contract Fields (Part 5.2, 5.3)
// ============================================================================

/// A single field in the `has:` (state) block: `name is Type`.
pub const StateField = struct {
    name:         []const u8,
    type_:        TypeExpr,
    /// Optional `in namespace` sub-namespace tag.
    namespace:    ?[]const u8,
    span:         Span,
};

/// A `computed:` field — derived from state, not stored directly.
pub const ComputedField = struct {
    name:    []const u8,
    type_:   TypeExpr,
    /// The expression evaluated to produce the computed value.
    expr:    *Expr,
    span:    Span,
};

/// A field in the `config:` block — runtime-configurable constant.
pub const ConfigField = struct {
    name:         []const u8,
    type_:        TypeExpr,
    default_val:  ?*Expr,
    span:         Span,
};

/// A top-level constant: `define NAME as value`.
pub const ConstDecl = struct {
    name:  []const u8,
    type_: ?TypeExpr,
    value: *Expr,
    span:  Span,
};

// ============================================================================
// SECTION 11 — Function-Level Declarations (Part 5)
// ============================================================================

/// Visibility keyword on an action or view.
pub const Visibility = enum {
    /// Default — callable from outside.
    shared,
    /// Only callable from this contract or inheriting contracts.
    within,
    /// Only callable from exactly this contract.
    hidden,
    /// Only callable from external programs, not EOA wallets.
    outside,
    /// Only callable by the Zephyria system program.
    system,
};

/// An action declaration (state-changing function).
pub const ActionDecl = struct {
    name:        []const u8,
    visibility:  Visibility,
    /// Generic type parameters, e.g. `[T where T follows Transferable]`.
    type_params: []TypeParam,
    params:      []Param,
    return_type: ?TypeExpr,
    annotations: []Annotation,
    /// Local account declarations inside the action.
    accounts:    []AccountDecl,
    body:        []Stmt,
    span:        Span,
};

/// A view declaration (read-only function).
pub const ViewDecl = struct {
    name:        []const u8,
    visibility:  Visibility,
    type_params: []TypeParam,
    params:      []Param,
    return_type: ?TypeExpr,
    /// Local account declarations.
    accounts:    []AccountDecl,
    body:        []Stmt,
    span:        Span,
};

/// A pure function (no state access).
pub const PureDecl = struct {
    name:        []const u8,
    type_params: []TypeParam,
    params:      []Param,
    return_type: ?TypeExpr,
    body:        []Stmt,
    span:        Span,
};

/// A generic type parameter with optional constraint: `T where T follows I`.
pub const TypeParam = struct {
    name:       []const u8,
    /// Interface constraint (`where T follows InterfaceName`), or `null`.
    constraint: ?[]const u8,
};

/// An internal helper declaration (`helper` keyword — within-only by default).
pub const HelperDecl = struct {
    name:        []const u8,
    params:      []Param,
    return_type: ?TypeExpr,
    body:        []Stmt,
    span:        Span,
};

/// A guard declaration: `guard name(params): body`.
pub const GuardDecl = struct {
    name:   []const u8,
    params: []Param,
    body:   []Stmt,
    span:   Span,
};

/// An event declaration: `event Name(field is Type indexed, ...)`.
pub const EventDecl = struct {
    name:   []const u8,
    fields: []EventField,
    span:   Span,
};

/// One field in an event declaration.
pub const EventField = struct {
    name:    []const u8,
    type_:   TypeExpr,
    /// `indexed` — this field is searchable in the event log.
    indexed: bool,
    span:    Span,
};

/// A contract-level error declaration: `error Name(field is Type, ...)`.
pub const ErrorDecl = struct {
    name:   []const u8,
    fields: []ErrorField,
    span:   Span,
};

/// One field in an error declaration.
pub const ErrorField = struct {
    name:  []const u8,
    type_: TypeExpr,
    span:  Span,
};

/// The `setup` (constructor) block of a contract.
pub const SetupBlock = struct {
    params: []Param,
    body:   []Stmt,
    span:   Span,
};

/// A contract-level invariant (for formal verification / fuzzing).
pub const InvariantDecl = struct {
    name:  []const u8,
    cond:  *Expr,
    span:  Span,
};

/// The `upgrade:` block — declares upgrade policy (Part 13).
pub const UpgradeBlock = struct {
    /// The authority that can authorise upgrades.
    authority:  []const u8,
    /// Optional migration function name.
    migrate_fn: ?[]const u8,
    /// Optional version guard expression.
    version:    ?*Expr,
    span:       Span,
};

// ============================================================================
// SECTION 12 — Asset Declarations (Part 8)
// ============================================================================

/// A transfer hook inside an asset declaration.
pub const AssetTransferHook = struct {
    /// `before_transfer` or `after_transfer`.
    when: AssetHookWhen,
    params: []Param,
    body:   []Stmt,
    span:   Span,
};

/// When a transfer hook fires.
pub const AssetHookWhen = enum {
    before_transfer,
    after_transfer,
};

/// A top-level `asset Name { … }` declaration.
pub const AssetDef = struct {
    name:             []const u8,
    /// `name:` display name (e.g. `"Zephyria Token"`).
    display_name:     ?[]const u8,
    /// `symbol:` short ticker (e.g. `"ZEPH"`).
    symbol:           ?[]const u8,
    /// `decimals:` N decimal places.
    decimals:         ?u8,
    /// `max_supply:` hard cap on total tokens.
    max_supply:       ?*Expr,
    /// Authorities declared for this asset (mint, freeze, burn, etc.).
    authorities:      []AuthorityDecl,
    /// Optional before/after transfer hooks.
    before_transfer:  ?AssetTransferHook,
    after_transfer:   ?AssetTransferHook,
    /// `metadata_per_token: yes` — each token ID has its own metadata (NFT).
    metadata_per_token: bool,
    span:             Span,
};

// ============================================================================
// SECTION 13 — Interface Declarations (Part 15)
// ============================================================================

/// A declaration inside an interface body.
pub const InterfaceMember = union(enum) {
    action: InterfaceAction,
    view:   InterfaceView,
    event:  EventDecl,
    error_:  ErrorDecl,
};

/// An action signature inside an interface (no body).
pub const InterfaceAction = struct {
    name:        []const u8,
    params:      []Param,
    return_type: ?TypeExpr,
    span:        Span,
};

/// A view signature inside an interface.
pub const InterfaceView = struct {
    name:        []const u8,
    params:      []Param,
    return_type: ?TypeExpr,
    span:        Span,
};

/// A top-level `interface Name { … }` declaration.
pub const InterfaceDef = struct {
    name:    []const u8,
    members: []InterfaceMember,
    span:    Span,
};

// ============================================================================
// SECTION 14 — Top-Level File Nodes
// ============================================================================

/// `use module.path` import statement.
pub const UseImport = struct {
    /// Dot-separated path, e.g. `["standard", "math"]`.
    path:  [][]const u8,
    /// Optional local alias: `use standard.math as sm`.
    alias: ?[]const u8,
    span:  Span,
};

/// Every top-level construct that can appear in a `.foz` file.
pub const TopLevel = union(enum) {
    /// `version N` — must be the first declaration.
    version:       u32,
    /// `use module.path` — import.
    use_import:    UseImport,
    /// `define NAME as value` — top-level constant.
    constant:      ConstDecl,
    /// `asset Name { … }` — asset definition.
    asset_def:     AssetDef,
    /// `interface Name { … }` — interface definition.
    interface_def: InterfaceDef,
    /// `contract Name { … }` — the primary construct.
    contract:      ContractDef,
    /// `record Name { … }` — named tuple type alias.
    record_def:    RecordDef,
    /// `struct Name { … }` — user-defined struct type.
    struct_def:    StructDef,
    /// `enum Name { … }` — user-defined enum type.
    enum_def:      EnumDef,
    /// `alias NewName = ExistingType`.
    type_alias:    TypeAliasDef,
};

// ── User-defined type definitions ────────────────────────────────────────────

/// `record Name { field is Type, ... }` — named tuple.
pub const RecordDef = struct {
    name:   []const u8,
    fields: []RecordField,
    span:   Span,
};

/// A single field in a record or struct.
pub const RecordField = struct {
    name:    []const u8,
    type_:   TypeExpr,
    /// Optional default value.
    default: ?*Expr,
    span:    Span,
};

/// `struct Name { field is Type, ... }` — value type struct.
pub const StructDef = struct {
    name:        []const u8,
    type_params: []TypeParam,
    fields:      []RecordField,
    span:        Span,
};

/// `enum Name { Variant, Variant { field is Type }, ... }`.
pub const EnumDef = struct {
    name:     []const u8,
    variants: []EnumVariant,
    span:     Span,
};

/// One variant of an enum (simple or with associated data).
pub const EnumVariant = struct {
    name:   []const u8,
    /// Empty slice = no associated data.
    fields: []RecordField,
    span:   Span,
};

/// `alias NewName = ExistingType`.
pub const TypeAliasDef = struct {
    name: []const u8,
    type_: TypeExpr,
    span: Span,
};

// ============================================================================
// SECTION 15 — ContractDef (Part 5)
// ============================================================================

/// The complete AST node for a `contract Name { … }` declaration.
pub const ContractDef = struct {
    /// Contract name.
    name:        []const u8,
    /// `inherits OtherContract`.
    inherits:    ?[]const u8,
    /// `implements Interface1, Interface2`.
    implements:  [][]const u8,
    /// `accounts:` block.
    accounts:    []AccountDecl,
    /// `authorities:` block.
    authorities: []AuthorityDecl,
    /// `config:` block — runtime-configurable parameters.
    config:      []ConfigField,
    /// `always:` block — contract-level constants.
    always:      []ConstDecl,
    /// `has:` block — persistent state fields.
    state:       []StateField,
    /// `computed:` — derived (non-stored) fields.
    computed:    []ComputedField,
    /// `setup` — constructor.
    setup:       ?SetupBlock,
    /// Named guards.
    guards:      []GuardDecl,
    /// Public / internal actions.
    actions:     []ActionDecl,
    /// Read-only views.
    views:       []ViewDecl,
    /// Pure functions.
    pures:       []PureDecl,
    /// Internal helpers.
    helpers:     []HelperDecl,
    /// Emittable events.
    events:      []EventDecl,
    /// Typed errors this contract can throw.
    errors_:     []ErrorDecl,
    /// `upgrade:` block (optional, Part 13).
    upgrade:     ?UpgradeBlock,
    /// Sub-namespace names declared with `namespace X`.
    namespaces:  [][]const u8,
    /// Invariant declarations for formal verification.
    invariants:  []InvariantDecl,
    span:        Span,
};

/// The parsed representation of an entire `.foz` source file.
pub const SourceFile = struct {
    /// Absolute or relative path to the file.
    path:       []const u8,
    top_levels: []TopLevel,
};

// ============================================================================
// SECTION 16 — Memory Management Helper
// ============================================================================

/// Recursively free all heap memory owned by an AST node.
///
/// This is called by the compiler driver after code generation is complete
/// to release the AST.  It uses `@TypeOf(node)` at comptime to dispatch
/// to per-type logic; unknown types are ignored (e.g. scalar fields).
///
/// The caller is responsible for ensuring `allocator` is the same allocator
/// that was used to allocate the node's children.
pub fn freeAll(node: anytype, allocator: std.mem.Allocator) void {
    const T = @TypeOf(node);
    freeValue(T, node, allocator);
}

// ── Internal recursive dispatcher (comptime type dispatch) ───────────────────

fn freeValue(comptime T: type, value: T, allocator: std.mem.Allocator) void {
    const info = @typeInfo(T);
    switch (info) {
        .pointer => |ptr_info| {
            if (ptr_info.size == .slice) {
                // Free each element, then free the slice itself.
                for (value) |elem| {
                    freeValue(ptr_info.child, elem, allocator);
                }
                allocator.free(value);
            } else if (ptr_info.size == .one) {
                // Single pointer: recurse into the pointee, then free.
                freeValue(ptr_info.child, value.*, allocator);
                allocator.destroy(value);
            }
            // Multi/C pointers not used in this AST.
        },
        .optional => |opt_info| {
            if (value) |inner| {
                freeValue(opt_info.child, inner, allocator);
            }
        },
        .@"struct" => |struct_info| {
            inline for (struct_info.fields) |field| {
                freeValue(field.type, @field(value, field.name), allocator);
            }
        },
        .@"union" => |union_info| {
            if (union_info.tag_type != null) {
                // Tagged union: dispatch to the active field.
                inline for (union_info.fields) |field| {
                    if (std.mem.eql(u8, @tagName(value), field.name)) {
                        freeValue(field.type, @field(value, field.name), allocator);
                        return;
                    }
                }
            }
        },
        // Scalar types (int, float, bool, enum): nothing to free.
        else => {},
    }
}

