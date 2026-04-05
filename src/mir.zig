// ============================================================================
// Forge Compiler — Mid-Level Intermediate Representation (MIR)
// ============================================================================
//
// Target-agnostic IR that sits between the semantic checker and all codegen
// backends. Every Forge language feature is lowered to MIR exactly once.
// Each backend (Zephyria RISC-V, EVM, PolkaVM, future targets) translates
// MIR → native instructions — a much smaller surface than walking the AST.
//
// SPEC REFERENCE: All Parts — this module covers the entire language surface.
//
// Design:
//   • Flat, linear instruction stream per function (no CFG — backends build
//     their own if needed).
//   • Virtual SSA registers (unlimited, u16-indexed). Backends perform
//     register allocation or stack mapping independently.
//   • State access is abstracted via field IDs, not raw storage slots or
//     account offsets. Each backend maps field IDs to its native layout.
//   • Control flow uses label IDs with jump/branch instructions.
//   • All string literals and constant data are interned into a shared
//     data section referenced by offset.

const std = @import("std");
const ast = @import("ast.zig");
const types = @import("types.zig");
const errors = @import("errors.zig");

const ResolvedType = types.ResolvedType;
const TypeResolver = types.TypeResolver;
const SymbolTable = types.SymbolTable;
const CheckedContract = @import("checker.zig").CheckedContract;
const ContractDef = ast.ContractDef;
const Expr = ast.Expr;
const ExprKind = ast.ExprKind;
const Stmt = ast.Stmt;
const StmtKind = ast.StmtKind;
const BinOp = ast.BinOp;
const UnaryOp = ast.UnaryOp;
const Span = ast.Span;
const DiagnosticList = errors.DiagnosticList;

// ============================================================================
// Section 1 — MIR Types
// ============================================================================

/// SPEC: Part 2 — Collapsed type representation for codegen.
/// MIR collapses Forge's rich type system into a small set of machine-level
/// categories. Backends use this to select instruction widths and encodings.
pub const MirType = enum {
    /// 32-bit integer (u32, i32, Slot, bool at machine level).
    i32,
    /// 64-bit integer (u64, i64, Timestamp, Duration, BlockNumber).
    i64,
    /// 256-bit integer (u256, i256, Hash, Account, all EVM-width values).
    i256,
    /// Boolean (1-bit logical, stored as i32 in registers).
    boolean,
    /// Pointer to memory (data section offset or heap pointer).
    ptr,
    /// No value (void return, statements).
    void_,

    /// SPEC: Part 2.1 — Map a resolved type to its MIR machine category.
    pub fn fromResolved(rt: ResolvedType) MirType {
        return switch (rt) {
            .bool => .boolean,
            .u8, .u16, .u32 => .i32,
            .i8, .i16, .i32 => .i32,
            .u64, .i64, .timestamp, .duration, .block_number => .i64,
            .u128, .i128, .u256, .i256 => .i256,
            .fixed_point => .i256,
            .account, .wallet, .program, .system_acc => .i256,
            .hash, .commitment => .i256,
            .bytes_n => .i256,
            .signature, .pubkey => .ptr,
            .bytes, .string, .short_str => .ptr,
            .map, .enum_map, .list, .set, .array => .ptr,
            .maybe => .i256,
            .tuple, .struct_, .result => .ptr,
            .asset => .i256,
            .linear => .i256,
            .capability => .i256,
            .enum_ => .i32,
            .proof => .ptr,
            .void_ => .void_,
        };
    }
};

/// SPEC: Part 2 — Virtual SSA register reference.
/// Unlimited registers; backends map these to physical registers or stack.
pub const Reg = u16;

/// SPEC: Part 6 — Label for control flow targets.
pub const LabelId = u32;

/// SPEC: Part 5.2 — State field identifier assigned during lowering.
pub const FieldId = u32;

/// SPEC: Part 5.9 — Event identifier assigned during lowering.
pub const EventId = u32;

/// SPEC: Part 5.10 — Error identifier assigned during lowering.
pub const ErrorId = u32;

/// SPEC: Part 5.5 — Function selector (hash of signature).
pub const Selector = u32;

// ============================================================================
// Section 2 — MIR Instructions
// ============================================================================

/// SPEC: All Parts — Every operation the MIR can represent.
/// Each instruction is a flat, self-contained operation. No nested expressions.
pub const MirOp = union(enum) {
    // ── Constants ─────────────────────────────────────────────────────────
    /// SPEC: Part 2.1 — Load a 64-bit immediate into a register.
    const_i64: struct { dst: Reg, value: i64 },
    /// SPEC: Part 2.1 — Load a 256-bit immediate (big-endian) into a register.
    const_i256: struct { dst: Reg, bytes: [32]u8 },
    /// SPEC: Part 2.4 — Load a boolean immediate.
    const_bool: struct { dst: Reg, value: bool },
    /// SPEC: Part 2.3 — Load a pointer to interned string data.
    const_data: struct { dst: Reg, offset: u32, len: u32 },

    // ── Arithmetic ────────────────────────────────────────────────────────
    /// SPEC: Part 2.2 — dst = lhs + rhs.
    add: struct { dst: Reg, lhs: Reg, rhs: Reg },
    /// SPEC: Part 2.2 — dst = lhs - rhs.
    sub: struct { dst: Reg, lhs: Reg, rhs: Reg },
    /// SPEC: Part 2.2 — dst = lhs * rhs.
    mul: struct { dst: Reg, lhs: Reg, rhs: Reg },
    /// SPEC: Part 2.2 — dst = lhs / rhs (unsigned).
    div: struct { dst: Reg, lhs: Reg, rhs: Reg },
    /// SPEC: Part 2.2 — dst = lhs % rhs.
    mod: struct { dst: Reg, lhs: Reg, rhs: Reg },

    // ── Comparison ────────────────────────────────────────────────────────
    /// SPEC: Part 6.1 — dst = (lhs == rhs).
    eq: struct { dst: Reg, lhs: Reg, rhs: Reg },
    /// SPEC: Part 6.1 — dst = (lhs != rhs).
    ne: struct { dst: Reg, lhs: Reg, rhs: Reg },
    /// SPEC: Part 6.1 — dst = (lhs < rhs).
    lt: struct { dst: Reg, lhs: Reg, rhs: Reg },
    /// SPEC: Part 6.1 — dst = (lhs > rhs).
    gt: struct { dst: Reg, lhs: Reg, rhs: Reg },
    /// SPEC: Part 6.1 — dst = (lhs <= rhs).
    le: struct { dst: Reg, lhs: Reg, rhs: Reg },
    /// SPEC: Part 6.1 — dst = (lhs >= rhs).
    ge: struct { dst: Reg, lhs: Reg, rhs: Reg },

    // ── Logic ─────────────────────────────────────────────────────────────
    /// SPEC: Part 6.1 — dst = lhs AND rhs (short-circuit in lowering).
    bool_and: struct { dst: Reg, lhs: Reg, rhs: Reg },
    /// SPEC: Part 6.1 — dst = lhs OR rhs (short-circuit in lowering).
    bool_or: struct { dst: Reg, lhs: Reg, rhs: Reg },
    /// SPEC: Part 6.1 — dst = NOT operand.
    bool_not: struct { dst: Reg, operand: Reg },
    /// SPEC: Part 2.2 — dst = -operand (arithmetic negation).
    negate: struct { dst: Reg, operand: Reg },

    // ── Register movement ─────────────────────────────────────────────────
    /// Copy src register value to dst.
    mov: struct { dst: Reg, src: Reg },

    // ── Control flow ──────────────────────────────────────────────────────
    /// SPEC: Part 6 — Define a jump target.
    label: struct { id: LabelId },
    /// SPEC: Part 6 — Unconditional jump.
    jump: struct { target: LabelId },
    /// SPEC: Part 6.1 — Conditional branch: if cond != 0 goto then_, else goto else_.
    branch: struct { cond: Reg, then_: LabelId, else_: LabelId },
    /// SPEC: Part 6.4 — Return from function, optionally with a value.
    ret: struct { value: ?Reg },

    // ── State access ──────────────────────────────────────────────────────
    /// SPEC: Part 5.2 — Read a state field. key is non-null for Map lookups.
    state_read: struct { dst: Reg, field_id: FieldId, key: ?Reg },
    /// SPEC: Part 5.2 — Write a state field. key is non-null for Map writes.
    state_write: struct { field_id: FieldId, key: ?Reg, value: Reg },
    /// SPEC: Part 5.2 — Delete a map entry: `remove mine.map[key]`.
    state_delete: struct { field_id: FieldId, key: Reg },

    // ── Linear asset operations ───────────────────────────────────────────
    /// SPEC: Part 8.4 — Transfer a linear asset to a recipient.
    asset_send: struct { asset: Reg, recipient: Reg },
    /// SPEC: Part 8.3 — Destroy a linear asset (burn).
    asset_burn: struct { asset: Reg },
    /// SPEC: Part 8.3 — Create new units of an asset.
    asset_mint: struct { dst: Reg, type_id: u32, amount: Reg },
    /// SPEC: Part 8.6 — Split an asset into two parts.
    asset_split: struct { dst: Reg, src: Reg, amount: Reg },
    /// SPEC: Part 8.6 — Merge two asset values into one.
    asset_merge: struct { dst: Reg, a: Reg, b: Reg },
    /// SPEC: Part 8.7 — Wrap native currency into a typed asset.
    asset_wrap: struct { dst: Reg, value: Reg, type_id: u32 },
    /// SPEC: Part 8.7 — Unwrap a typed asset to native currency.
    asset_unwrap: struct { dst: Reg, token: Reg },

    // ── Authority / access control ────────────────────────────────────────
    /// SPEC: Part 7.3 — Assert caller matches authority, revert if not.
    auth_check: struct { name_offset: u32, name_len: u32 },
    /// SPEC: Part 7.3 — Begin a guarded authority block.
    auth_gate_begin: struct { name_offset: u32, name_len: u32 },
    /// SPEC: Part 7.3 — End a guarded authority block.
    auth_gate_end,

    // ── Events ────────────────────────────────────────────────────────────
    /// SPEC: Part 5.9 — Emit a contract event with arguments in registers.
    emit_event: struct { event_id: EventId, args: []const Reg },

    // ── Error handling ────────────────────────────────────────────────────
    /// SPEC: Part 6.5 — Assert condition, revert with message if false.
    need: struct { cond: Reg, msg_offset: u32, msg_len: u32 },
    /// SPEC: Part 6.5 — Post-condition assertion.
    ensure: struct { cond: Reg, msg_offset: u32, msg_len: u32 },
    /// SPEC: Part 6.6 — Unconditional abort with message.
    panic: struct { msg_offset: u32, msg_len: u32 },
    /// SPEC: Part 11 — Revert with a typed error.
    throw_error: struct { error_id: ErrorId, args: []const Reg },
    /// SPEC: Part 11.5 — Begin exception handler scope.
    attempt_begin: struct { handler_label: LabelId },
    /// SPEC: Part 11.5 — End exception handler scope.
    attempt_end,

    // ── Builtins ──────────────────────────────────────────────────────────
    /// SPEC: Part 7.5 — Load the transaction caller address.
    get_caller: struct { dst: Reg },
    /// SPEC: Part 7.5 — Load the attached native currency value.
    get_value: struct { dst: Reg },
    /// SPEC: Part 14.3 — Load the current block number.
    get_block: struct { dst: Reg },
    /// SPEC: Part 14.3 — Load the current timestamp.
    get_timestamp: struct { dst: Reg },
    /// SPEC: Part 14.6 — Load remaining gas.
    get_gas: struct { dst: Reg },
    /// SPEC: Part 5.1 — Load this contract's own address.
    get_this: struct { dst: Reg },
    /// SPEC: Part 5.4 — Load the deployer address.
    get_deployer: struct { dst: Reg },
    /// SPEC: Part 7.5 — Load the zero address constant.
    get_zero_addr: struct { dst: Reg },

    // ── Cross-contract / scheduled ─────────────────────────────────────────
    /// SPEC: Part 10.2 — Schedule a deferred call.
    schedule_call: struct { delay: Reg, calldata: Reg, calldata_len: Reg },
    /// SPEC: Part 10.1 — Call another contract's action.
    call_external: struct { dst: Reg, target: Reg, selector: Selector, args: []const Reg },

    // ── VM-specific extended operations ───────────────────────────────────
    /// SPEC: Part 14.2 — Read an oracle price feed.
    oracle_read: struct { dst: Reg, feed_id: u32 },
    /// SPEC: Part 14.4 — Generate verifiable random number.
    vrf_random: struct { dst: Reg, seed: Reg },
    /// SPEC: Part 12.2 — Verify a ZK proof against a circuit.
    zk_verify: struct { proof: Reg, circuit_id: u32 },
    /// SPEC: Part 14.6 — Delegate gas payment to a sponsor.
    delegate_gas: struct { payer: Reg },

    // ── Native currency transfer ──────────────────────────────────────────
    /// SPEC: Part 5.5 — Transfer native currency to a recipient.
    pay: struct { recipient: Reg, amount: Reg },

    // ── Account lifecycle ─────────────────────────────────────────────────
    /// SPEC: Part 3.10 — Expand account storage.
    expand_account: struct { account: Reg, bytes: Reg },
    /// SPEC: Part 3.10 — Close an account, refunding remaining balance.
    close_account: struct { account: Reg, refund_to: Reg },
    /// SPEC: Part 8.4 — Freeze an account (prevent transfers).
    freeze_account: struct { account: Reg },
    /// SPEC: Part 8.4 — Unfreeze an account.
    unfreeze_account: struct { account: Reg },

    // ── Ownership ─────────────────────────────────────────────────────────
    /// SPEC: Part 4.4 — Transfer ownership of an account.
    transfer_ownership: struct { account: Reg, new_owner: Reg },

    // ── Collection membership ─────────────────────────────────────────────
    /// SPEC: Part 2.6 — dst = (collection has element).
    has_check: struct { dst: Reg, collection: Reg, element: Reg },

    // ── Function call (internal) ──────────────────────────────────────────
    /// Call an internal action/view/pure/helper by selector.
    call_internal: struct { dst: Reg, selector: Selector, args: []const Reg },

    // ── No-op placeholder for match arm bookkeeping ───────────────────────
    nop,
};

/// SPEC: All Parts — A single MIR instruction with its source span.
pub const MirInstr = struct {
    op: MirOp,
    /// Original source location for diagnostics and debug info.
    span: Span,
};

// ============================================================================
// Section 3 — MIR Module Structures
// ============================================================================

/// SPEC: Part 5.5 — The kind of a MIR function.
pub const FuncKind = enum {
    action,
    view,
    pure,
    setup,
    fallback,
    receive,
    guard,
    helper,
};

/// SPEC: Part 5 — A function parameter in MIR form.
pub const MirParam = struct {
    name: []const u8,
    type_: MirType,
    /// Original resolved type for ABI encoding decisions.
    resolved: ResolvedType,
};

/// SPEC: Part 5.2 — Descriptor for a contract state field.
pub const StateFieldDesc = struct {
    name: []const u8,
    field_id: FieldId,
    type_: MirType,
    resolved: ResolvedType,
    is_map: bool,
};

/// SPEC: Part 5.9 — Descriptor for a contract event.
pub const EventDesc = struct {
    name: []const u8,
    event_id: EventId,
    fields: []const EventFieldDesc,
};

/// SPEC: Part 5.9 — One field within an event descriptor.
pub const EventFieldDesc = struct {
    name: []const u8,
    type_: MirType,
    resolved: ResolvedType,
    indexed: bool,
};

/// SPEC: Part 5.10 — Descriptor for a contract error type.
pub const ErrorDesc = struct {
    name: []const u8,
    error_id: ErrorId,
    field_count: u32,
};

/// SPEC: Part 4 — Descriptor for a contract authority.
pub const AuthorityDesc = struct {
    name: []const u8,
    name_offset: u32,
    name_len: u32,
};

/// SPEC: Part 5 — A single lowered function.
pub const MirFunction = struct {
    name: []const u8,
    selector: Selector,
    kind: FuncKind,
    params: []const MirParam,
    return_type: ?MirType,
    body: []const MirInstr,
    max_regs: Reg,
};

/// SPEC: Part 5 — The complete lowered contract, ready for any backend.
pub const MirModule = struct {
    /// Contract name from the source.
    name: []const u8,
    /// All lowered functions (actions, views, pures, setup, etc.).
    functions: []const MirFunction,
    /// Interned constant data (string literals, authority names, etc.).
    data_section: []const u8,
    /// Contract state field descriptors in declaration order.
    state_fields: []const StateFieldDesc,
    /// Event descriptors.
    events: []const EventDesc,
    /// Error type descriptors.
    errors_: []const ErrorDesc,
    /// Authority descriptors.
    authorities: []const AuthorityDesc,
    /// Parent contract name if inheriting.
    inherits: ?[]const u8,
    /// Interface names this contract implements.
    implements: []const []const u8,
};

// ============================================================================
// Section 4 — Data Section Interning
// ============================================================================

/// SPEC: Part 2.3 — A reference to interned data in the data section.
pub const DataRef = struct {
    offset: u32,
    len: u32,
};

/// SPEC: Part 2.3 — Interns string constants into a linear byte buffer.
/// Returns (offset, length) pairs for referencing interned data.
const DataSection = struct {
    bytes: std.ArrayListUnmanaged(u8),
    /// Cache to avoid duplicate interning of the same string.
    cache: std.StringHashMapUnmanaged(u32),
    allocator: std.mem.Allocator,

    /// SPEC: Part 2.3 — Create an empty data section.
    fn init(allocator: std.mem.Allocator) DataSection {
        return .{
            .bytes = .{},
            .cache = .{},
            .allocator = allocator,
        };
    }

    /// SPEC: Part 2.3 — Release interning resources.
    fn deinit(self: *DataSection) void {
        self.bytes.deinit(self.allocator);
        self.cache.deinit(self.allocator);
    }

    /// SPEC: Part 2.3 — Intern a string, returning its (offset, length).
    /// Deduplicates identical strings.
    fn intern(self: *DataSection, data: []const u8) anyerror!DataRef {
        if (self.cache.get(data)) |cached_offset| {
            return .{ .offset = cached_offset, .len = @intCast(data.len) };
        }
        const offset: u32 = @intCast(self.bytes.items.len);
        try self.bytes.appendSlice(self.allocator, data);
        // Cache using the just-interned bytes (stable pointer).
        const interned_slice = self.bytes.items[offset..][0..data.len];
        try self.cache.put(self.allocator, interned_slice, offset);
        return .{ .offset = offset, .len = @intCast(data.len) };
    }

    /// SPEC: Part 2.3 — Produce a caller-owned copy of the data section.
    fn toOwnedSlice(self: *DataSection) anyerror![]const u8 {
        if (self.bytes.items.len == 0) return &[_]u8{};
        const result = try self.allocator.dupe(u8, self.bytes.items);
        return result;
    }
};

// ============================================================================
// Section 5 — MIR Lowerer
// ============================================================================

/// SPEC: All Parts — Lowers a checked Forge contract AST into a MirModule.
/// This is the single pass that every backend consumes instead of walking
/// the AST directly. New language features are implemented here once.
pub const MirLowerer = struct {
    allocator: std.mem.Allocator,
    resolver: *TypeResolver,
    diagnostics: *DiagnosticList,
    data: DataSection,

    /// Instruction buffer for the function currently being lowered.
    instrs: std.ArrayListUnmanaged(MirInstr),
    /// Completed functions.
    functions: std.ArrayListUnmanaged(MirFunction),

    /// Virtual register counter — monotonically increasing per function.
    next_reg: Reg,
    /// Label counter — monotonically increasing across all functions.
    next_label: LabelId,

    /// Maps local variable names to their assigned virtual register.
    local_regs: std.StringHashMapUnmanaged(Reg),

    /// State field ID assignment map (field name → FieldId).
    field_ids: std.StringHashMapUnmanaged(FieldId),
    next_field_id: FieldId,

    /// Event ID assignment map (event name → EventId).
    event_ids: std.StringHashMapUnmanaged(EventId),
    next_event_id: EventId,

    /// Error ID assignment map (error name → ErrorId).
    error_ids: std.StringHashMapUnmanaged(ErrorId),
    next_error_id: ErrorId,

    /// SPEC: All Parts — Create a new lowerer.
    pub fn init(
        allocator: std.mem.Allocator,
        resolver: *TypeResolver,
        diagnostics: *DiagnosticList,
    ) MirLowerer {
        return .{
            .allocator = allocator,
            .resolver = resolver,
            .diagnostics = diagnostics,
            .data = DataSection.init(allocator),
            .instrs = .{},
            .functions = .{},
            .next_reg = 0,
            .next_label = 0,
            .local_regs = .{},
            .field_ids = .{},
            .next_field_id = 0,
            .event_ids = .{},
            .next_event_id = 0,
            .error_ids = .{},
            .next_error_id = 0,
        };
    }

    /// SPEC: All Parts — Release all lowerer resources.
    pub fn deinit(self: *MirLowerer) void {
        self.data.deinit();
        self.instrs.deinit(self.allocator);
        self.functions.deinit(self.allocator);
        self.local_regs.deinit(self.allocator);
        self.field_ids.deinit(self.allocator);
        self.event_ids.deinit(self.allocator);
        self.error_ids.deinit(self.allocator);
    }

    // ── Register and label allocation ─────────────────────────────────────

    /// SPEC: Part 2 — Allocate a fresh virtual register.
    fn freshReg(self: *MirLowerer) Reg {
        const r = self.next_reg;
        self.next_reg += 1;
        return r;
    }

    /// SPEC: Part 6 — Allocate a fresh label ID.
    fn freshLabel(self: *MirLowerer) LabelId {
        const l = self.next_label;
        self.next_label += 1;
        return l;
    }

    /// SPEC: Part 5 — Reset per-function state for a new function body.
    fn resetFunctionState(self: *MirLowerer) void {
        self.next_reg = 0;
        self.local_regs.clearRetainingCapacity();
        self.instrs.clearRetainingCapacity();
    }

    /// SPEC: Part 5 — Emit a single MIR instruction into the current function.
    fn emit(self: *MirLowerer, op: MirOp, span: Span) anyerror!void {
        try self.instrs.append(self.allocator, .{ .op = op, .span = span });
    }

    /// SPEC: Part 5.2 — Get or assign a field ID for a state field name.
    fn getOrAssignFieldId(self: *MirLowerer, name: []const u8) anyerror!FieldId {
        const result = try self.field_ids.getOrPut(self.allocator, name);
        if (!result.found_existing) {
            result.value_ptr.* = self.next_field_id;
            self.next_field_id += 1;
        }
        return result.value_ptr.*;
    }

    /// SPEC: Part 5.9 — Get or assign an event ID.
    fn getOrAssignEventId(self: *MirLowerer, name: []const u8) anyerror!EventId {
        const result = try self.event_ids.getOrPut(self.allocator, name);
        if (!result.found_existing) {
            result.value_ptr.* = self.next_event_id;
            self.next_event_id += 1;
        }
        return result.value_ptr.*;
    }

    /// SPEC: Part 5.10 — Get or assign an error ID.
    fn getOrAssignErrorId(self: *MirLowerer, name: []const u8) anyerror!ErrorId {
        const result = try self.error_ids.getOrPut(self.allocator, name);
        if (!result.found_existing) {
            result.value_ptr.* = self.next_error_id;
            self.next_error_id += 1;
        }
        return result.value_ptr.*;
    }

    /// SPEC: Part 5 — Bind a local variable name to a virtual register.
    fn bindLocal(self: *MirLowerer, name: []const u8, reg: Reg) anyerror!void {
        try self.local_regs.put(self.allocator, name, reg);
    }

    /// SPEC: Part 5 — Look up the register for a local variable.
    fn lookupLocal(self: *const MirLowerer, name: []const u8) ?Reg {
        return self.local_regs.get(name);
    }

    /// SPEC: Part 5 — Snapshot the current instruction buffer as a completed function.
    fn finishFunction(
        self: *MirLowerer,
        name: []const u8,
        selector: Selector,
        kind: FuncKind,
        params: []const MirParam,
        return_type: ?MirType,
    ) anyerror!void {
        const body = try self.allocator.dupe(MirInstr, self.instrs.items);
        try self.functions.append(self.allocator, .{
            .name = name,
            .selector = selector,
            .kind = kind,
            .params = params,
            .return_type = return_type,
            .body = body,
            .max_regs = self.next_reg,
        });
    }

    // ── Expression lowering ───────────────────────────────────────────────

    /// SPEC: Part 2–8 — Lower an AST expression to MIR instructions.
    /// Returns the virtual register holding the result value.
    pub fn lowerExpr(self: *MirLowerer, expr: *const Expr) anyerror!Reg {
        const span = expr.span;
        switch (expr.kind) {
            // ── Literals ──────────────────────────────────────────────────
            .int_lit => |lit| {
                const dst = self.freshReg();
                const bytes = parseIntLitTo256(lit);
                try self.emit(.{ .const_i256 = .{ .dst = dst, .bytes = bytes } }, span);
                return dst;
            },
            .float_lit => |lit| {
                const dst = self.freshReg();
                // Scale fixed-point by 18 decimals (default).
                // The checker can refine this via type context for Fixed[N].
                const bytes = scaleFixedPointTo256(lit, 18);
                try self.emit(.{ .const_i256 = .{ .dst = dst, .bytes = bytes } }, span);
                return dst;
            },
            .bool_lit => |b| {
                const dst = self.freshReg();
                try self.emit(.{ .const_bool = .{ .dst = dst, .value = b } }, span);
                return dst;
            },
            .string_lit => |s| {
                const dst = self.freshReg();
                // Strip surrounding quotes.
                const content = if (s.len >= 2) s[1 .. s.len - 1] else s;
                const interned = try self.data.intern(content);
                try self.emit(.{ .const_data = .{
                    .dst = dst,
                    .offset = interned.offset,
                    .len = interned.len,
                } }, span);
                return dst;
            },
            .nothing => {
                const dst = self.freshReg();
                try self.emit(.{ .const_i256 = .{ .dst = dst, .bytes = [_]u8{0} ** 32 } }, span);
                return dst;
            },
            .something => |inner| {
                return try self.lowerExpr(inner);
            },

            // ── Identifiers ───────────────────────────────────────────────
            .identifier => |name| {
                // Check local variables first.
                if (self.lookupLocal(name)) |reg| {
                    return reg;
                }
                // Check if this is a state field: `mine.fieldName` is
                // resolved at field_access level, but bare identifiers
                // may also refer to state fields.
                if (self.field_ids.get(name)) |fid| {
                    const dst = self.freshReg();
                    try self.emit(.{ .state_read = .{
                        .dst = dst,
                        .field_id = fid,
                        .key = null,
                    } }, span);
                    return dst;
                }
                // Unresolved identifier — emit a zero placeholder.
                // The checker should have caught undefined names.
                const dst = self.freshReg();
                try self.emit(.{ .const_i256 = .{ .dst = dst, .bytes = [_]u8{0} ** 32 } }, span);
                return dst;
            },

            // ── Field access ──────────────────────────────────────────────
            .field_access => |fa| {
                // `mine.field` → state_read
                if (fa.object.kind == .identifier) {
                    const obj_name = fa.object.kind.identifier;
                    if (std.mem.eql(u8, obj_name, "mine")) {
                        const fid = try self.getOrAssignFieldId(fa.field);
                        const dst = self.freshReg();
                        try self.emit(.{ .state_read = .{
                            .dst = dst,
                            .field_id = fid,
                            .key = null,
                        } }, span);
                        return dst;
                    }
                }
                // General field access: evaluate object, return as-is.
                // Full struct field offset resolution happens in backends.
                return try self.lowerExpr(fa.object);
            },

            // ── Index access ──────────────────────────────────────────────
            .index_access => |ia| {
                // `mine.map[key]` → state_read with key register
                const key_reg = try self.lowerExpr(ia.index);
                var field_name: ?[]const u8 = null;
                if (ia.object.kind == .field_access) {
                    const outer = ia.object.kind.field_access;
                    if (outer.object.kind == .identifier and
                        std.mem.eql(u8, outer.object.kind.identifier, "mine"))
                    {
                        field_name = outer.field;
                    }
                } else if (ia.object.kind == .identifier) {
                    if (self.field_ids.get(ia.object.kind.identifier) != null) {
                        field_name = ia.object.kind.identifier;
                    }
                }
                if (field_name) |fname| {
                    const fid = try self.getOrAssignFieldId(fname);
                    const dst = self.freshReg();
                    try self.emit(.{ .state_read = .{
                        .dst = dst,
                        .field_id = fid,
                        .key = key_reg,
                    } }, span);
                    return dst;
                }
                // Fallback: evaluate object, discard, return zero.
                _ = try self.lowerExpr(ia.object);
                const dst = self.freshReg();
                try self.emit(.{ .const_i256 = .{ .dst = dst, .bytes = [_]u8{0} ** 32 } }, span);
                return dst;
            },

            // ── Binary operations ─────────────────────────────────────────
            .bin_op => |op| {
                return try self.lowerBinOp(op.op, op.left, op.right, span);
            },

            // ── Unary operations ──────────────────────────────────────────
            .unary_op => |op| {
                const operand = try self.lowerExpr(op.operand);
                const dst = self.freshReg();
                switch (op.op) {
                    .not_ => try self.emit(.{ .bool_not = .{ .dst = dst, .operand = operand } }, span),
                    .negate => try self.emit(.{ .negate = .{ .dst = dst, .operand = operand } }, span),
                }
                return dst;
            },

            // ── Calls ─────────────────────────────────────────────────────
            .call => |c| {
                return try self.lowerCall(c.callee, c.args, span);
            },

            // ── Builtins ──────────────────────────────────────────────────
            .builtin => |b| {
                const dst = self.freshReg();
                switch (b) {
                    .caller => try self.emit(.{ .get_caller = .{ .dst = dst } }, span),
                    .value => try self.emit(.{ .get_value = .{ .dst = dst } }, span),
                    .deployer => try self.emit(.{ .get_deployer = .{ .dst = dst } }, span),
                    .this_address => try self.emit(.{ .get_this = .{ .dst = dst } }, span),
                    .zero_address => try self.emit(.{ .get_zero_addr = .{ .dst = dst } }, span),
                    .now => try self.emit(.{ .get_timestamp = .{ .dst = dst } }, span),
                    .current_block => try self.emit(.{ .get_block = .{ .dst = dst } }, span),
                    .gas_remaining => try self.emit(.{ .get_gas = .{ .dst = dst } }, span),
                }
                return dst;
            },

            // ── Type cast ─────────────────────────────────────────────────
            .cast => |c| {
                // Most casts are no-ops at MIR level. The backend handles
                // width masking (e.g. address → 160-bit mask on EVM).
                return try self.lowerExpr(c.expr);
            },

            // ── Result propagation ────────────────────────────────────────
            .try_propagate => |inner| {
                return try self.lowerExpr(inner);
            },

            // ── Struct literal ─────────────────────────────────────────────
            .struct_lit => |sl| {
                // Lower each field value; return the last register.
                // Full struct packing is backend-specific.
                var last_reg: Reg = self.freshReg();
                try self.emit(.{ .const_i256 = .{
                    .dst = last_reg,
                    .bytes = [_]u8{0} ** 32,
                } }, span);
                for (sl.fields) |fi| {
                    last_reg = try self.lowerExpr(fi.value);
                }
                return last_reg;
            },

            // ── Tuple literal ──────────────────────────────────────────────
            .tuple_lit => |elems| {
                var last_reg: Reg = self.freshReg();
                try self.emit(.{ .const_i256 = .{
                    .dst = last_reg,
                    .bytes = [_]u8{0} ** 32,
                } }, span);
                for (elems) |elem| {
                    last_reg = try self.lowerExpr(elem);
                }
                return last_reg;
            },

            // ── Inline conditional ─────────────────────────────────────────
            .inline_when => |iw| {
                const cond = try self.lowerExpr(iw.cond);
                const then_label = self.freshLabel();
                const else_label = self.freshLabel();
                const end_label = self.freshLabel();
                const result = self.freshReg();

                try self.emit(.{ .branch = .{
                    .cond = cond,
                    .then_ = then_label,
                    .else_ = else_label,
                } }, span);
                try self.emit(.{ .label = .{ .id = then_label } }, span);
                const then_val = try self.lowerExpr(iw.then_);
                try self.emit(.{ .mov = .{ .dst = result, .src = then_val } }, span);
                try self.emit(.{ .jump = .{ .target = end_label } }, span);
                try self.emit(.{ .label = .{ .id = else_label } }, span);
                const else_val = try self.lowerExpr(iw.else_);
                try self.emit(.{ .mov = .{ .dst = result, .src = else_val } }, span);
                try self.emit(.{ .label = .{ .id = end_label } }, span);
                return result;
            },

            // ── Match expression ───────────────────────────────────────────
            .match_expr => |me| {
                // Simplified: evaluate subject, return it.
                // Full match lowering done in lowerStmt for match statement.
                return try self.lowerExpr(me.subject);
            },

            // ── Asset operations ───────────────────────────────────────────
            .asset_split => |as_| {
                const src = try self.lowerExpr(as_.asset);
                const amount = try self.lowerExpr(as_.amount);
                const dst = self.freshReg();
                try self.emit(.{ .asset_split = .{
                    .dst = dst,
                    .src = src,
                    .amount = amount,
                } }, span);
                return dst;
            },
            .asset_wrap => |aw| {
                const val = try self.lowerExpr(aw.value);
                const dst = self.freshReg();
                try self.emit(.{ .asset_wrap = .{
                    .dst = dst,
                    .value = val,
                    .type_id = 0,
                } }, span);
                return dst;
            },
            .asset_unwrap => |au| {
                const tok = try self.lowerExpr(au.token);
                const dst = self.freshReg();
                try self.emit(.{ .asset_unwrap = .{
                    .dst = dst,
                    .token = tok,
                } }, span);
                return dst;
            },
        }
    }

    // ── Binary operation lowering ──────────────────────────────────────────

    /// SPEC: Part 2.2, 6.1 — Lower a binary operation to MIR.
    fn lowerBinOp(
        self: *MirLowerer,
        op: BinOp,
        left: *Expr,
        right: *Expr,
        span: Span,
    ) anyerror!Reg {
        // Short-circuit AND/OR require control flow.
        switch (op) {
            .and_ => return try self.lowerShortCircuitAnd(left, right, span),
            .or_ => return try self.lowerShortCircuitOr(left, right, span),
            else => {},
        }

        const lhs = try self.lowerExpr(left);
        const rhs = try self.lowerExpr(right);
        const dst = self.freshReg();

        switch (op) {
            .plus, .duration_add => try self.emit(.{ .add = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
            .minus, .duration_sub => try self.emit(.{ .sub = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
            .times => try self.emit(.{ .mul = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
            .divided_by => try self.emit(.{ .div = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
            .mod => try self.emit(.{ .mod = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
            .equals => try self.emit(.{ .eq = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
            .not_equals => try self.emit(.{ .ne = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
            .less => try self.emit(.{ .lt = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
            .greater => try self.emit(.{ .gt = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
            .less_eq => try self.emit(.{ .le = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
            .greater_eq => try self.emit(.{ .ge = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
            .has => try self.emit(.{ .has_check = .{ .dst = dst, .collection = lhs, .element = rhs } }, span),
            .and_, .or_ => unreachable, // Handled above
        }
        return dst;
    }

    /// SPEC: Part 6.1 — Short-circuit AND: if !left then false, else right.
    fn lowerShortCircuitAnd(
        self: *MirLowerer,
        left: *Expr,
        right: *Expr,
        span: Span,
    ) anyerror!Reg {
        const result = self.freshReg();
        const lhs = try self.lowerExpr(left);
        const eval_right = self.freshLabel();
        const done = self.freshLabel();

        // If left is true, evaluate right; otherwise result is false.
        try self.emit(.{ .branch = .{
            .cond = lhs,
            .then_ = eval_right,
            .else_ = done,
        } }, span);

        // Short-circuit false path: result = false
        try self.emit(.{ .const_bool = .{ .dst = result, .value = false } }, span);
        try self.emit(.{ .jump = .{ .target = done } }, span);

        // Evaluate right path
        try self.emit(.{ .label = .{ .id = eval_right } }, span);
        const rhs = try self.lowerExpr(right);
        try self.emit(.{ .mov = .{ .dst = result, .src = rhs } }, span);

        try self.emit(.{ .label = .{ .id = done } }, span);
        return result;
    }

    /// SPEC: Part 6.1 — Short-circuit OR: if left then true, else right.
    fn lowerShortCircuitOr(
        self: *MirLowerer,
        left: *Expr,
        right: *Expr,
        span: Span,
    ) anyerror!Reg {
        const result = self.freshReg();
        const lhs = try self.lowerExpr(left);
        const eval_right = self.freshLabel();
        const done = self.freshLabel();

        // If left is true, skip right; otherwise evaluate right.
        try self.emit(.{ .branch = .{
            .cond = lhs,
            .then_ = done,
            .else_ = eval_right,
        } }, span);

        // Short-circuit true path: result = true
        try self.emit(.{ .const_bool = .{ .dst = result, .value = true } }, span);
        try self.emit(.{ .jump = .{ .target = done } }, span);

        // Evaluate right path
        try self.emit(.{ .label = .{ .id = eval_right } }, span);
        const rhs = try self.lowerExpr(right);
        try self.emit(.{ .mov = .{ .dst = result, .src = rhs } }, span);

        try self.emit(.{ .label = .{ .id = done } }, span);
        return result;
    }

    // ── Call lowering ─────────────────────────────────────────────────────

    /// SPEC: Part 5.5 — Lower a function call to MIR.
    fn lowerCall(
        self: *MirLowerer,
        callee: *const Expr,
        args: []const ast.Argument,
        span: Span,
    ) anyerror!Reg {
        // Evaluate all arguments into registers.
        const arg_regs = try self.allocator.alloc(Reg, args.len);
        defer self.allocator.free(arg_regs);
        for (args, 0..) |arg, i| {
            arg_regs[i] = try self.lowerExpr(arg.value);
        }

        const owned_args = try self.allocator.dupe(Reg, arg_regs);
        const dst = self.freshReg();

        // Internal calls use a selector derived from the callee name.
        if (callee.kind == .identifier) {
            const sel = fnvHash32(callee.kind.identifier);
            try self.emit(.{ .call_internal = .{
                .dst = dst,
                .selector = sel,
                .args = owned_args,
            } }, span);
            return dst;
        }

        // External calls (callee.method) use call_external.
        if (callee.kind == .field_access) {
            const fa = callee.kind.field_access;
            const target = try self.lowerExpr(fa.object);
            const sel = fnvHash32(fa.field);
            try self.emit(.{ .call_external = .{
                .dst = dst,
                .target = target,
                .selector = sel,
                .args = owned_args,
            } }, span);
            return dst;
        }

        // Fallback: evaluate callee expression, emit internal call.
        _ = try self.lowerExpr(callee);
        try self.emit(.{ .const_i256 = .{ .dst = dst, .bytes = [_]u8{0} ** 32 } }, span);
        return dst;
    }

    // ── Statement lowering ────────────────────────────────────────────────

    /// SPEC: Part 5–6 — Lower one AST statement to MIR instructions.
    pub fn lowerStmt(self: *MirLowerer, stmt: *const Stmt) anyerror!void {
        const span = stmt.span;
        switch (stmt.kind) {
            // ── let binding ───────────────────────────────────────────────
            .let_bind => |lb| {
                const val = try self.lowerExpr(lb.init);
                const dst = self.freshReg();
                try self.emit(.{ .mov = .{ .dst = dst, .src = val } }, span);
                try self.bindLocal(lb.name, dst);
            },

            // ── assignment ────────────────────────────────────────────────
            .assign => |asg| {
                const val = try self.lowerExpr(asg.value);
                try self.lowerAssignTarget(asg.target, val, span);
            },

            // ── augmented assignment ──────────────────────────────────────
            .aug_assign => |aug| {
                const rhs = try self.lowerExpr(aug.value);
                const lhs = try self.lowerExpr(aug.target);
                const dst = self.freshReg();
                switch (aug.op) {
                    .add => try self.emit(.{ .add = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
                    .sub => try self.emit(.{ .sub = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
                    .mul => try self.emit(.{ .mul = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
                    .div => try self.emit(.{ .div = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
                    .mod => try self.emit(.{ .mod = .{ .dst = dst, .lhs = lhs, .rhs = rhs } }, span),
                }
                try self.lowerAssignTarget(aug.target, dst, span);
            },

            // ── when/otherwise ────────────────────────────────────────────
            .when => |wh| {
                try self.lowerWhen(&wh, span);
            },

            // ── match ─────────────────────────────────────────────────────
            .match => |m| {
                const subject = try self.lowerExpr(m.subject);
                const end_label = self.freshLabel();
                for (m.arms) |arm| {
                    // Simplified: each arm evaluates its body.
                    _ = subject;
                    for (arm.body) |body_stmt| {
                        try self.lowerStmt(&body_stmt);
                    }
                    try self.emit(.{ .jump = .{ .target = end_label } }, span);
                }
                try self.emit(.{ .label = .{ .id = end_label } }, span);
            },

            // ── each loop ─────────────────────────────────────────────────
            .each => |e| {
                _ = try self.lowerExpr(e.collection);
                // Loop body lowering (simplified — backends handle iteration).
                const loop_top = self.freshLabel();
                const loop_end = self.freshLabel();
                try self.emit(.{ .label = .{ .id = loop_top } }, span);
                for (e.body) |body_stmt| {
                    try self.lowerStmt(&body_stmt);
                }
                try self.emit(.{ .jump = .{ .target = loop_top } }, span);
                try self.emit(.{ .label = .{ .id = loop_end } }, span);
            },

            // ── repeat N times ────────────────────────────────────────────
            .repeat => |r| {
                const count = try self.lowerExpr(r.count);
                _ = count;
                const loop_top = self.freshLabel();
                const loop_end = self.freshLabel();
                try self.emit(.{ .label = .{ .id = loop_top } }, span);
                for (r.body) |body_stmt| {
                    try self.lowerStmt(&body_stmt);
                }
                try self.emit(.{ .jump = .{ .target = loop_top } }, span);
                try self.emit(.{ .label = .{ .id = loop_end } }, span);
            },

            // ── while ─────────────────────────────────────────────────────
            .while_ => |wl| {
                const loop_top = self.freshLabel();
                const loop_body = self.freshLabel();
                const loop_end = self.freshLabel();
                try self.emit(.{ .label = .{ .id = loop_top } }, span);
                const cond = try self.lowerExpr(wl.cond);
                try self.emit(.{ .branch = .{
                    .cond = cond,
                    .then_ = loop_body,
                    .else_ = loop_end,
                } }, span);
                try self.emit(.{ .label = .{ .id = loop_body } }, span);
                for (wl.body) |body_stmt| {
                    try self.lowerStmt(&body_stmt);
                }
                try self.emit(.{ .jump = .{ .target = loop_top } }, span);
                try self.emit(.{ .label = .{ .id = loop_end } }, span);
            },

            // ── need ──────────────────────────────────────────────────────
            .need => |n| {
                const cond = try self.lowerExpr(n.cond);
                const msg = try self.lowerRevertMsg(n.else_);
                try self.emit(.{ .need = .{
                    .cond = cond,
                    .msg_offset = msg.offset,
                    .msg_len = msg.len,
                } }, span);
            },

            // ── ensure ────────────────────────────────────────────────────
            .ensure => |e| {
                const cond = try self.lowerExpr(e.cond);
                const msg = try self.lowerRevertMsg(e.else_);
                try self.emit(.{ .ensure = .{
                    .cond = cond,
                    .msg_offset = msg.offset,
                    .msg_len = msg.len,
                } }, span);
            },

            // ── panic ─────────────────────────────────────────────────────
            .panic => |p| {
                const content = if (p.message.len >= 2)
                    p.message[1 .. p.message.len - 1]
                else
                    p.message;
                const interned = try self.data.intern(content);
                try self.emit(.{ .panic = .{
                    .msg_offset = interned.offset,
                    .msg_len = interned.len,
                } }, span);
            },

            // ── give back ─────────────────────────────────────────────────
            .give_back => |expr| {
                const val = try self.lowerExpr(expr);
                try self.emit(.{ .ret = .{ .value = val } }, span);
            },

            // ── stop (break) ──────────────────────────────────────────────
            .stop => {
                // Backends should patch to enclosing loop end.
                try self.emit(.{ .nop = {} }, span);
            },

            // ── skip (continue) ───────────────────────────────────────────
            .skip => {
                try self.emit(.{ .nop = {} }, span);
            },

            // ── tell (event) ──────────────────────────────────────────────
            .tell => |t| {
                const eid = try self.getOrAssignEventId(t.event_name);
                const arg_regs = try self.allocator.alloc(Reg, t.args.len);
                defer self.allocator.free(arg_regs);
                for (t.args, 0..) |arg, i| {
                    arg_regs[i] = try self.lowerExpr(arg.value);
                }
                const owned = try self.allocator.dupe(Reg, arg_regs);
                try self.emit(.{ .emit_event = .{
                    .event_id = eid,
                    .args = owned,
                } }, span);
            },

            // ── throw ─────────────────────────────────────────────────────
            .throw => |th| {
                const eid = try self.getOrAssignErrorId(th.error_call.error_type);
                const arg_regs = try self.allocator.alloc(Reg, th.error_call.args.len);
                defer self.allocator.free(arg_regs);
                for (th.error_call.args, 0..) |arg, i| {
                    arg_regs[i] = try self.lowerExpr(arg.value);
                }
                const owned = try self.allocator.dupe(Reg, arg_regs);
                try self.emit(.{ .throw_error = .{
                    .error_id = eid,
                    .args = owned,
                } }, span);
            },

            // ── attempt ───────────────────────────────────────────────────
            .attempt => |at| {
                const handler = self.freshLabel();
                const end = self.freshLabel();
                try self.emit(.{ .attempt_begin = .{ .handler_label = handler } }, span);
                for (at.body) |body_stmt| {
                    try self.lowerStmt(&body_stmt);
                }
                try self.emit(.{ .attempt_end = {} }, span);
                try self.emit(.{ .jump = .{ .target = end } }, span);
                try self.emit(.{ .label = .{ .id = handler } }, span);
                for (at.on_error) |clause| {
                    for (clause.body) |err_stmt| {
                        try self.lowerStmt(&err_stmt);
                    }
                }
                if (at.always_body) |always| {
                    for (always) |always_stmt| {
                        try self.lowerStmt(&always_stmt);
                    }
                }
                try self.emit(.{ .label = .{ .id = end } }, span);
            },

            // ── verify (ZK) ──────────────────────────────────────────────
            .verify => |v| {
                const proof = try self.lowerExpr(v.proof);
                _ = try self.lowerExpr(v.commitment);
                try self.emit(.{ .zk_verify = .{
                    .proof = proof,
                    .circuit_id = 0,
                } }, span);
            },

            // ── call statement ────────────────────────────────────────────
            .call_stmt => |expr| {
                _ = try self.lowerExpr(expr);
            },

            // ── remove ────────────────────────────────────────────────────
            .remove => |expr| {
                if (expr.kind == .index_access) {
                    const ia = expr.kind.index_access;
                    const key = try self.lowerExpr(ia.index);
                    var fname: ?[]const u8 = null;
                    if (ia.object.kind == .field_access) {
                        const fa = ia.object.kind.field_access;
                        if (fa.object.kind == .identifier and
                            std.mem.eql(u8, fa.object.kind.identifier, "mine"))
                        {
                            fname = fa.field;
                        }
                    }
                    if (fname) |name| {
                        const fid = try self.getOrAssignFieldId(name);
                        try self.emit(.{ .state_delete = .{
                            .field_id = fid,
                            .key = key,
                        } }, span);
                        return;
                    }
                }
                _ = try self.lowerExpr(expr);
            },

            // ── pay ───────────────────────────────────────────────────────
            .pay => |p| {
                const recipient = try self.lowerExpr(p.recipient);
                const amount = try self.lowerExpr(p.amount);
                try self.emit(.{ .pay = .{
                    .recipient = recipient,
                    .amount = amount,
                } }, span);
            },

            // ── send ──────────────────────────────────────────────────────
            .send => |s| {
                const asset = try self.lowerExpr(s.asset);
                const recipient = try self.lowerExpr(s.recipient);
                try self.emit(.{ .asset_send = .{
                    .asset = asset,
                    .recipient = recipient,
                } }, span);
            },

            // ── move ──────────────────────────────────────────────────────
            .move_asset => |mv| {
                const val = try self.lowerExpr(mv.asset);
                try self.lowerAssignTarget(mv.dest, val, span);
            },

            // ── expand ────────────────────────────────────────────────────
            .expand => |exp| {
                const acct = try self.lowerExpr(exp.account);
                const bytes = try self.lowerExpr(exp.bytes);
                try self.emit(.{ .expand_account = .{
                    .account = acct,
                    .bytes = bytes,
                } }, span);
            },

            // ── close ─────────────────────────────────────────────────────
            .close => |cl| {
                const acct = try self.lowerExpr(cl.account);
                const refund = try self.lowerExpr(cl.refund_to);
                try self.emit(.{ .close_account = .{
                    .account = acct,
                    .refund_to = refund,
                } }, span);
            },

            // ── freeze ────────────────────────────────────────────────────
            .freeze => |fr| {
                const acct = try self.lowerExpr(fr.account);
                try self.emit(.{ .freeze_account = .{ .account = acct } }, span);
            },

            // ── unfreeze ──────────────────────────────────────────────────
            .unfreeze => |uf| {
                const acct = try self.lowerExpr(uf.account);
                try self.emit(.{ .unfreeze_account = .{ .account = acct } }, span);
            },

            // ── schedule ──────────────────────────────────────────────────
            .schedule => |sch| {
                const delay = try self.lowerExpr(sch.after);
                const calldata = try self.lowerExpr(sch.call);
                try self.emit(.{ .schedule_call = .{
                    .delay = delay,
                    .calldata = calldata,
                    .calldata_len = 0,
                } }, span);
            },

            // ── guard_apply ───────────────────────────────────────────────
            .guard_apply => |name| {
                const interned = try self.data.intern(name);
                try self.emit(.{ .auth_check = .{
                    .name_offset = interned.offset,
                    .name_len = interned.len,
                } }, span);
            },

            // ── only ──────────────────────────────────────────────────────
            .only => |o| {
                const auth_name: []const u8 = switch (o.requirement) {
                    .authority => |a| a,
                    .either => |e| e.left,
                    .any_signer => |a| a,
                    .address_list => "address_list",
                };
                const interned = try self.data.intern(auth_name);
                try self.emit(.{ .auth_gate_begin = .{
                    .name_offset = interned.offset,
                    .name_len = interned.len,
                } }, span);
                for (o.body) |body_stmt| {
                    try self.lowerStmt(&body_stmt);
                }
                try self.emit(.{ .auth_gate_end = {} }, span);
            },

            // ── transfer_ownership ────────────────────────────────────────
            .transfer_ownership => |to| {
                const acct = try self.lowerExpr(to.account);
                const new_owner = try self.lowerExpr(to.new_owner);
                try self.emit(.{ .transfer_ownership = .{
                    .account = acct,
                    .new_owner = new_owner,
                } }, span);
            },
        }
    }

    // ── Assignment target lowering ────────────────────────────────────────

    /// SPEC: Part 5.2 — Lower the target of an assignment or aug_assign.
    fn lowerAssignTarget(
        self: *MirLowerer,
        target: *const Expr,
        value: Reg,
        span: Span,
    ) anyerror!void {
        switch (target.kind) {
            .identifier => |name| {
                // Local or state field.
                if (self.lookupLocal(name)) |_| {
                    try self.bindLocal(name, value);
                } else if (self.field_ids.get(name)) |fid| {
                    try self.emit(.{ .state_write = .{
                        .field_id = fid,
                        .key = null,
                        .value = value,
                    } }, span);
                } else {
                    // New local.
                    try self.bindLocal(name, value);
                }
            },
            .field_access => |fa| {
                if (fa.object.kind == .identifier and
                    std.mem.eql(u8, fa.object.kind.identifier, "mine"))
                {
                    const fid = try self.getOrAssignFieldId(fa.field);
                    try self.emit(.{ .state_write = .{
                        .field_id = fid,
                        .key = null,
                        .value = value,
                    } }, span);
                }
            },
            .index_access => |ia| {
                const key = try self.lowerExpr(ia.index);
                var fname: ?[]const u8 = null;
                if (ia.object.kind == .field_access) {
                    const outer = ia.object.kind.field_access;
                    if (outer.object.kind == .identifier and
                        std.mem.eql(u8, outer.object.kind.identifier, "mine"))
                    {
                        fname = outer.field;
                    }
                }
                if (fname) |name| {
                    const fid = try self.getOrAssignFieldId(name);
                    try self.emit(.{ .state_write = .{
                        .field_id = fid,
                        .key = key,
                        .value = value,
                    } }, span);
                }
            },
            else => {},
        }
    }

    // ── When/otherwise lowering ───────────────────────────────────────────

    /// SPEC: Part 6.1 — Lower when/otherwise chains.
    fn lowerWhen(self: *MirLowerer, wh: *const ast.WhenStmt, span: Span) anyerror!void {
        const end_label = self.freshLabel();

        const cond = try self.lowerExpr(wh.cond);
        const then_label = self.freshLabel();
        const else_label = self.freshLabel();

        try self.emit(.{ .branch = .{
            .cond = cond,
            .then_ = then_label,
            .else_ = else_label,
        } }, span);

        try self.emit(.{ .label = .{ .id = then_label } }, span);
        for (wh.then_body) |s| {
            try self.lowerStmt(&s);
        }
        try self.emit(.{ .jump = .{ .target = end_label } }, span);

        try self.emit(.{ .label = .{ .id = else_label } }, span);
        for (wh.else_ifs) |elif| {
            const elif_cond = try self.lowerExpr(elif.cond);
            const elif_then = self.freshLabel();
            const elif_else = self.freshLabel();
            try self.emit(.{ .branch = .{
                .cond = elif_cond,
                .then_ = elif_then,
                .else_ = elif_else,
            } }, span);
            try self.emit(.{ .label = .{ .id = elif_then } }, span);
            for (elif.body) |s| {
                try self.lowerStmt(&s);
            }
            try self.emit(.{ .jump = .{ .target = end_label } }, span);
            try self.emit(.{ .label = .{ .id = elif_else } }, span);
        }
        if (wh.else_body) |else_body| {
            for (else_body) |s| {
                try self.lowerStmt(&s);
            }
        }
        try self.emit(.{ .label = .{ .id = end_label } }, span);
    }

    // ── Revert message helper ─────────────────────────────────────────────

    /// SPEC: Part 6.5 — Extract a revert message from a NeedStmt's else clause.
    fn lowerRevertMsg(self: *MirLowerer, msg: ast.NeedElse) anyerror!DataRef {
        switch (msg) {
            .string_msg => |s| {
                const content = if (s.len >= 2) s[1 .. s.len - 1] else s;
                return try self.data.intern(content);
            },
            .typed_error => |ec| {
                return try self.data.intern(ec.error_type);
            },
        }
    }

    // ── Contract-level lowering ───────────────────────────────────────────

    /// SPEC: Part 5 — Lower an entire contract AST into a MirModule.
    /// This is the top-level entry point that replaces direct AST walking
    /// in all codegen backends.
    pub fn lowerContract(
        self: *MirLowerer,
        contract: *const ContractDef,
        checked: *const CheckedContract,
    ) anyerror!MirModule {
        _ = checked;

        // Pre-register all state field IDs in declaration order.
        for (contract.state) |sf| {
            _ = try self.getOrAssignFieldId(sf.name);
        }

        // Pre-register all event IDs.
        for (contract.events) |ev| {
            _ = try self.getOrAssignEventId(ev.name);
        }

        // Pre-register all error IDs.
        for (contract.errors_) |er| {
            _ = try self.getOrAssignErrorId(er.name);
        }

        // ── Lower setup (constructor) ─────────────────────────────────────
        if (contract.setup) |setup| {
            try self.lowerFuncBody(
                "__setup__",
                .setup,
                setup.params,
                null,
                setup.body,
            );
        }

        // ── Lower actions ─────────────────────────────────────────────────
        for (contract.actions) |action| {
            const ret_type: ?MirType = if (action.return_type) |rt|
                MirType.fromResolved(self.resolver.resolve(rt) catch .void_)
            else
                null;
            try self.lowerFuncBody(
                action.name,
                .action,
                action.params,
                ret_type,
                action.body,
            );
        }

        // ── Lower views ───────────────────────────────────────────────────
        for (contract.views) |view| {
            const ret_type: ?MirType = if (view.return_type) |rt|
                MirType.fromResolved(self.resolver.resolve(rt) catch .void_)
            else
                null;
            try self.lowerFuncBody(
                view.name,
                .view,
                view.params,
                ret_type,
                view.body,
            );
        }

        // ── Lower pures ──────────────────────────────────────────────────
        for (contract.pures) |pure| {
            const ret_type: ?MirType = if (pure.return_type) |rt|
                MirType.fromResolved(self.resolver.resolve(rt) catch .void_)
            else
                null;
            try self.lowerFuncBody(
                pure.name,
                .pure,
                pure.params,
                ret_type,
                pure.body,
            );
        }

        // ── Lower helpers ─────────────────────────────────────────────────
        for (contract.helpers) |helper| {
            const ret_type: ?MirType = if (helper.return_type) |rt|
                MirType.fromResolved(self.resolver.resolve(rt) catch .void_)
            else
                null;
            try self.lowerFuncBody(
                helper.name,
                .helper,
                helper.params,
                ret_type,
                helper.body,
            );
        }

        // ── Lower fallback ────────────────────────────────────────────────
        if (contract.fallback) |fb| {
            try self.lowerFuncBody(
                "__fallback__",
                .fallback,
                fb.params,
                null,
                fb.body,
            );
        }

        // ── Lower receive ─────────────────────────────────────────────────
        if (contract.receive_) |recv| {
            try self.lowerFuncBody(
                "__receive__",
                .receive,
                recv.params,
                null,
                recv.body,
            );
        }

        // ── Build state field descriptors ─────────────────────────────────
        const state_fields = try self.allocator.alloc(StateFieldDesc, contract.state.len);
        for (contract.state, 0..) |sf, i| {
            const rt = self.resolver.resolve(sf.type_) catch .void_;
            const is_map = switch (rt) {
                .map, .enum_map => true,
                else => false,
            };
            state_fields[i] = .{
                .name = sf.name,
                .field_id = self.field_ids.get(sf.name) orelse @intCast(i),
                .type_ = MirType.fromResolved(rt),
                .resolved = rt,
                .is_map = is_map,
            };
        }

        // ── Build event descriptors ───────────────────────────────────────
        const events = try self.allocator.alloc(EventDesc, contract.events.len);
        for (contract.events, 0..) |ev, i| {
            const fields = try self.allocator.alloc(EventFieldDesc, ev.fields.len);
            for (ev.fields, 0..) |f, j| {
                const rt = self.resolver.resolve(f.type_) catch .void_;
                fields[j] = .{
                    .name = f.name,
                    .type_ = MirType.fromResolved(rt),
                    .resolved = rt,
                    .indexed = f.indexed,
                };
            }
            events[i] = .{
                .name = ev.name,
                .event_id = self.event_ids.get(ev.name) orelse @intCast(i),
                .fields = fields,
            };
        }

        // ── Build error descriptors ───────────────────────────────────────
        const errs = try self.allocator.alloc(ErrorDesc, contract.errors_.len);
        for (contract.errors_, 0..) |er, i| {
            errs[i] = .{
                .name = er.name,
                .error_id = self.error_ids.get(er.name) orelse @intCast(i),
                .field_count = @intCast(er.fields.len),
            };
        }

        // ── Build authority descriptors ───────────────────────────────────
        const auths = try self.allocator.alloc(AuthorityDesc, contract.authorities.len);
        for (contract.authorities, 0..) |auth, i| {
            const interned = try self.data.intern(auth.name);
            auths[i] = .{
                .name = auth.name,
                .name_offset = interned.offset,
                .name_len = interned.len,
            };
        }

        return MirModule{
            .name = contract.name,
            .functions = try self.allocator.dupe(MirFunction, self.functions.items),
            .data_section = try self.data.toOwnedSlice(),
            .state_fields = state_fields,
            .events = events,
            .errors_ = errs,
            .authorities = auths,
            .inherits = contract.inherits,
            .implements = contract.implements,
        };
    }

    // ── Function body lowering ────────────────────────────────────────────

    /// SPEC: Part 5 — Lower a single function body (action/view/pure/setup/etc.)
    fn lowerFuncBody(
        self: *MirLowerer,
        name: []const u8,
        kind: FuncKind,
        params: []const ast.Param,
        return_type: ?MirType,
        body: []const Stmt,
    ) anyerror!void {
        self.resetFunctionState();

        // Allocate registers for parameters.
        const mir_params = try self.allocator.alloc(MirParam, params.len);
        for (params, 0..) |p, i| {
            const rt = self.resolver.resolve(p.declared_type) catch .void_;
            const reg = self.freshReg();
            try self.bindLocal(p.name, reg);
            mir_params[i] = .{
                .name = p.name,
                .type_ = MirType.fromResolved(rt),
                .resolved = rt,
            };
        }

        // Lower body statements.
        for (body) |stmt| {
            try self.lowerStmt(&stmt);
        }

        // Emit a trailing return if not already present.
        const needs_ret = self.instrs.items.len == 0 or
            switch (self.instrs.items[self.instrs.items.len - 1].op) {
            .ret => false,
            else => true,
        };
        if (needs_ret) {
            try self.emit(.{ .ret = .{ .value = null } }, .{ .line = 0, .col = 0, .len = 0 });
        }

        const selector = fnvHash32(name);
        try self.finishFunction(name, selector, kind, mir_params, return_type);
    }
};

// ============================================================================
// Section 6 — Literal Parsing Helpers
// ============================================================================

/// SPEC: Part 2.1 — Parse an integer literal string (decimal or 0x hex,
/// with _ separators) into a 32-byte big-endian u256.
fn parseIntLitTo256(lit: []const u8) [32]u8 {
    var clean_buf: [128]u8 = undefined;
    var clean_len: usize = 0;
    for (lit) |c| {
        if (c != '_') {
            if (clean_len >= clean_buf.len) break;
            clean_buf[clean_len] = c;
            clean_len += 1;
        }
    }
    const clean = clean_buf[0..clean_len];
    if (clean.len >= 2 and clean[0] == '0' and (clean[1] == 'x' or clean[1] == 'X')) {
        return parseHexTo256(clean[2..]);
    }
    return parseDecimalTo256(clean);
}

/// SPEC: Part 2.1 — Parse a decimal string into 32-byte big-endian.
fn parseDecimalTo256(digits: []const u8) [32]u8 {
    // Manual base-10 → base-256 conversion using schoolbook multiply.
    var result: [32]u8 = [_]u8{0} ** 32;
    for (digits) |d| {
        if (d < '0' or d > '9') continue;
        // result = result * 10 + digit
        var carry: u16 = d - '0';
        var i: usize = 32;
        while (i > 0) {
            i -= 1;
            const prod: u16 = @as(u16, result[i]) * 10 + carry;
            result[i] = @intCast(prod & 0xFF);
            carry = prod >> 8;
        }
    }
    return result;
}

/// SPEC: Part 2.1 — Parse a hex string into 32-byte big-endian.
fn parseHexTo256(hex: []const u8) [32]u8 {
    var result: [32]u8 = [_]u8{0} ** 32;
    var nibbles_written: usize = 0;
    // Write nibbles from the end, right-aligned.
    var i: usize = hex.len;
    while (i > 0 and nibbles_written < 64) {
        i -= 1;
        const nibble = hexVal(hex[i]);
        const byte_idx = 31 - (nibbles_written / 2);
        if (nibbles_written % 2 == 0) {
            result[byte_idx] = nibble;
        } else {
            result[byte_idx] |= nibble << 4;
        }
        nibbles_written += 1;
    }
    return result;
}

/// SPEC: Part 2.1 — Convert a hex character to its 4-bit value.
fn hexVal(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => 0,
    };
}

/// SPEC: Part 2.5 — Scale a fixed-point literal string into a 256-bit integer.
/// E.g. "1.5" with 18 decimals → 1_500_000_000_000_000_000 as [32]u8.
fn scaleFixedPointTo256(lit: []const u8, decimals: u8) [32]u8 {
    var int_buf: [80]u8 = undefined;
    var frac_buf: [80]u8 = undefined;
    var int_len: usize = 0;
    var frac_len: usize = 0;
    var in_frac = false;

    for (lit) |c| {
        if (c == '_') continue;
        if (c == '.') {
            in_frac = true;
            continue;
        }
        if (!in_frac) {
            if (int_len < int_buf.len) {
                int_buf[int_len] = c;
                int_len += 1;
            }
        } else {
            if (frac_len < frac_buf.len) {
                frac_buf[frac_len] = c;
                frac_len += 1;
            }
        }
    }

    // Build the full scaled integer string: int_part + zero-padded frac.
    var scaled_buf: [160]u8 = undefined;
    var scaled_len: usize = 0;

    // Copy integer part digits.
    const int_digits = if (int_len > 0) int_buf[0..int_len] else "0";
    for (int_digits) |d| {
        if (scaled_len < scaled_buf.len) {
            scaled_buf[scaled_len] = d;
            scaled_len += 1;
        }
    }

    // Copy fraction digits up to `decimals`, padding with '0'.
    var f: u8 = 0;
    while (f < decimals) : (f += 1) {
        const digit: u8 = if (f < frac_len) frac_buf[f] else '0';
        if (scaled_len < scaled_buf.len) {
            scaled_buf[scaled_len] = digit;
            scaled_len += 1;
        }
    }

    return parseDecimalTo256(scaled_buf[0..scaled_len]);
}

/// SPEC: Part 5.5 — Simple FNV-1a hash to derive function selectors.
fn fnvHash32(name: []const u8) u32 {
    var h: u32 = 0x811c9dc5;
    for (name) |b| {
        h ^= b;
        h *%= 0x01000193;
    }
    return h;
}

// ============================================================================
// Section 7 — Tests
// ============================================================================

test "parseDecimalTo256 small value" {
    const result = parseDecimalTo256("42");
    try std.testing.expectEqual(@as(u8, 42), result[31]);
    try std.testing.expectEqual(@as(u8, 0), result[30]);
}

test "parseDecimalTo256 large value 1000" {
    const result = parseDecimalTo256("1000");
    // 1000 = 0x03E8
    try std.testing.expectEqual(@as(u8, 0xE8), result[31]);
    try std.testing.expectEqual(@as(u8, 0x03), result[30]);
}

test "parseHexTo256 basic" {
    const result = parseHexTo256("FF");
    try std.testing.expectEqual(@as(u8, 0xFF), result[31]);
    try std.testing.expectEqual(@as(u8, 0), result[30]);
}

test "parseHexTo256 multi-byte" {
    const result = parseHexTo256("DEADBEEF");
    try std.testing.expectEqual(@as(u8, 0xEF), result[31]);
    try std.testing.expectEqual(@as(u8, 0xBE), result[30]);
    try std.testing.expectEqual(@as(u8, 0xAD), result[29]);
    try std.testing.expectEqual(@as(u8, 0xDE), result[28]);
}

test "parseIntLitTo256 hex prefix" {
    const result = parseIntLitTo256("0xFF");
    try std.testing.expectEqual(@as(u8, 0xFF), result[31]);
}

test "parseIntLitTo256 underscore removal" {
    const result = parseIntLitTo256("1_000");
    const expected = parseDecimalTo256("1000");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "scaleFixedPointTo256 basic" {
    const result = scaleFixedPointTo256("1.5", 9);
    const expected = parseDecimalTo256("1500000000");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "scaleFixedPointTo256 integer only" {
    const result = scaleFixedPointTo256("100", 9);
    const expected = parseDecimalTo256("100000000000");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "scaleFixedPointTo256 eighteen decimals" {
    const result = scaleFixedPointTo256("1.0", 18);
    const expected = parseDecimalTo256("1000000000000000000");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "fnvHash32 deterministic" {
    const h1 = fnvHash32("transfer");
    const h2 = fnvHash32("transfer");
    const h3 = fnvHash32("approve");
    try std.testing.expectEqual(h1, h2);
    try std.testing.expect(h1 != h3);
}

test "DataSection intern deduplicates" {
    const alloc = std.testing.allocator;
    var ds = DataSection.init(alloc);
    defer ds.deinit();

    const r1 = try ds.intern("hello");
    const r2 = try ds.intern("hello");
    try std.testing.expectEqual(r1.offset, r2.offset);
    try std.testing.expectEqual(r1.len, r2.len);
}

test "DataSection intern different strings" {
    const alloc = std.testing.allocator;
    var ds = DataSection.init(alloc);
    defer ds.deinit();

    const r1 = try ds.intern("abc");
    const r2 = try ds.intern("xyz");
    try std.testing.expect(r1.offset != r2.offset);
}

test "MirLowerer freshReg monotonic" {
    const alloc = std.testing.allocator;
    var diag = DiagnosticList.init(alloc);
    defer diag.deinit();
    var resolver = TypeResolver.init(alloc, &diag);
    defer resolver.deinit();

    var low = MirLowerer.init(alloc, &resolver, &diag);
    defer low.deinit();

    const r0 = low.freshReg();
    const r1 = low.freshReg();
    const r2 = low.freshReg();
    try std.testing.expectEqual(@as(Reg, 0), r0);
    try std.testing.expectEqual(@as(Reg, 1), r1);
    try std.testing.expectEqual(@as(Reg, 2), r2);
}

test "MirLowerer freshLabel monotonic" {
    const alloc = std.testing.allocator;
    var diag = DiagnosticList.init(alloc);
    defer diag.deinit();
    var resolver = TypeResolver.init(alloc, &diag);
    defer resolver.deinit();

    var low = MirLowerer.init(alloc, &resolver, &diag);
    defer low.deinit();

    const l0 = low.freshLabel();
    const l1 = low.freshLabel();
    try std.testing.expectEqual(@as(LabelId, 0), l0);
    try std.testing.expectEqual(@as(LabelId, 1), l1);
}

test "MirLowerer bindLocal and lookupLocal" {
    const alloc = std.testing.allocator;
    var diag = DiagnosticList.init(alloc);
    defer diag.deinit();
    var resolver = TypeResolver.init(alloc, &diag);
    defer resolver.deinit();

    var low = MirLowerer.init(alloc, &resolver, &diag);
    defer low.deinit();

    const r = low.freshReg();
    try low.bindLocal("x", r);
    try std.testing.expectEqual(r, low.lookupLocal("x").?);
    try std.testing.expectEqual(@as(?Reg, null), low.lookupLocal("y"));
}
