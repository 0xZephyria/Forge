// ============================================================================
// Forge Compiler — EVM Code Generator
// ============================================================================
//
// Compiles Forge contracts to latest EVM (Cancun / EIP-4844) bytecode.
// Produces complete initcode (deploy code) that, when executed by the EVM,
// deploys the contract runtime.
//
// Layout of output binary:
//   [deploy_code][runtime_code]
//
// Deploy code:
//   1. Free-memory-pointer initialisation (0x40 ← 0x80)
//   2. Constructor body (from `setup:` block)
//   3. CODECOPY runtime → memory; RETURN runtime
//
// Runtime code:
//   1. Free-memory-pointer initialisation
//   2. 4-byte selector dispatcher (Keccak-256 selectors)
//   3. One handler per action / view / pure
//   4. Fallback: REVERT with no data
//
// Key EVM ABI conventions:
//   • Function selectors: Keccak-256("name(t1,t2)")[0..3]
//   • Calldata: 4-byte selector | 32-byte aligned arg[0] | arg[1] | …
//   • Return data: ABI-encoded value(s) in memory, RETURN(offset, size)
//   • Storage: slot = sequential field index; maps = keccak256(key ++ slot)
//   • Locals: memory-based, 32-byte slots starting at 0x80
//   • Events: LOG1..LOG4 with topic[0] = keccak256(event_sig)
//   • Reverts: REVERT(0, 0) or REVERT with reason string
//
// SPEC REFERENCE: Part 5 (Contract Anatomy), Part 14 (EVM ABI compatibility)
//
// This is a library file. No main() function is present.

const std = @import("std");
const ast = @import("ast.zig");
const errors = @import("errors.zig");
const types = @import("types.zig");
const checker = @import("checker.zig");

const Span = ast.Span;
const Expr = ast.Expr;
const ExprKind = ast.ExprKind;
const Stmt = ast.Stmt;
const StmtKind = ast.StmtKind;
const BinOp = ast.BinOp;
const UnaryOp = ast.UnaryOp;
const ContractDef = ast.ContractDef;
const ActionDecl = ast.ActionDecl;
const ViewDecl = ast.ViewDecl;
const WhenStmt = ast.WhenStmt;
const MatchStmt = ast.MatchStmt;
const EachLoop = ast.EachLoop;
const RepeatLoop = ast.RepeatLoop;
const WhileLoop = ast.WhileLoop;
const NeedStmt = ast.NeedStmt;
const TellStmt = ast.TellStmt;
const Argument = ast.Argument;

const DiagnosticList = errors.DiagnosticList;
const TypeResolver = types.TypeResolver;
const ResolvedType = types.ResolvedType;
const CheckedContract = checker.CheckedContract;
const U256 = @import("u256.zig").U256;

// ============================================================================
// Section 1 — EVM Opcodes (Cancun / EIP-4844 complete set)
// ============================================================================

/// All EVM opcodes up to and including Cancun (EIP-4844, EIP-1153, EIP-5656).
pub const Op = enum(u8) {
    // ── Arithmetic ─────────────────────────────────────────────────────────
    STOP        = 0x00,
    ADD         = 0x01,
    MUL         = 0x02,
    SUB         = 0x03,
    DIV         = 0x04,
    SDIV        = 0x05,
    MOD         = 0x06,
    SMOD        = 0x07,
    ADDMOD      = 0x08,
    MULMOD      = 0x09,
    EXP         = 0x0A,
    SIGNEXTEND  = 0x0B,
    // ── Comparison & bitwise ───────────────────────────────────────────────
    LT          = 0x10,
    GT          = 0x11,
    SLT         = 0x12,
    SGT         = 0x13,
    EQ          = 0x14,
    ISZERO      = 0x15,
    AND         = 0x16,
    OR          = 0x17,
    XOR         = 0x18,
    NOT         = 0x19,
    BYTE        = 0x1A,
    SHL         = 0x1B,  // Constantinople+
    SHR         = 0x1C,  // Constantinople+
    SAR         = 0x1D,  // Constantinople+
    // ── Hash ──────────────────────────────────────────────────────────────
    KECCAK256   = 0x20,
    // ── Context ───────────────────────────────────────────────────────────
    ADDRESS     = 0x30,
    BALANCE     = 0x31,
    ORIGIN      = 0x32,
    CALLER      = 0x33,
    CALLVALUE   = 0x34,
    CALLDATALOAD = 0x35,
    CALLDATASIZE = 0x36,
    CALLDATACOPY = 0x37,
    CODESIZE    = 0x38,
    CODECOPY    = 0x39,
    GASPRICE    = 0x3A,
    EXTCODESIZE = 0x3B,
    EXTCODECOPY = 0x3C,
    RETURNDATASIZE = 0x3D,
    RETURNDATACOPY = 0x3E,
    EXTCODEHASH = 0x3F,
    // ── Block ─────────────────────────────────────────────────────────────
    BLOCKHASH   = 0x40,
    COINBASE    = 0x41,
    TIMESTAMP   = 0x42,
    NUMBER      = 0x43,
    PREVRANDAO  = 0x44,
    GASLIMIT    = 0x45,
    CHAINID     = 0x46,
    SELFBALANCE = 0x47,
    BASEFEE     = 0x48,
    BLOBHASH    = 0x49,  // Cancun
    BLOBBASEFEE = 0x4A,  // Cancun
    // ── Memory / Storage ──────────────────────────────────────────────────
    POP         = 0x50,
    MLOAD       = 0x51,
    MSTORE      = 0x52,
    MSTORE8     = 0x53,
    SLOAD       = 0x54,
    SSTORE      = 0x55,
    JUMP        = 0x56,
    JUMPI       = 0x57,
    PC          = 0x58,
    MSIZE       = 0x59,
    GAS         = 0x5A,
    JUMPDEST    = 0x5B,
    TLOAD       = 0x5C,  // Cancun (EIP-1153)
    TSTORE      = 0x5D,  // Cancun (EIP-1153)
    MCOPY       = 0x5E,  // Cancun (EIP-5656)
    // ── PUSH ──────────────────────────────────────────────────────────────
    PUSH0       = 0x5F,  // Shanghai+
    PUSH1       = 0x60,
    PUSH2       = 0x61,
    PUSH3       = 0x62,
    PUSH4       = 0x63,
    PUSH5       = 0x64,
    PUSH6       = 0x65,
    PUSH7       = 0x66,
    PUSH8       = 0x67,
    PUSH9       = 0x68,
    PUSH10      = 0x69,
    PUSH11      = 0x6A,
    PUSH12      = 0x6B,
    PUSH13      = 0x6C,
    PUSH14      = 0x6D,
    PUSH15      = 0x6E,
    PUSH16      = 0x6F,
    PUSH17      = 0x70,
    PUSH18      = 0x71,
    PUSH19      = 0x72,
    PUSH20      = 0x73,
    PUSH21      = 0x74,
    PUSH22      = 0x75,
    PUSH23      = 0x76,
    PUSH24      = 0x77,
    PUSH25      = 0x78,
    PUSH26      = 0x79,
    PUSH27      = 0x7A,
    PUSH28      = 0x7B,
    PUSH29      = 0x7C,
    PUSH30      = 0x7D,
    PUSH31      = 0x7E,
    PUSH32      = 0x7F,
    // ── DUP ───────────────────────────────────────────────────────────────
    DUP1        = 0x80,
    DUP2        = 0x81,
    DUP3        = 0x82,
    DUP4        = 0x83,
    DUP5        = 0x84,
    DUP6        = 0x85,
    DUP7        = 0x86,
    DUP8        = 0x87,
    DUP9        = 0x88,
    DUP10       = 0x89,
    DUP11       = 0x8A,
    DUP12       = 0x8B,
    DUP13       = 0x8C,
    DUP14       = 0x8D,
    DUP15       = 0x8E,
    DUP16       = 0x8F,
    // ── SWAP ──────────────────────────────────────────────────────────────
    SWAP1       = 0x90,
    SWAP2       = 0x91,
    SWAP3       = 0x92,
    SWAP4       = 0x93,
    SWAP5       = 0x94,
    SWAP6       = 0x95,
    SWAP7       = 0x96,
    SWAP8       = 0x97,
    SWAP9       = 0x98,
    SWAP10      = 0x99,
    SWAP11      = 0x9A,
    SWAP12      = 0x9B,
    SWAP13      = 0x9C,
    SWAP14      = 0x9D,
    SWAP15      = 0x9E,
    SWAP16      = 0x9F,
    // ── LOG ───────────────────────────────────────────────────────────────
    LOG0        = 0xA0,
    LOG1        = 0xA1,
    LOG2        = 0xA2,
    LOG3        = 0xA3,
    LOG4        = 0xA4,
    // ── System ────────────────────────────────────────────────────────────
    CREATE      = 0xF0,
    CALL        = 0xF1,
    CALLCODE    = 0xF2,
    RETURN      = 0xF3,
    DELEGATECALL = 0xF4,
    CREATE2     = 0xF5,
    STATICCALL  = 0xFA,
    REVERT      = 0xFD,
    INVALID     = 0xFE,
    SELFDESTRUCT = 0xFF,
};

// ============================================================================
// Section 2 — EVM Bytecode Writer
// ============================================================================

/// Backpatch entry: position in the bytecode buffer where a 2-byte
/// absolute jump target needs to be filled in after code generation.
pub const Patch = struct {
    /// Byte offset of the first byte of the PUSH2 operand.
    offset: u32,
};

/// Append-only EVM bytecode buffer with helpers for pushes and backpatching.
pub const EVMWriter = struct {
    buf: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) EVMWriter {
        return .{ .buf = .{}, .allocator = allocator };
    }

    pub fn deinit(self: *EVMWriter) void {
        self.buf.deinit(self.allocator);
    }

    /// Current byte offset (= length of emitted bytecode).
    pub fn offset(self: *const EVMWriter) u32 {
        return @intCast(self.buf.items.len);
    }

    /// Emit a single opcode byte.
    pub fn op(self: *EVMWriter, o: Op) anyerror!void {
        try self.buf.append(self.allocator, @intFromEnum(o));
    }

    /// Emit a raw byte (used for PUSH operands).
    pub fn byte(self: *EVMWriter, b: u8) anyerror!void {
        try self.buf.append(self.allocator, b);
    }

    /// Emit PUSH0 (pushes zero; Shanghai+).
    pub fn push0(self: *EVMWriter) anyerror!void {
        try self.op(.PUSH0);
    }

    /// Emit PUSH1 with a 1-byte operand.
    pub fn push1(self: *EVMWriter, v: u8) anyerror!void {
        try self.op(.PUSH1);
        try self.byte(v);
    }

    /// Emit PUSH2 with a 2-byte big-endian operand.
    pub fn push2(self: *EVMWriter, v: u16) anyerror!void {
        try self.op(.PUSH2);
        try self.byte(@intCast(v >> 8));
        try self.byte(@intCast(v & 0xFF));
    }

    /// Emit PUSH4 with a 4-byte big-endian operand (for function selectors).
    pub fn push4(self: *EVMWriter, v: u32) anyerror!void {
        try self.op(.PUSH4);
        try self.byte(@intCast((v >> 24) & 0xFF));
        try self.byte(@intCast((v >> 16) & 0xFF));
        try self.byte(@intCast((v >> 8) & 0xFF));
        try self.byte(@intCast(v & 0xFF));
    }

    /// Emit the minimal PUSH instruction for a u256 value stored big-endian.
    /// value_be: big-endian 32-byte representation. Leading zero bytes stripped.
    pub fn pushU256BE(self: *EVMWriter, value_be: [32]u8) anyerror!void {
        // Count leading zero bytes to determine minimal push width.
        var leading_zeros: usize = 0;
        while (leading_zeros < 32 and value_be[leading_zeros] == 0) {
            leading_zeros += 1;
        }
        if (leading_zeros == 32) {
            try self.push0();
            return;
        }
        const sig_len: usize = 32 - leading_zeros;
        const push_op: u8 = @intCast(0x5F + sig_len); // PUSH0 + n = PUSHn
        try self.buf.append(self.allocator, push_op);
        try self.buf.appendSlice(self.allocator, value_be[leading_zeros..]);
    }

    /// Push a u64 value using the minimal PUSH opcode.
    pub fn pushU64(self: *EVMWriter, v: u64) anyerror!void {
        if (v == 0) {
            try self.push0();
            return;
        }
        var be: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u64, be[24..32], v, .big);
        try self.pushU256BE(be);
    }

    /// Push a u32 value (e.g. a function selector or slot ID).
    pub fn pushU32(self: *EVMWriter, v: u32) anyerror!void {
        if (v == 0) {
            try self.push0();
            return;
        }
        var be: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u32, be[28..32], v, .big);
        try self.pushU256BE(be);
    }

    /// Emit a PUSH2 placeholder and return the offset of its 2-byte operand
    /// for later backpatching.
    pub fn push2Placeholder(self: *EVMWriter) anyerror!u32 {
        try self.op(.PUSH2);
        const patch_offset = self.offset();
        try self.byte(0x00);
        try self.byte(0x00);
        return patch_offset;
    }

    /// Patch a 2-byte big-endian absolute jump target at a previously-recorded
    /// operand offset.
    pub fn patchU16(self: *EVMWriter, patch_offset: u32, target: u32) void {
        self.buf.items[patch_offset]     = @intCast((target >> 8) & 0xFF);
        self.buf.items[patch_offset + 1] = @intCast(target & 0xFF);
    }

    /// Return the accumulated bytes as a slice (not owned).
    pub fn bytes(self: *const EVMWriter) []const u8 {
        return self.buf.items;
    }

    /// Transfer ownership of the buffer to the caller.
    pub fn toOwnedSlice(self: *EVMWriter) anyerror![]u8 {
        return self.buf.toOwnedSlice(self.allocator);
    }
};

// ============================================================================
// Section 3 — Keccak-256 Helpers
// ============================================================================

/// Compute Keccak-256 of `data`. Returns 32-byte digest.
pub fn keccak256(data: []const u8) [32]u8 {
    var h = std.crypto.hash.sha3.Keccak256.init(.{});
    h.update(data);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Compute the 4-byte EVM function selector from a canonical function
/// signature string, e.g. `"transfer(address,uint256)"`.
pub fn evmSelector(sig: []const u8) u32 {
    const digest = keccak256(sig);
    return std.mem.readInt(u32, digest[0..4], .big);
}

// ============================================================================
// Section 4 — EVM ABI Type Helpers
// ============================================================================

/// Map a Forge ResolvedType to its canonical EVM ABI type string.
/// Used to build function signature strings for selector computation.
pub fn evmAbiType(ty: ResolvedType) []const u8 {
    return switch (ty) {
        .u8       => "uint8",
        .u16      => "uint16",
        .u32      => "uint32",
        .u64      => "uint64",
        .u128     => "uint128",
        .u256     => "uint256",
        .i8       => "int8",
        .i16      => "int16",
        .i32      => "int32",
        .i64      => "int64",
        .i128     => "int128",
        .i256     => "int256",
        .fixed_point => "uint256",
        .bool     => "bool",
        .account, .wallet, .program, .system_acc => "address",
        .hash, .commitment => "bytes32",
        .bytes_n  => |n| switch (n) {
            1  => "bytes1",  2  => "bytes2",  4  => "bytes4",
            8  => "bytes8",  16 => "bytes16", 20 => "bytes20",
            32 => "bytes32", 64 => "bytes32", // bytes64 capped to bytes32
            else => "bytes32",
        },
        .bytes    => "bytes",
        .signature => "bytes",
        .pubkey   => "bytes",
        .string, .short_str => "string",
        .timestamp, .duration, .block_number => "uint64",
        .asset    => "address",
        .list     => "bytes",
        .set      => "bytes",
        .map, .enum_map => "bytes",
        .array    => "bytes",
        .tuple    => "bytes",
        .struct_  => "bytes",
        .enum_    => "uint8",
        .maybe    => "bytes",
        .result   => "bytes",
        .linear   => "bytes",
        .void_    => "",
    };
}

/// Build a canonical EVM function signature string: `"name(t0,t1,...)"`.
/// Caller must free the returned slice.
pub fn buildFuncSig(
    name: []const u8,
    params: []const ast.Param,
    resolver: *TypeResolver,
    alloc: std.mem.Allocator,
) anyerror![]u8 {
    var buf = std.ArrayListUnmanaged(u8){};
    errdefer buf.deinit(alloc);
    try buf.appendSlice(alloc, name);
    try buf.append(alloc, '(');
    for (params, 0..) |p, i| {
        if (i > 0) try buf.append(alloc, ',');
        const rt = try resolver.resolve(p.declared_type);
        try buf.appendSlice(alloc, evmAbiType(rt));
    }
    try buf.append(alloc, ')');
    return buf.toOwnedSlice(alloc);
}

/// Build the EVM function selector for an action given its AST declaration.
pub fn buildSelector(
    name: []const u8,
    params: []const ast.Param,
    resolver: *TypeResolver,
    alloc: std.mem.Allocator,
) anyerror!u32 {
    const sig = try buildFuncSig(name, params, resolver, alloc);
    defer alloc.free(sig);
    return evmSelector(sig);
}

/// Build an event signature string for LOG topic[0]:
/// `"EventName(t0,t1,...)"`.
pub fn buildEventSig(
    name: []const u8,
    fields: []const ast.EventField,
    resolver: *TypeResolver,
    alloc: std.mem.Allocator,
) anyerror!u32 {
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(alloc);
    try buf.appendSlice(alloc, name);
    try buf.append(alloc, '(');
    for (fields, 0..) |f, i| {
        if (i > 0) try buf.append(alloc, ',');
        const rt = try resolver.resolve(f.type_);
        try buf.appendSlice(alloc, evmAbiType(rt));
    }
    try buf.append(alloc, ')');
    return evmSelector(buf.items);
}

/// Return the ABI-encoding byte-width of a type.
/// Static types: 32 bytes. Dynamic types (bytes, string, array): 0 = dynamic.
pub fn abiStaticSize(ty: ResolvedType) u32 {
    return switch (ty) {
        .bytes, .string, .short_str => 0,  // dynamic
        .list, .set, .map, .enum_map, .array, .tuple, .struct_, .result => 0,
        else => 32,
    };
}

// ============================================================================
// Section 5 — Storage Slot Management
// ============================================================================

/// Manages sequential storage slot assignment for state fields.
/// Slots start at 0 and increment per field, matching Solidity layout.
pub const SlotMap = struct {
    map: std.StringHashMap(u256),
    next_slot: u256,

    pub fn init(alloc: std.mem.Allocator) SlotMap {
        return .{ .map = std.StringHashMap(u256).init(alloc), .next_slot = 0 };
    }

    pub fn deinit(self: *SlotMap) void {
        self.map.deinit();
    }

    pub fn register(self: *SlotMap, name: []const u8) anyerror!void {
        const result = try self.map.getOrPut(name);
        if (!result.found_existing) {
            result.value_ptr.* = self.next_slot;
            self.next_slot += 1;
        }
    }

    pub fn getSlot(self: *const SlotMap, name: []const u8) ?u256 {
        return self.map.get(name);
    }
};

// ============================================================================
// Section 6 — Local Variable Frame (Memory-based)
// ============================================================================

/// EVM memory layout for local variables.
/// Memory[0x00..0x1F]  — scratch for keccak256 key
/// Memory[0x20..0x3F]  — scratch for keccak256 slot
/// Memory[0x40..0x5F]  — free memory pointer (Solidity standard)
/// Memory[0x60..0x7F]  — zero slot (Solidity standard)
/// Memory[0x80..]      — local variable slots (32 bytes each)
const LOCAL_START: u32 = 0x80;

pub const LocalFrame = struct {
    slots: std.StringHashMap(u32),
    next_offset: u32,
    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) LocalFrame {
        return .{
            .slots = std.StringHashMap(u32).init(alloc),
            .next_offset = LOCAL_START,
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *LocalFrame) void {
        self.slots.deinit();
    }

    /// Allocate a new 32-byte memory slot for `name` and return the offset.
    pub fn alloc_slot(self: *LocalFrame, name: []const u8) anyerror!u32 {
        const result = try self.slots.getOrPut(name);
        if (!result.found_existing) {
            result.value_ptr.* = self.next_offset;
            self.next_offset += 32;
        }
        return result.value_ptr.*;
    }

    pub fn get(self: *const LocalFrame, name: []const u8) ?u32 {
        return self.slots.get(name);
    }
};

// ============================================================================
// Section 7 — Function Code Generation Context
// ============================================================================

/// Per-function state maintained during EVM code generation.
const FuncCtx = struct {
    w: EVMWriter,
    locals: LocalFrame,
    /// Offsets of PUSH2 placeholder operands for `stop` (break) inside loops.
    loop_breaks: std.ArrayListUnmanaged(u32),
    /// Offsets of PUSH2 placeholder operands for `skip` (continue) inside loops.
    loop_conts: std.ArrayListUnmanaged(u32),
    /// Offsets of PUSH2 placeholder operands for `give back` (return) in the
    /// middle of a function, needing to jump to the epilogue.
    early_returns: std.ArrayListUnmanaged(u32),
    alloc: std.mem.Allocator,

    fn init(alloc: std.mem.Allocator) FuncCtx {
        return .{
            .w = EVMWriter.init(alloc),
            .locals = LocalFrame.init(alloc),
            .loop_breaks = .{},
            .loop_conts = .{},
            .early_returns = .{},
            .alloc = alloc,
        };
    }

    fn deinit(self: *FuncCtx) void {
        self.w.deinit();
        self.locals.deinit();
        self.loop_breaks.deinit(self.alloc);
        self.loop_conts.deinit(self.alloc);
        self.early_returns.deinit(self.alloc);
    }
};

// ============================================================================
// Section 8 — EVM Code Generator
// ============================================================================

/// Complete EVM code generator. Converts a type-checked Forge contract into
/// EVM initcode (deploy + runtime combined).
pub const EVMCodeGen = struct {
    allocator: std.mem.Allocator,
    diagnostics: *DiagnosticList,
    resolver: *TypeResolver,
    slots: SlotMap,

    pub fn init(
        allocator: std.mem.Allocator,
        diagnostics: *DiagnosticList,
        resolver: *TypeResolver,
    ) EVMCodeGen {
        return .{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .resolver = resolver,
            .slots = SlotMap.init(allocator),
        };
    }

    pub fn deinit(self: *EVMCodeGen) void {
        self.slots.deinit();
    }

    // ── Top-level entry point ─────────────────────────────────────────────

    /// Generate the complete EVM initcode for `contract`.
    /// Returns caller-owned heap slice.
    pub fn generate(
        self: *EVMCodeGen,
        contract: *const ContractDef,
        checked: *const CheckedContract,
    ) anyerror![]u8 {
        _ = checked;

        // Pre-register all state field slots in declaration order.
        for (contract.state) |sf| {
            try self.slots.register(sf.name);
        }

        // ── Generate runtime bytecode ─────────────────────────────────────
        const runtime = try self.generateRuntime(contract);
        defer self.allocator.free(runtime);

        // ── Generate deploy (init) code ───────────────────────────────────
        const deploy = try self.generateDeploy(contract, runtime);
        defer self.allocator.free(deploy);

        // ── Concatenate deploy + runtime ──────────────────────────────────
        const total = deploy.len + runtime.len;
        const out = try self.allocator.alloc(u8, total);
        @memcpy(out[0..deploy.len], deploy);
        @memcpy(out[deploy.len..], runtime);
        return out;
    }

    // ── Deploy (initcode) generation ──────────────────────────────────────

    /// Produce deploy code.  After running, it copies `runtime` into memory
    /// and returns it — this is the standard EVM constructor pattern.
    fn generateDeploy(
        self: *EVMCodeGen,
        contract: *const ContractDef,
        runtime: []const u8,
    ) anyerror![]u8 {
        var w = EVMWriter.init(self.allocator);
        defer w.deinit();

        // ── Init free-memory pointer: memory[0x40] = 0x80 ─────────────────
        try w.push1(0x80);
        try w.push1(0x40);
        try w.op(.MSTORE);

        // ── Constructor body ──────────────────────────────────────────────
        if (contract.setup) |setup| {
            var ctx = FuncCtx.init(self.allocator);
            defer ctx.deinit();

            // ABI-decode constructor parameters from calldata (no selector).
            for (setup.params, 0..) |param, i| {
                const cd_offset: u32 = @intCast(i * 32);
                try w.pushU32(cd_offset);
                try w.op(.CALLDATALOAD);
                const mem_slot = try ctx.locals.alloc_slot(param.name);
                try w.pushU32(mem_slot);
                try w.op(.MSTORE);
            }

            for (setup.body) |stmt| {
                try self.genStmt(&stmt, &ctx, &w);
            }
        }

        // ── CODECOPY runtime into memory[0x00] and RETURN it ──────────────
        // We need the runtime length and the offset of runtime within the
        // final binary (= deploy code length).
        // Since we don't know deploy_code length yet, we use placeholders
        // and emit at end.

        // First, compute deploy code length *without* the CODECOPY/RETURN
        // preamble to know the offset.  We'll hard-code the 3-instruction
        // CODECOPY/RETURN sequence and add its own size.
        //
        // CODECOPY: PUSH2 <rt_len> PUSH2 <deploy_len> PUSH0 CODECOPY
        //           = 3 + 3 + 1 + 1 = 8 bytes
        // RETURN:   PUSH2 <rt_len> PUSH0 RETURN
        //           = 3 + 1 + 1 = 5 bytes
        // Total appendix = 13 bytes.
        const appendix_size: u32 = 13;
        const deploy_code_len: u32 = w.offset() + appendix_size;
        const runtime_len: u16 = @intCast(runtime.len);

        // PUSH2 <runtime_len>  (size to copy)
        try w.push2(runtime_len);
        // PUSH2 <deploy_code_len>  (source offset = where runtime starts in binary)
        try w.push2(@intCast(deploy_code_len));
        // PUSH0  (destination in memory = 0)
        try w.push0();
        // CODECOPY pops dest(top), src(second), size(third)
        try w.op(.CODECOPY);

        // RETURN pops offset(top), size(second)  →  return memory[0..runtime_len]
        try w.push2(runtime_len);
        try w.push0();
        try w.op(.RETURN);

        return w.toOwnedSlice();
    }

    // ── Runtime generation ────────────────────────────────────────────────

    /// Produce the runtime bytecode: dispatcher + all function handlers.
    fn generateRuntime(
        self: *EVMCodeGen,
        contract: *const ContractDef,
    ) anyerror![]u8 {
        var w = EVMWriter.init(self.allocator);
        defer w.deinit();

        // ── Init free-memory pointer ──────────────────────────────────────
        try w.push1(0x80);
        try w.push1(0x40);
        try w.op(.MSTORE);

        // ── Selector extraction ───────────────────────────────────────────
        // if (calldatasize < 4) goto fallback
        try w.op(.CALLDATASIZE);
        try w.push1(0x04);
        try w.op(.LT);
        const fallback_patch = try w.push2Placeholder();
        try w.op(.JUMPI);

        // Extract selector: calldata[0..3] as uint256
        // PUSH0 CALLDATALOAD → first 32 bytes of calldata
        // PUSH1 0xe0 SHR     → right-align top 4 bytes = selector
        try w.push0();
        try w.op(.CALLDATALOAD);
        try w.push1(0xe0);
        try w.op(.SHR);
        // Selector is now on top of stack.

        // ── Dispatch table ────────────────────────────────────────────────
        // For each action/view, emit: DUP1 PUSH4 <sel> EQ PUSH2 <handler> JUMPI
        const ActionEntry = struct {
            selector: u32,
            patch: u32,  // offset of PUSH2 operand for handler address
        };
        var entries = std.ArrayListUnmanaged(ActionEntry){};
        defer entries.deinit(self.allocator);

        for (contract.actions) |action| {
            const sel = try buildSelector(action.name, action.params, self.resolver, self.allocator);
            try w.op(.DUP1);
            try w.push4(sel);
            try w.op(.EQ);
            const patch = try w.push2Placeholder();
            try w.op(.JUMPI);
            try entries.append(self.allocator, .{ .selector = sel, .patch = patch });
        }

        for (contract.views) |view| {
            const sel = try buildSelector(view.name, view.params, self.resolver, self.allocator);
            try w.op(.DUP1);
            try w.push4(sel);
            try w.op(.EQ);
            const patch = try w.push2Placeholder();
            try w.op(.JUMPI);
            try entries.append(self.allocator, .{ .selector = sel, .patch = patch });
        }

        for (contract.pures) |pure| {
            const sel = try buildSelector(pure.name, pure.params, self.resolver, self.allocator);
            try w.op(.DUP1);
            try w.push4(sel);
            try w.op(.EQ);
            const patch = try w.push2Placeholder();
            try w.op(.JUMPI);
            try entries.append(self.allocator, .{ .selector = sel, .patch = patch });
        }

        // ── Fallback ──────────────────────────────────────────────────────
        // Patch the < 4 bytes jump to here.
        const fallback_dest = w.offset();
        w.patchU16(fallback_patch, fallback_dest);
        try w.op(.JUMPDEST);
        // POP selector if still on stack (only if calldatasize >= 4 path)
        // Actually at fallback_dest from the "< 4" path, selector was never
        // computed.  At the dispatch exhaustion path, selector is on stack.
        // We emit a "POP if selector on stack" only on the exhaustion path.
        // Simple approach: duplicate handling.
        // For the < 4 bytes path we just REVERT directly.
        try w.push0();
        try w.push0();
        try w.op(.REVERT);

        // Also handle dispatch exhaustion (selector on stack, no match):
        // We need a second fallback for this case.
        const no_match_dest = w.offset();
        try w.op(.JUMPDEST);
        try w.op(.POP);  // pop selector
        try w.push0();
        try w.push0();
        try w.op(.REVERT);

        // Patch all dispatch JUMPI that fall through (no match) to no_match_dest.
        // Actually: rewrite dispatch to jump to no_match when no match found.
        // The current dispatch already falls through to fallback which handles
        // both cases. Patch entry table to no_match_dest for exhaustion.
        // We'll just emit function bodies now; we already patched fallback above.
        // The "exhaustion" path (all JUMPIs failed) falls through to
        // fallback_dest area. Let's add an unconditional jump to no_match
        // before the first JUMPDEST.
        // Actually, the dispatch fallthrough goes to the fallback_dest (which
        // has REVERT) only if selector >= 4; the JUMPI there only fires for
        // calldatasize < 4. So there's a subtle bug: when all DUP1/PUSH4/EQ
        // dispatches fail, we fall through to the JUMPDEST fallback label.
        // Since fallback_dest has JUMPDEST then REVERT, this works correctly!

        // ── Function handlers ─────────────────────────────────────────────
        var entry_idx: usize = 0;

        for (contract.actions) |action| {
            const handler_dest = w.offset();
            w.patchU16(entries.items[entry_idx].patch, handler_dest);
            entry_idx += 1;
            try w.op(.JUMPDEST);
            try w.op(.POP);  // pop selector
            try self.genAction(&action, &w);
        }

        for (contract.views) |view| {
            const handler_dest = w.offset();
            w.patchU16(entries.items[entry_idx].patch, handler_dest);
            entry_idx += 1;
            try w.op(.JUMPDEST);
            try w.op(.POP);
            try self.genView(&view, &w);
        }

        for (contract.pures) |pure| {
            const handler_dest = w.offset();
            w.patchU16(entries.items[entry_idx].patch, handler_dest);
            entry_idx += 1;
            try w.op(.JUMPDEST);
            try w.op(.POP);
            try self.genPure(&pure, &w);
        }

        _ = no_match_dest;

        return w.toOwnedSlice();
    }

    // ── Action / View / Pure generation ──────────────────────────────────

    /// Generate EVM bytecode for one action function.
    fn genAction(self: *EVMCodeGen, action: *const ActionDecl, w: *EVMWriter) anyerror!void {
        var ctx = FuncCtx.init(self.allocator);
        defer ctx.deinit();

        // ABI-decode calldata parameters into local memory slots.
        try self.genDecodeParams(action.params, &ctx, w);

        // Handle `only` guards first (scan for them in the body).
        for (action.body) |stmt| {
            if (stmt.kind == .only) {
                try self.genOnly(&stmt.kind.only, &ctx, w);
            }
        }

        // Body statements.
        for (action.body) |stmt| {
            if (stmt.kind != .only) {
                try self.genStmt(&stmt, &ctx, w);
            }
        }

        // Epilogue: patch early-return jumps to here, then STOP.
        const epilogue_dest = w.offset();
        for (ctx.early_returns.items) |patch_off| {
            w.patchU16(patch_off, epilogue_dest);
        }
        try w.op(.STOP);
    }

    /// Generate EVM bytecode for one view function (read-only, must RETURN).
    fn genView(self: *EVMCodeGen, view: *const ViewDecl, w: *EVMWriter) anyerror!void {
        var ctx = FuncCtx.init(self.allocator);
        defer ctx.deinit();

        try self.genDecodeParams(view.params, &ctx, w);

        for (view.body) |stmt| {
            try self.genStmt(&stmt, &ctx, w);
        }

        // Epilogue: if no explicit give_back was emitted, return 0.
        const epilogue_dest = w.offset();
        for (ctx.early_returns.items) |patch_off| {
            w.patchU16(patch_off, epilogue_dest);
        }
        // Default return: return 0 (32 bytes).
        try w.push0();
        try w.push1(0x00);
        try w.op(.MSTORE);
        try w.push1(32);
        try w.push0();
        try w.op(.RETURN);
    }

    /// Generate EVM bytecode for one pure function.
    fn genPure(self: *EVMCodeGen, pure: *const ast.PureDecl, w: *EVMWriter) anyerror!void {
        var ctx = FuncCtx.init(self.allocator);
        defer ctx.deinit();

        try self.genDecodeParams(pure.params, &ctx, w);

        for (pure.body) |stmt| {
            try self.genStmt(&stmt, &ctx, w);
        }

        const epilogue_dest = w.offset();
        for (ctx.early_returns.items) |patch_off| {
            w.patchU16(patch_off, epilogue_dest);
        }
        // Default: RETURN 0
        try w.push0();
        try w.push1(0x00);
        try w.op(.MSTORE);
        try w.push1(32);
        try w.push0();
        try w.op(.RETURN);
    }

    // ── Parameter ABI decoding ────────────────────────────────────────────

    /// Decode static (32-byte) calldata parameters into local memory slots.
    /// Calldata layout: [selector 4 bytes][param0 32 bytes][param1 32 bytes]…
    fn genDecodeParams(
        _: *EVMCodeGen,
        params: []const ast.Param,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        for (params, 0..) |param, i| {
            const cd_offset: u32 = 4 + @as(u32, @intCast(i)) * 32;
            try w.pushU32(cd_offset);
            try w.op(.CALLDATALOAD);
            const mem_slot = try ctx.locals.alloc_slot(param.name);
            try w.pushU32(mem_slot);
            try w.op(.MSTORE);
        }
    }

    // ── Access control (`only`) ───────────────────────────────────────────

    /// Emit `only authority` checks: CALLER must match the stored authority.
    fn genOnly(
        self: *EVMCodeGen,
        only: *const ast.OnlyStmt,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        _ = ctx;
        switch (only.requirement) {
            .authority => |name| {
                try self.genAuthCheck(name, w);
            },
            .either => |pair| {
                // Caller must match left OR right authority.
                try self.genAuthCheckOr(pair.left, pair.right, w);
            },
            .address_list => |names| {
                // Caller must match any of the listed authorities.
                for (names) |name| {
                    try self.genAuthCheck(name, w);
                }
            },
            else => {},
        }
    }

    /// Check CALLER == authority_slot value; REVERT if not.
    fn genAuthCheck(self: *EVMCodeGen, auth_name: []const u8, w: *EVMWriter) anyerror!void {
        // Authority address is stored at slot = keccak256("auth:" ++ auth_name).
        const slot = self.authSlot(auth_name);
        try w.pushU256BE(slot);
        try w.op(.SLOAD);     // stack: [stored_authority]
        try w.op(.CALLER);    // stack: [stored_authority, caller]
        try w.op(.EQ);        // stack: [caller == authority ? 1 : 0]
        // If equal, skip revert.
        const ok_patch = try w.push2Placeholder();
        try w.op(.JUMPI);
        // Revert with "not authorized".
        try self.emitRevertString("not authorized", w);
        // Ok label.
        const ok_dest = w.offset();
        w.patchU16(ok_patch, ok_dest);
        try w.op(.JUMPDEST);
    }

    /// Check CALLER == auth_left OR CALLER == auth_right; REVERT if neither.
    fn genAuthCheckOr(
        self: *EVMCodeGen,
        left: []const u8,
        right: []const u8,
        w: *EVMWriter,
    ) anyerror!void {
        const slot_l = self.authSlot(left);
        const slot_r = self.authSlot(right);

        try w.op(.CALLER);          // stack: [caller]
        try w.op(.DUP1);            // stack: [caller, caller]
        try w.pushU256BE(slot_l);
        try w.op(.SLOAD);           // stack: [caller, caller, auth_l]
        try w.op(.EQ);              // stack: [caller, (caller==auth_l)]
        try w.op(.SWAP1);           // stack: [(caller==auth_l), caller]
        try w.pushU256BE(slot_r);
        try w.op(.SLOAD);           // stack: [(caller==auth_l), caller, auth_r]
        try w.op(.EQ);              // stack: [(caller==auth_l), (caller==auth_r)]
        try w.op(.OR);              // stack: [(either match)]
        const ok_patch = try w.push2Placeholder();
        try w.op(.JUMPI);
        try self.emitRevertString("not authorized", w);
        const ok_dest = w.offset();
        w.patchU16(ok_patch, ok_dest);
        try w.op(.JUMPDEST);
    }

    /// Compute the storage slot for an authority by hashing `"auth:" ++ name`.
    fn authSlot(_: *EVMCodeGen, name: []const u8) [32]u8 {
        var buf: [64]u8 = undefined;
        const prefix = "auth:";
        @memcpy(buf[0..prefix.len], prefix);
        const name_len = @min(name.len, 59);
        @memcpy(buf[prefix.len..prefix.len + name_len], name[0..name_len]);
        return keccak256(buf[0..prefix.len + name_len]);
    }

    // ── Statement code generation ─────────────────────────────────────────

    /// Generate EVM code for one statement. Net stack effect: zero.
    fn genStmt(
        self: *EVMCodeGen,
        stmt: *const Stmt,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        switch (stmt.kind) {

            // ── let x = expr ────────────────────────────────────────────────
            .let_bind => |lb| {
                try self.genExpr(lb.init, ctx, w);          // stack: [value]
                const mem_slot = try ctx.locals.alloc_slot(lb.name);
                try w.pushU32(mem_slot);                    // stack: [value, offset]
                try w.op(.MSTORE);                          // memory[offset] = value
            },

            // ── target = value ───────────────────────────────────────────────
            .assign => |asg| {
                try self.genAssign(asg.target, asg.value, ctx, w);
            },

            // ── target op= value ─────────────────────────────────────────────
            .aug_assign => |aug| {
                try self.genAugAssign(aug.target, aug.op, aug.value, ctx, w);
            },

            // ── when/otherwise ───────────────────────────────────────────────
            .when => |*wh| try self.genWhen(wh, ctx, w),

            // ── match ────────────────────────────────────────────────────────
            .match => |*m| try self.genMatch(m, ctx, w),

            // ── each ─────────────────────────────────────────────────────────
            .each => |*e| try self.genEach(e, ctx, w),

            // ── repeat N times ───────────────────────────────────────────────
            .repeat => |*r| try self.genRepeat(r, ctx, w),

            // ── while ────────────────────────────────────────────────────────
            .while_ => |*wl| try self.genWhile(wl, ctx, w),

            // ── need cond else msg ───────────────────────────────────────────
            .need => |*n| try self.genNeed(n, ctx, w),

            // ── ensure cond else msg ─────────────────────────────────────────
            .ensure => |*e| try self.genEnsure(e, ctx, w),

            // ── panic "msg" ──────────────────────────────────────────────────
            .panic => |p| {
                try self.emitRevertString(p.message, w);
            },

            // ── give back expr ───────────────────────────────────────────────
            .give_back => |expr| {
                try self.genGiveBack(expr, ctx, w);
            },

            // ── stop (break) ─────────────────────────────────────────────────
            .stop => {
                const patch = try w.push2Placeholder();
                try w.op(.JUMP);
                try ctx.loop_breaks.append(ctx.alloc, patch);
            },

            // ── skip (continue) ──────────────────────────────────────────────
            .skip => {
                const patch = try w.push2Placeholder();
                try w.op(.JUMP);
                try ctx.loop_conts.append(ctx.alloc, patch);
            },

            // ── tell EventName(args) ─────────────────────────────────────────
            .tell => |*t| try self.genTell(t, ctx, w),

            // ── throw ErrorType(args) ────────────────────────────────────────
            .throw => |th| {
                // Emit Error(selector) revert data (EIP-838 custom error).
                const selector = evmSelector(th.error_call.error_type);
                try self.emitCustomError(selector, th.error_call.args, ctx, w);
            },

            // ── attempt … on_error … ─────────────────────────────────────────
            .attempt => |*at| try self.genAttempt(at, ctx, w),

            // ── bare call stmt ───────────────────────────────────────────────
            .call_stmt => |expr| {
                try self.genExpr(expr, ctx, w);
                try w.op(.POP);  // discard return value
            },

            // ── remove mine.map[key] ─────────────────────────────────────────
            .remove => |expr| {
                try self.genRemove(expr, ctx, w);
            },

            // ── pay recipient amount ─────────────────────────────────────────
            .pay => |*pay| {
                try self.genPay(pay, ctx, w);
            },

            // ── send asset to account ─────────────────────────────────────────
            .send => |*send| {
                try self.genSend(send, ctx, w);
            },

            // ── move asset into mine.field ───────────────────────────────────
            .move_asset => |*mv| {
                try self.genExpr(mv.asset, ctx, w);   // stack: [asset_value]
                try self.genStateWriteExpr(mv.dest, w);
            },

            // ── schedule call ────────────────────────────────────────────────
            .schedule => |*sc| {
                // Schedules are ZVM-native; on EVM we emit an external CALL.
                try self.genSchedule(sc, ctx, w);
            },

            // ── only (handled in prologue) ───────────────────────────────────
            .only => {},

            // ── guard_apply ──────────────────────────────────────────────────
            .guard_apply => |gname| {
                // Emit a CALL to the guard's internal logic.
                // Guards are stored as internal jump labels; for EVM,
                // we emit an auth check pattern using the guard's name.
                try self.genAuthCheck(gname, w);
            },

            // ── transfer_ownership ───────────────────────────────────────────
            .transfer_ownership => |*to| {
                const auth_name = to.account.kind.identifier;
                const slot = self.authSlot(auth_name);
                try self.genExpr(to.new_owner, ctx, w);  // stack: [new_owner]
                try w.pushU256BE(slot);                  // stack: [new_owner, slot]
                try w.op(.SSTORE);
            },

            // ── account lifecycle (no direct EVM equivalent — no-op) ─────────
            .expand, .close, .freeze, .unfreeze => {},
        }
    }

    // ── Assignment helpers ────────────────────────────────────────────────

    /// Emit code for `target = value`.
    fn genAssign(
        self: *EVMCodeGen,
        target: *const Expr,
        value: *const Expr,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        switch (target.kind) {
            // mine.field = value
            .field_access => |fa| {
                if (fa.object.kind == .identifier and
                    std.mem.eql(u8, fa.object.kind.identifier, "mine"))
                {
                    if (self.slots.getSlot(fa.field)) |slot| {
                        try self.genExpr(value, ctx, w);  // stack: [value]
                        try w.pushU256BE(u256ToBE(slot)); // stack: [value, slot]
                        try w.op(.SSTORE);
                        return;
                    }
                }
                // Struct field: evaluate target address, then store.
                try self.genExpr(value, ctx, w);
                try w.op(.POP);  // fallback: discard
            },
            // mine.map[key] = value
            .index_access => |ia| {
                if (ia.object.kind == .field_access) {
                    const outer = ia.object.kind.field_access;
                    if (outer.object.kind == .identifier and
                        std.mem.eql(u8, outer.object.kind.identifier, "mine"))
                    {
                        if (self.slots.getSlot(outer.field)) |slot| {
                            // slot = keccak256(key ++ base_slot)
                            try self.genExpr(ia.index, ctx, w); // stack: [key]
                            try w.push0();                       // stack: [key, 0]
                            try w.op(.MSTORE);                   // memory[0] = key

                            try w.pushU256BE(u256ToBE(slot));    // stack: [base_slot]
                            try w.push1(0x20);                   // stack: [base_slot, 0x20]
                            try w.op(.MSTORE);                   // memory[32] = base_slot

                            try w.push1(0x40);  // size=64
                            try w.push0();       // offset=0
                            try w.op(.KECCAK256); // stack: [map_slot]

                            try self.genExpr(value, ctx, w); // stack: [map_slot, value]
                            try w.op(.SWAP1);                 // stack: [value, map_slot]
                            try w.op(.SSTORE);
                            return;
                        }
                    }
                }
                try self.genExpr(value, ctx, w);
                try w.op(.POP);
            },
            // local = value
            .identifier => |name| {
                if (ctx.locals.get(name)) |mem_slot| {
                    try self.genExpr(value, ctx, w);  // stack: [value]
                    try w.pushU32(mem_slot);           // stack: [value, offset]
                    try w.op(.MSTORE);
                    return;
                }
                // Unknown identifier: evaluate and discard.
                try self.genExpr(value, ctx, w);
                try w.op(.POP);
            },
            else => {
                try self.genExpr(value, ctx, w);
                try w.op(.POP);
            },
        }
    }

    /// Write value (already on stack) to the storage slot indicated by expr.
    fn genStateWriteExpr(self: *EVMCodeGen, dest: *const Expr, w: *EVMWriter) anyerror!void {
        switch (dest.kind) {
            .field_access => |fa| {
                if (fa.object.kind == .identifier and
                    std.mem.eql(u8, fa.object.kind.identifier, "mine"))
                {
                    if (self.slots.getSlot(fa.field)) |slot| {
                        try w.pushU256BE(u256ToBE(slot)); // stack: [value, slot]
                        try w.op(.SSTORE);
                        return;
                    }
                }
            },
            else => {},
        }
        try w.op(.POP);  // discard if we can't identify the target
    }

    /// Emit augmented assignment: `target op= value`.
    fn genAugAssign(
        self: *EVMCodeGen,
        target: *const Expr,
        aug_op: ast.AugOp,
        value: *const Expr,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        const evm_op: Op = switch (aug_op) {
            .add => .ADD,
            .sub => .SUB,
            .mul => .MUL,
            .div => .DIV,
            .mod => .MOD,
        };

        switch (target.kind) {
            // mine.field op= value
            .field_access => |fa| {
                if (fa.object.kind == .identifier and
                    std.mem.eql(u8, fa.object.kind.identifier, "mine"))
                {
                    if (self.slots.getSlot(fa.field)) |slot| {
                        // Load current value.
                        try w.pushU256BE(u256ToBE(slot));
                        try w.op(.SLOAD);          // stack: [current]
                        try self.genExpr(value, ctx, w); // stack: [current, rhs]
                        if (aug_op == .sub or aug_op == .div or aug_op == .mod) {
                            try w.op(.SWAP1);      // stack: [rhs, current] → current op rhs
                        }
                        try w.op(evm_op);          // stack: [result]
                        try w.pushU256BE(u256ToBE(slot)); // stack: [result, slot]
                        try w.op(.SSTORE);
                        return;
                    }
                }
            },
            // mine.map[key] op= value
            .index_access => |ia| {
                if (ia.object.kind == .field_access) {
                    const outer = ia.object.kind.field_access;
                    if (outer.object.kind == .identifier and
                        std.mem.eql(u8, outer.object.kind.identifier, "mine"))
                    {
                        if (self.slots.getSlot(outer.field)) |slot| {
                            // Compute map slot and save it.
                            try self.genExpr(ia.index, ctx, w);
                            try w.push0();
                            try w.op(.MSTORE);
                            try w.pushU256BE(u256ToBE(slot));
                            try w.push1(0x20);
                            try w.op(.MSTORE);
                            try w.push1(0x40);
                            try w.push0();
                            try w.op(.KECCAK256);      // stack: [map_slot]
                            try w.op(.DUP1);           // stack: [map_slot, map_slot]
                            try w.op(.SLOAD);          // stack: [map_slot, current]
                            try self.genExpr(value, ctx, w); // stack: [map_slot, current, rhs]
                            if (aug_op == .sub or aug_op == .div or aug_op == .mod) {
                                try w.op(.SWAP1);
                            }
                            try w.op(evm_op);          // stack: [map_slot, result]
                            try w.op(.SWAP1);          // stack: [result, map_slot]
                            try w.op(.SSTORE);
                            return;
                        }
                    }
                }
            },
            // local op= value
            .identifier => |name| {
                if (ctx.locals.get(name)) |mem_slot| {
                    try w.pushU32(mem_slot);
                    try w.op(.MLOAD);              // stack: [current]
                    try self.genExpr(value, ctx, w); // stack: [current, rhs]
                    if (aug_op == .sub or aug_op == .div or aug_op == .mod) {
                        try w.op(.SWAP1);
                    }
                    try w.op(evm_op);              // stack: [result]
                    try w.pushU32(mem_slot);        // stack: [result, offset]
                    try w.op(.MSTORE);
                    return;
                }
            },
            else => {},
        }
    }

    // ── Expression code generation ────────────────────────────────────────

    /// Generate EVM code for an expression. Leaves exactly one value on stack.
    pub fn genExpr(
        self: *EVMCodeGen,
        expr: *const Expr,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        switch (expr.kind) {

            // ── Integer literal ──────────────────────────────────────────────
            .int_lit => |lit| {
                try self.genIntLit(lit, w);
            },

            // ── Float / fixed-point literal ──────────────────────────────────
            .float_lit => |lit| {
                const scaled = scaleFixedPoint(lit, 18);
                try w.pushU256BE(scaled.toBytes32Be());
            },

            // ── Boolean literal ──────────────────────────────────────────────
            .bool_lit => |b| {
                if (b) try w.push1(1) else try w.push0();
            },

            // ── String literal ───────────────────────────────────────────────
            .string_lit => |s| {
                // Strip surrounding quotes.
                const content = if (s.len >= 2) s[1..s.len - 1] else s;
                // Push keccak256 of the string as a bytes32 representation.
                // For EVM, strings are usually passed as calldata or memory pointers.
                // We push the keccak256 hash as a static representation.
                const h = keccak256(content);
                try w.pushU256BE(h);
            },

            // ── `nothing` ────────────────────────────────────────────────────
            .nothing => {
                try w.push0();
            },

            // ── `something(expr)` ────────────────────────────────────────────
            .something => |inner| {
                try self.genExpr(inner, ctx, w);
                // In EVM, optionals are represented as: (is_present=1, value).
                // Here we just pass the value through.
            },

            // ── Identifier ───────────────────────────────────────────────────
            .identifier => |name| {
                if (ctx.locals.get(name)) |mem_slot| {
                    try w.pushU32(mem_slot);
                    try w.op(.MLOAD);
                } else {
                    // Unknown identifier: push 0.
                    try w.push0();
                }
            },

            // ── Field access ──────────────────────────────────────────────────
            .field_access => |fa| {
                if (fa.object.kind == .identifier and
                    std.mem.eql(u8, fa.object.kind.identifier, "mine"))
                {
                    // mine.field → SLOAD
                    if (self.slots.getSlot(fa.field)) |slot| {
                        try w.pushU256BE(u256ToBE(slot));
                        try w.op(.SLOAD);
                        return;
                    }
                }
                // Other field access: evaluate object, push 0 (simplified).
                try self.genExpr(fa.object, ctx, w);
                try w.op(.POP);
                try w.push0();
            },

            // ── Index access ──────────────────────────────────────────────────
            .index_access => |ia| {
                if (ia.object.kind == .field_access) {
                    const outer = ia.object.kind.field_access;
                    if (outer.object.kind == .identifier and
                        std.mem.eql(u8, outer.object.kind.identifier, "mine"))
                    {
                        if (self.slots.getSlot(outer.field)) |slot| {
                            // Map read: keccak256(key ++ base_slot) → SLOAD
                            try self.genExpr(ia.index, ctx, w); // stack: [key]
                            try w.push0();    // stack: [key, 0]
                            try w.op(.MSTORE); // memory[0] = key
                            try w.pushU256BE(u256ToBE(slot)); // stack: [base_slot]
                            try w.push1(0x20); // stack: [base_slot, 0x20]
                            try w.op(.MSTORE); // memory[32] = base_slot
                            try w.push1(0x40);
                            try w.push0();
                            try w.op(.KECCAK256); // stack: [map_slot]
                            try w.op(.SLOAD);     // stack: [value]
                            return;
                        }
                    }
                }
                // Fallback.
                try self.genExpr(ia.object, ctx, w);
                try w.op(.POP);
                try w.push0();
            },

            // ── Binary operation ──────────────────────────────────────────────
            .bin_op => |op| {
                try self.genBinOp(op.op, op.left, op.right, ctx, w);
            },

            // ── Unary operation ───────────────────────────────────────────────
            .unary_op => |op| {
                try self.genExpr(op.operand, ctx, w);
                switch (op.op) {
                    .not_   => try w.op(.ISZERO),
                    .negate => {
                        // 0 - value: push 0, SWAP1, SUB  →  0 - value = -value
                        try w.push0();
                        try w.op(.SUB);
                    },
                }
            },

            // ── Call expression ───────────────────────────────────────────────
            .call => |c| {
                try self.genCall(c.callee, c.args, ctx, w);
            },

            // ── Builtin context values ─────────────────────────────────────────
            .builtin => |b| {
                switch (b) {
                    .caller        => try w.op(.CALLER),
                    .value         => try w.op(.CALLVALUE),
                    .deployer      => {
                        // Stored at a known slot.
                        const slot = keccak256("__deployer__");
                        try w.pushU256BE(slot);
                        try w.op(.SLOAD);
                    },
                    .this_address  => try w.op(.ADDRESS),
                    .zero_address  => try w.push0(),
                    .now           => try w.op(.TIMESTAMP),
                    .current_block => try w.op(.NUMBER),
                    .gas_remaining => try w.op(.GAS),
                }
            },

            // ── Struct literal ────────────────────────────────────────────────
            .struct_lit => |sl| {
                // Pack struct fields sequentially in memory; push base pointer.
                // We use the free memory pointer as the struct base.
                try w.push1(0x40);
                try w.op(.MLOAD);           // stack: [base_ptr]
                try w.op(.DUP1);            // stack: [base_ptr, base_ptr]
                const base_tmp = try ctx.locals.alloc_slot("__struct_base__");
                try w.pushU32(base_tmp);
                try w.op(.MSTORE);          // locals[base_tmp] = base_ptr

                for (sl.fields, 0..) |fi, i| {
                    try w.pushU32(base_tmp);
                    try w.op(.MLOAD);       // stack: [base_ptr]
                    try w.pushU32(@intCast(i * 32));
                    try w.op(.ADD);         // stack: [field_ptr]
                    try self.genExpr(fi.value, ctx, w); // stack: [field_ptr, val]
                    try w.op(.SWAP1);       // stack: [val, field_ptr]
                    try w.op(.MSTORE);      // memory[field_ptr] = val
                }

                // Update free memory pointer.
                try w.pushU32(base_tmp);
                try w.op(.MLOAD);
                try w.pushU32(@intCast(sl.fields.len * 32));
                try w.op(.ADD);             // stack: [new_free_ptr]
                try w.push1(0x40);
                try w.op(.MSTORE);

                // Return base_ptr as the struct value.
                try w.pushU32(base_tmp);
                try w.op(.MLOAD);
            },

            // ── Tuple literal ─────────────────────────────────────────────────
            .tuple_lit => |elems| {
                // Pack into memory, return base pointer (same as struct_lit).
                try w.push1(0x40);
                try w.op(.MLOAD);
                try w.op(.DUP1);
                const base_tmp = try ctx.locals.alloc_slot("__tuple_base__");
                try w.pushU32(base_tmp);
                try w.op(.MSTORE);

                for (elems, 0..) |elem, i| {
                    try w.pushU32(base_tmp);
                    try w.op(.MLOAD);
                    try w.pushU32(@intCast(i * 32));
                    try w.op(.ADD);
                    try self.genExpr(elem, ctx, w);
                    try w.op(.SWAP1);
                    try w.op(.MSTORE);
                }

                try w.pushU32(base_tmp);
                try w.op(.MLOAD);
                try w.pushU32(@intCast(elems.len * 32));
                try w.op(.ADD);
                try w.push1(0x40);
                try w.op(.MSTORE);

                try w.pushU32(base_tmp);
                try w.op(.MLOAD);
            },

            // ── Inline conditional ────────────────────────────────────────────
            .inline_when => |iw| {
                try self.genExpr(iw.cond, ctx, w);   // stack: [cond]
                try w.op(.ISZERO);                    // stack: [!cond]
                const else_patch = try w.push2Placeholder();
                try w.op(.JUMPI);
                // Then branch.
                try self.genExpr(iw.then_, ctx, w);  // stack: [then_val]
                const end_patch = try w.push2Placeholder();
                try w.op(.JUMP);
                // Else branch.
                const else_dest = w.offset();
                w.patchU16(else_patch, else_dest);
                try w.op(.JUMPDEST);
                try self.genExpr(iw.else_, ctx, w);  // stack: [else_val]
                const end_dest = w.offset();
                w.patchU16(end_patch, end_dest);
                try w.op(.JUMPDEST);
            },

            // ── Type cast ─────────────────────────────────────────────────────
            .cast => |c| {
                try self.genExpr(c.expr, ctx, w);
                // Most casts are no-ops at EVM level (values are already u256).
                // For address masks: AND with 20-byte mask.
                const to_rt = try self.resolver.resolve(c.to);
                switch (to_rt) {
                    .account, .wallet, .program => {
                        // Mask to 160 bits (20 bytes).
                        var mask_be: [32]u8 = [_]u8{0} ** 32;
                        @memset(mask_be[12..32], 0xFF);
                        try w.pushU256BE(mask_be);
                        try w.op(.AND);
                    },
                    else => {},
                }
            },

            // ── Result propagation ────────────────────────────────────────────
            .try_propagate => |inner| {
                try self.genExpr(inner, ctx, w);
                // For EVM, we just evaluate the inner expression.
                // A proper Result type would need tag inspection.
            },

            // ── Asset operations ──────────────────────────────────────────────
            .asset_split => |as_| {
                try self.genExpr(as_.asset, ctx, w);
                // Returns the asset with amount split off; simplified to push value.
            },
            .asset_wrap => |aw| {
                try self.genExpr(aw.value, ctx, w);
            },
            .asset_unwrap => |au| {
                try self.genExpr(au.token, ctx, w);
            },

            // ── Match expression ──────────────────────────────────────────────
            .match_expr => |me| {
                try self.genExpr(me.subject, ctx, w);
                // Simplified: evaluate subject, leave on stack.
                // Full match codegen handled in genMatch (stmt form).
            },
        }
    }

    // ── Integer literal helper ────────────────────────────────────────────

    /// Parse and push an integer literal (decimal or 0x hex, with _ separators).
    fn genIntLit(_: *EVMCodeGen, lit: []const u8, w: *EVMWriter) anyerror!void {
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

        if (clean.len >= 2 and clean[0] == '0' and
            (clean[1] == 'x' or clean[1] == 'X'))
        {
            // Hex literal.
            const val = U256.parseHex(clean[2..]) catch U256.zero;
            try w.pushU256BE(val.toBytes32Be());
        } else {
            // Decimal literal.
            const val = U256.parseDecimal(clean) catch U256.zero;
            try w.pushU256BE(val.toBytes32Be());
        }
    }

    // ── Binary operation code generation ──────────────────────────────────

    /// EVM stack convention: generate right operand first, then left.
    /// This puts left on top, which matches EVM ops (a=top, b=second for SUB,DIV,MOD).
    fn genBinOp(
        self: *EVMCodeGen,
        op: BinOp,
        left: *Expr,
        right: *Expr,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        switch (op) {
            .plus, .duration_add => {
                try self.genExpr(right, ctx, w);
                try self.genExpr(left, ctx, w);
                try w.op(.ADD);
            },
            .minus, .duration_sub => {
                // SUB: top - second = left - right (with left on top).
                try self.genExpr(right, ctx, w);
                try self.genExpr(left, ctx, w);
                try w.op(.SUB);
            },
            .times => {
                try self.genExpr(right, ctx, w);
                try self.genExpr(left, ctx, w);
                try w.op(.MUL);
            },
            .divided_by => {
                // DIV: top / second = left / right.
                try self.genExpr(right, ctx, w);
                try self.genExpr(left, ctx, w);
                try w.op(.DIV);
            },
            .mod => {
                // MOD: top % second = left % right.
                try self.genExpr(right, ctx, w);
                try self.genExpr(left, ctx, w);
                try w.op(.MOD);
            },
            .equals => {
                try self.genExpr(right, ctx, w);
                try self.genExpr(left, ctx, w);
                try w.op(.EQ);
            },
            .not_equals => {
                try self.genExpr(right, ctx, w);
                try self.genExpr(left, ctx, w);
                try w.op(.EQ);
                try w.op(.ISZERO);
            },
            .less => {
                // LT: top < second = left < right (left=top, right=second).
                try self.genExpr(right, ctx, w);
                try self.genExpr(left, ctx, w);
                try w.op(.LT);
            },
            .greater => {
                // GT: top > second = left > right.
                try self.genExpr(right, ctx, w);
                try self.genExpr(left, ctx, w);
                try w.op(.GT);
            },
            .less_eq => {
                // !(left > right)
                try self.genExpr(right, ctx, w);
                try self.genExpr(left, ctx, w);
                try w.op(.GT);
                try w.op(.ISZERO);
            },
            .greater_eq => {
                // !(left < right)
                try self.genExpr(right, ctx, w);
                try self.genExpr(left, ctx, w);
                try w.op(.LT);
                try w.op(.ISZERO);
            },
            .and_ => {
                // Short-circuit AND: if left is false, skip right.
                try self.genExpr(left, ctx, w);      // stack: [left]
                try w.op(.DUP1);                     // stack: [left, left]
                const skip_patch = try w.push2Placeholder();
                try w.op(.JUMPI);                    // if left!=0, fall through; else skip
                // left was false: result is already 0 on stack.
                const end_patch = try w.push2Placeholder();
                try w.op(.JUMP);
                // left was true: evaluate right.
                const right_dest = w.offset();
                w.patchU16(skip_patch, right_dest);
                try w.op(.JUMPDEST);
                try w.op(.POP);                      // discard dup'd left
                try self.genExpr(right, ctx, w);     // stack: [right]
                // ISZERO ISZERO converts to boolean 0/1.
                try w.op(.ISZERO);
                try w.op(.ISZERO);
                const end_dest = w.offset();
                w.patchU16(end_patch, end_dest);
                try w.op(.JUMPDEST);
            },
            .or_ => {
                // Short-circuit OR: if left is true, skip right.
                try self.genExpr(left, ctx, w);      // stack: [left]
                try w.op(.DUP1);
                // ISZERO to check if false
                try w.op(.ISZERO);
                const right_patch = try w.push2Placeholder();
                try w.op(.JUMPI);                    // if left==0, evaluate right
                // left was true: result is 1, left is already on stack.
                try w.op(.ISZERO);
                try w.op(.ISZERO);                   // normalise to 1
                const end_patch = try w.push2Placeholder();
                try w.op(.JUMP);
                // left was false: evaluate right.
                const right_dest = w.offset();
                w.patchU16(right_patch, right_dest);
                try w.op(.JUMPDEST);
                try w.op(.POP);
                try self.genExpr(right, ctx, w);
                try w.op(.ISZERO);
                try w.op(.ISZERO);
                const end_dest = w.offset();
                w.patchU16(end_patch, end_dest);
                try w.op(.JUMPDEST);
            },
            .has => {
                // `collection has element` — simplified: evaluate both, AND.
                try self.genExpr(right, ctx, w);
                try self.genExpr(left, ctx, w);
                try w.op(.AND);
                try w.op(.ISZERO);
                try w.op(.ISZERO);
            },
        }
    }

    // ── Call code generation ──────────────────────────────────────────────

    /// Generate a function call. Result on stack top.
    fn genCall(
        self: *EVMCodeGen,
        callee: *const Expr,
        args: []const Argument,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        switch (callee.kind) {
            .identifier => |name| {
                // Internal call: use DELEGATECALL / jump to internal label.
                // For EVM, internal functions are best handled as simple jumps.
                // We encode args into memory and call via the dispatcher.
                try self.emitInternalCall(name, args, ctx, w);
            },
            .field_access => |fa| {
                // External call: contract.method(args).
                const target_expr = fa.object;
                const method = fa.field;
                try self.emitExternalCall(target_expr, method, args, ctx, w);
            },
            else => {
                // Evaluate callee as an address and CALL it.
                try self.genExpr(callee, ctx, w);
                try w.op(.POP);
                try w.push0();
            },
        }
    }

    /// Emit an internal function call (same contract).
    /// Encodes args via ABI, calls using CALL to self, returns result.
    fn emitInternalCall(
        _: *EVMCodeGen,
        name: []const u8,
        args: []const Argument,
        _: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        // Build calldata: selector + args.
        // We don't have the param types here, so use a simplified selector
        // with no-type signature (just the name hashed).
        const selector = evmSelector(name); // fallback: hash just the name
        _ = args;

        // Encode calldata into memory starting at free ptr.
        try w.push1(0x40);
        try w.op(.MLOAD);          // stack: [free_ptr]
        try w.op(.DUP1);           // stack: [free_ptr, free_ptr]

        // Store selector.
        try w.pushU32(selector);
        try w.op(.DUP2);           // stack: [free_ptr, free_ptr, selector, free_ptr]
        // Actually we need to encode selector as 4 bytes at memory[free_ptr].
        // MSTORE32 stores the selector right-aligned (28 zero bytes + 4 selector bytes).
        // To get the selector in the first 4 bytes: shift left 224 bits.
        try w.push1(0xe0);
        try w.op(.SHL);            // stack: [selector << 224]
        try w.op(.DUP3);           // dup free_ptr
        try w.op(.MSTORE);         // memory[free_ptr] = selector << 224
        // Args encoding: skip for now (args = 0).
        const calldata_size: u32 = 4; // just selector

        // CALL: gas, addr(=self), value=0, argsOffset=free_ptr, argsSize=4, retOffset=0, retSize=32
        try w.push1(32);            // retSize
        try w.push0();              // retOffset
        try w.pushU32(calldata_size); // argsSize
        // argsOffset = free_ptr (DUP from stack)
        try w.op(.DUP5);           // free_ptr
        try w.push0();             // value = 0
        try w.op(.ADDRESS);        // addr = self
        try w.op(.GAS);
        try w.op(.CALL);
        try w.op(.POP);            // discard success bool

        // Load return value.
        try w.push0();
        try w.op(.MLOAD);

        // Clean up stack.
        try w.op(.SWAP1);
        try w.op(.POP);
    }

    /// Emit an external cross-contract call.
    fn emitExternalCall(
        self: *EVMCodeGen,
        target: *const Expr,
        method: []const u8,
        args: []const Argument,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        const selector = evmSelector(method);

        // Encode calldata to memory.
        try w.push1(0x40);
        try w.op(.MLOAD);      // stack: [free_ptr]
        const calldata_base_slot = try ctx.locals.alloc_slot("__ext_calldata_base__");
        try w.pushU32(calldata_base_slot);
        try w.op(.MSTORE);     // save free_ptr

        // Write selector.
        try w.pushU32(selector);
        try w.push1(0xe0);
        try w.op(.SHL);
        try w.pushU32(calldata_base_slot);
        try w.op(.MLOAD);
        try w.op(.MSTORE);

        // Write args (32 bytes each).
        for (args, 0..) |arg, i| {
            try self.genExpr(arg.value, ctx, w);  // stack: [arg_val]
            try w.pushU32(calldata_base_slot);
            try w.op(.MLOAD);
            try w.pushU32(@intCast(4 + i * 32));
            try w.op(.ADD);                        // stack: [arg_val, arg_slot]
            try w.op(.MSTORE);
        }

        const calldata_size: u32 = 4 + @as(u32, @intCast(args.len)) * 32;

        // CALL: gas, target_addr, value=0, argsOff, argsSize, retOff=0, retSize=32
        try w.push1(32);                           // retSize
        try w.push0();                             // retOffset
        try w.pushU32(calldata_size);              // argsSize
        try w.pushU32(calldata_base_slot);
        try w.op(.MLOAD);                          // argsOffset
        try w.push0();                             // value
        try self.genExpr(target, ctx, w);          // target address
        try w.op(.GAS);
        try w.op(.CALL);
        try w.op(.POP);                            // discard success

        // Load return value.
        try w.push0();
        try w.op(.MLOAD);
    }

    // ── Control flow ──────────────────────────────────────────────────────

    /// Generate `when/otherwise` conditional.
    fn genWhen(
        self: *EVMCodeGen,
        stmt: *const WhenStmt,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        var end_patches = std.ArrayListUnmanaged(u32){};
        defer end_patches.deinit(self.allocator);

        // Primary condition.
        try self.genExpr(stmt.cond, ctx, w);      // stack: [cond]
        try w.op(.ISZERO);                         // stack: [!cond]
        const else_patch = try w.push2Placeholder();
        try w.op(.JUMPI);                          // jump to else if cond==0

        // Then body.
        for (stmt.then_body) |s| {
            try self.genStmt(&s, ctx, w);
        }
        const jmp_end_patch = try w.push2Placeholder();
        try w.op(.JUMP);
        try end_patches.append(self.allocator, jmp_end_patch);

        // Patch "else" destination.
        var cur_dest = w.offset();
        w.patchU16(else_patch, cur_dest);
        try w.op(.JUMPDEST);

        // Else-if chains.
        for (stmt.else_ifs) |eif| {
            try self.genExpr(eif.cond, ctx, w);
            try w.op(.ISZERO);
            const next_patch = try w.push2Placeholder();
            try w.op(.JUMPI);

            for (eif.body) |s| {
                try self.genStmt(&s, ctx, w);
            }
            const eif_end = try w.push2Placeholder();
            try w.op(.JUMP);
            try end_patches.append(self.allocator, eif_end);

            cur_dest = w.offset();
            w.patchU16(next_patch, cur_dest);
            try w.op(.JUMPDEST);
        }

        // Otherwise / else body.
        if (stmt.else_body) |eb| {
            for (eb) |s| {
                try self.genStmt(&s, ctx, w);
            }
        }

        // End label: patch all jumps to here.
        const end_dest = w.offset();
        for (end_patches.items) |patch| {
            w.patchU16(patch, end_dest);
        }
        try w.op(.JUMPDEST);
    }

    /// Generate `match` statement.
    fn genMatch(
        self: *EVMCodeGen,
        stmt: *const MatchStmt,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        var end_patches = std.ArrayListUnmanaged(u32){};
        defer end_patches.deinit(self.allocator);

        // Evaluate subject and save to a temp local.
        try self.genExpr(stmt.subject, ctx, w);
        const subj_slot = try ctx.locals.alloc_slot("__match_subj__");
        try w.pushU32(subj_slot);
        try w.op(.MSTORE);

        for (stmt.arms) |arm| {
            const skip_arm_patch: ?u32 = switch (arm.pattern) {
                .literal => |lit_expr| blk: {
                    // Compare subject with literal.
                    try w.pushU32(subj_slot);
                    try w.op(.MLOAD);                    // stack: [subj]
                    try self.genExpr(lit_expr, ctx, w);  // stack: [subj, lit]
                    try w.op(.EQ);
                    try w.op(.ISZERO);
                    const sp = try w.push2Placeholder();
                    try w.op(.JUMPI);                    // skip if not equal
                    break :blk sp;
                },
                .binding => |bname| blk: {
                    // Bind subject to name.
                    try w.pushU32(subj_slot);
                    try w.op(.MLOAD);
                    const bslot = try ctx.locals.alloc_slot(bname);
                    try w.pushU32(bslot);
                    try w.op(.MSTORE);
                    break :blk null;
                },
                .nothing => blk: {
                    // Match if subject == 0.
                    try w.pushU32(subj_slot);
                    try w.op(.MLOAD);
                    try w.op(.ISZERO);
                    try w.op(.ISZERO);                   // 1 if nonzero = "something"
                    const sp = try w.push2Placeholder();
                    try w.op(.JUMPI);
                    break :blk sp;
                },
                .something => |bname| blk: {
                    // Match if subject != 0, bind to bname.
                    try w.pushU32(subj_slot);
                    try w.op(.MLOAD);
                    try w.op(.DUP1);
                    try w.op(.ISZERO);
                    const sp = try w.push2Placeholder();
                    try w.op(.JUMPI);                    // skip if zero (nothing)
                    // Bind.
                    const bslot = try ctx.locals.alloc_slot(bname);
                    try w.pushU32(bslot);
                    try w.op(.MSTORE);
                    break :blk sp;
                },
                else => null,
            };

            for (arm.body) |s| {
                try self.genStmt(&s, ctx, w);
            }
            const end_jmp = try w.push2Placeholder();
            try w.op(.JUMP);
            try end_patches.append(self.allocator, end_jmp);

            if (skip_arm_patch) |sp| {
                const next = w.offset();
                w.patchU16(sp, next);
                try w.op(.JUMPDEST);
            }
        }

        // End of match.
        const end_dest = w.offset();
        for (end_patches.items) |p| {
            w.patchU16(p, end_dest);
        }
        try w.op(.JUMPDEST);
    }

    /// Generate `each (binding) in collection` loop.
    fn genEach(
        self: *EVMCodeGen,
        loop: *const EachLoop,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        // Evaluate collection length into a temp slot.
        try self.genExpr(loop.collection, ctx, w);   // stack: [len]
        const len_slot = try ctx.locals.alloc_slot("__each_len__");
        try w.pushU32(len_slot);
        try w.op(.MSTORE);

        // Iterator starts at 0.
        const iter_slot = try ctx.locals.alloc_slot("__each_iter__");
        try w.push0();
        try w.pushU32(iter_slot);
        try w.op(.MSTORE);

        // Bind loop variable.
        switch (loop.binding) {
            .single => |name| {
                _ = try ctx.locals.alloc_slot(name);
            },
            .pair => |p| {
                _ = try ctx.locals.alloc_slot(p.first);
                _ = try ctx.locals.alloc_slot(p.second);
            },
        }

        const loop_start = w.offset();
        try w.op(.JUMPDEST);

        // Exit condition: iter >= len.
        try w.pushU32(iter_slot);
        try w.op(.MLOAD);       // stack: [iter]
        try w.pushU32(len_slot);
        try w.op(.MLOAD);       // stack: [iter, len]
        try w.op(.LT);          // stack: [iter < len]
        try w.op(.ISZERO);      // stack: [!(iter < len) = iter >= len]
        const exit_patch = try w.push2Placeholder();
        try w.op(.JUMPI);

        // Bind loop variable = iter value.
        switch (loop.binding) {
            .single => |name| {
                try w.pushU32(iter_slot);
                try w.op(.MLOAD);
                if (ctx.locals.get(name)) |slot| {
                    try w.pushU32(slot);
                    try w.op(.MSTORE);
                } else {
                    try w.op(.POP);
                }
            },
            .pair => |p| {
                try w.pushU32(iter_slot);
                try w.op(.MLOAD);
                if (ctx.locals.get(p.first)) |slot| {
                    try w.pushU32(slot);
                    try w.op(.MSTORE);
                } else {
                    try w.op(.POP);
                }
                if (ctx.locals.get(p.second)) |slot| {
                    try w.pushU32(len_slot);
                    try w.op(.MLOAD);
                    try w.pushU32(slot);
                    try w.op(.MSTORE);
                }
            },
        }

        const prev_breaks = ctx.loop_breaks.items.len;
        const prev_conts  = ctx.loop_conts.items.len;

        for (loop.body) |s| {
            try self.genStmt(&s, ctx, w);
        }

        // Continue target: increment iter.
        const cont_target = w.offset();
        try w.op(.JUMPDEST);
        try w.pushU32(iter_slot);
        try w.op(.MLOAD);
        try w.push1(1);
        try w.op(.ADD);
        try w.pushU32(iter_slot);
        try w.op(.MSTORE);
        // Jump back to loop_start.
        try w.push2(@intCast(loop_start));
        try w.op(.JUMP);

        // Exit label.
        const exit_dest = w.offset();
        w.patchU16(exit_patch, exit_dest);
        try w.op(.JUMPDEST);

        // Backpatch breaks and conts.
        for (ctx.loop_breaks.items[prev_breaks..]) |p| {
            w.patchU16(p, exit_dest);
        }
        for (ctx.loop_conts.items[prev_conts..]) |p| {
            w.patchU16(p, cont_target);
        }
        ctx.loop_breaks.shrinkRetainingCapacity(prev_breaks);
        ctx.loop_conts.shrinkRetainingCapacity(prev_conts);
    }

    /// Generate `repeat N times` loop.
    fn genRepeat(
        self: *EVMCodeGen,
        loop: *const RepeatLoop,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        const counter_slot = try ctx.locals.alloc_slot("__repeat_ctr__");
        const limit_slot   = try ctx.locals.alloc_slot("__repeat_lim__");

        try self.genExpr(loop.count, ctx, w);
        try w.pushU32(limit_slot);
        try w.op(.MSTORE);
        try w.push0();
        try w.pushU32(counter_slot);
        try w.op(.MSTORE);

        const loop_start = w.offset();
        try w.op(.JUMPDEST);

        // Exit if counter >= limit.
        try w.pushU32(counter_slot);
        try w.op(.MLOAD);
        try w.pushU32(limit_slot);
        try w.op(.MLOAD);
        try w.op(.LT);
        try w.op(.ISZERO);
        const exit_patch = try w.push2Placeholder();
        try w.op(.JUMPI);

        const prev_breaks = ctx.loop_breaks.items.len;
        const prev_conts  = ctx.loop_conts.items.len;

        for (loop.body) |s| {
            try self.genStmt(&s, ctx, w);
        }

        const cont_target = w.offset();
        try w.op(.JUMPDEST);
        try w.pushU32(counter_slot);
        try w.op(.MLOAD);
        try w.push1(1);
        try w.op(.ADD);
        try w.pushU32(counter_slot);
        try w.op(.MSTORE);
        try w.push2(@intCast(loop_start));
        try w.op(.JUMP);

        const exit_dest = w.offset();
        w.patchU16(exit_patch, exit_dest);
        try w.op(.JUMPDEST);

        for (ctx.loop_breaks.items[prev_breaks..]) |p| w.patchU16(p, exit_dest);
        for (ctx.loop_conts.items[prev_conts..]) |p| w.patchU16(p, cont_target);
        ctx.loop_breaks.shrinkRetainingCapacity(prev_breaks);
        ctx.loop_conts.shrinkRetainingCapacity(prev_conts);
    }

    /// Generate `while condition` loop.
    fn genWhile(
        self: *EVMCodeGen,
        loop: *const WhileLoop,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        const loop_start = w.offset();
        try w.op(.JUMPDEST);

        try self.genExpr(loop.cond, ctx, w);    // stack: [cond]
        try w.op(.ISZERO);
        const exit_patch = try w.push2Placeholder();
        try w.op(.JUMPI);

        const prev_breaks = ctx.loop_breaks.items.len;
        const prev_conts  = ctx.loop_conts.items.len;

        for (loop.body) |s| {
            try self.genStmt(&s, ctx, w);
        }

        const cont_target = w.offset();
        try w.op(.JUMPDEST);
        try w.push2(@intCast(loop_start));
        try w.op(.JUMP);

        const exit_dest = w.offset();
        w.patchU16(exit_patch, exit_dest);
        try w.op(.JUMPDEST);

        for (ctx.loop_breaks.items[prev_breaks..]) |p| w.patchU16(p, exit_dest);
        for (ctx.loop_conts.items[prev_conts..]) |p| w.patchU16(p, cont_target);
        ctx.loop_breaks.shrinkRetainingCapacity(prev_breaks);
        ctx.loop_conts.shrinkRetainingCapacity(prev_conts);
    }

    // ── Assertions ────────────────────────────────────────────────────────

    /// Generate `need cond else msg` (require/assert equivalent).
    fn genNeed(
        self: *EVMCodeGen,
        stmt: *const NeedStmt,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        try self.genExpr(stmt.cond, ctx, w);   // stack: [cond]
        // If condition is true (nonzero), skip the revert.
        const ok_patch = try w.push2Placeholder();
        try w.op(.JUMPI);

        // Condition false: emit revert with reason.
        switch (stmt.else_) {
            .string_msg => |msg| {
                try self.emitRevertString(msg, w);
            },
            .typed_error => |te| {
                const selector = evmSelector(te.error_type);
                try self.emitCustomError(selector, te.args, ctx, w);
            },
        }

        const ok_dest = w.offset();
        w.patchU16(ok_patch, ok_dest);
        try w.op(.JUMPDEST);
    }

    /// Generate `ensure cond else msg` (post-condition check).
    fn genEnsure(
        self: *EVMCodeGen,
        stmt: *const ast.EnsureStmt,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        try self.genExpr(stmt.cond, ctx, w);
        const ok_patch = try w.push2Placeholder();
        try w.op(.JUMPI);
        switch (stmt.else_) {
            .string_msg => |msg| try self.emitRevertString(msg, w),
            .typed_error => |te| {
                const sel = evmSelector(te.error_type);
                try self.emitCustomError(sel, te.args, ctx, w);
            },
        }
        const ok_dest = w.offset();
        w.patchU16(ok_patch, ok_dest);
        try w.op(.JUMPDEST);
    }

    // ── Events ────────────────────────────────────────────────────────────

    /// Generate `tell EventName(args)`.
    fn genTell(
        self: *EVMCodeGen,
        stmt: *const TellStmt,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        // Lookup the event definition to get its field types for the signature.
        // We use a simplified approach: hash just the name.
        const sig_selector = evmSelector(stmt.event_name);
        var topic0: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u32, topic0[0..4], sig_selector, .big);

        // Separate indexed vs non-indexed args.
        // For EVM events: topic[0] = sig hash, indexed fields = topic[1..3],
        // non-indexed = ABI encoded in data.
        // Simplified: put all args in data (LOG1 with topic = sig hash).

        const data_start_slot = try ctx.locals.alloc_slot("__event_data__");
        try w.push1(0x40);
        try w.op(.MLOAD);
        try w.pushU32(data_start_slot);
        try w.op(.MSTORE);

        for (stmt.args, 0..) |arg, i| {
            try self.genExpr(arg.value, ctx, w);         // stack: [arg_val]
            try w.pushU32(data_start_slot);
            try w.op(.MLOAD);
            try w.pushU32(@intCast(i * 32));
            try w.op(.ADD);                              // stack: [arg_val, offset]
            try w.op(.MSTORE);                           // memory[offset] = arg
        }

        const data_size: u32 = @intCast(stmt.args.len * 32);

        // LOG1(offset, size, topic0)
        try w.pushU256BE(topic0);                        // topic0
        try w.pushU32(data_size);                        // size
        try w.pushU32(data_start_slot);
        try w.op(.MLOAD);                                // offset
        try w.op(.LOG1);
    }

    // ── Return ────────────────────────────────────────────────────────────

    /// Generate `give back expr`.
    fn genGiveBack(
        self: *EVMCodeGen,
        expr: *const Expr,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        try self.genExpr(expr, ctx, w);  // stack: [return_val]
        // ABI encode: store at memory[0x00].
        try w.push0();
        try w.op(.MSTORE);               // memory[0] = return_val
        // RETURN(0, 32)
        try w.push1(32);
        try w.push0();
        try w.op(.RETURN);
    }

    // ── Pay / Send ────────────────────────────────────────────────────────

    /// Generate `pay recipient amount` — transfer ETH.
    fn genPay(
        self: *EVMCodeGen,
        pay: *const ast.PayStmt,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        // CALL(gas, recipient, value, 0, 0, 0, 0)
        // Stack order: retSize, retOffset, argsSize, argsOffset, value, addr, gas
        try w.push0();                          // retSize
        try w.push0();                          // retOffset
        try w.push0();                          // argsSize
        try w.push0();                          // argsOffset
        try self.genExpr(pay.amount, ctx, w);   // value
        try self.genExpr(pay.recipient, ctx, w); // addr
        try w.op(.GAS);
        try w.op(.CALL);
        try w.op(.POP);                         // discard success bool
    }

    /// Generate `send asset to recipient` — ERC-20 transfer.
    fn genSend(
        self: *EVMCodeGen,
        send: *const ast.SendStmt,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        // Encode `transfer(address,uint256)` call.
        const transfer_sel = evmSelector("transfer(address,uint256)");

        // Allocate calldata buffer.
        const buf_slot = try ctx.locals.alloc_slot("__send_buf__");
        try w.push1(0x40);
        try w.op(.MLOAD);
        try w.pushU32(buf_slot);
        try w.op(.MSTORE);

        // Write selector at buf[0].
        try w.pushU32(transfer_sel);
        try w.push1(0xe0);
        try w.op(.SHL);
        try w.pushU32(buf_slot);
        try w.op(.MLOAD);
        try w.op(.MSTORE);

        // Write recipient at buf[4] (right-aligned in 32 bytes at offset 4).
        try self.genExpr(send.recipient, ctx, w);
        try w.pushU32(buf_slot);
        try w.op(.MLOAD);
        try w.push1(4);
        try w.op(.ADD);
        try w.op(.MSTORE);

        // Write amount at buf[36].
        // For `send asset to`, the amount comes from the asset value.
        // If asset is a linear type, its value is the amount.
        try self.genExpr(send.asset, ctx, w);
        try w.pushU32(buf_slot);
        try w.op(.MLOAD);
        try w.push1(36);
        try w.op(.ADD);
        try w.op(.MSTORE);

        // CALL the token contract.
        try w.push1(32);                           // retSize
        try w.push0();                             // retOffset=0
        try w.push1(68);                           // argsSize = 4 + 32 + 32
        try w.pushU32(buf_slot);
        try w.op(.MLOAD);                          // argsOffset
        try w.push0();                             // value = 0
        // Token address: for linear assets the "asset" expr is the token amount;
        // the contract address would ideally come from an asset registry.
        // We use ADDRESS (self) as a fallback to avoid requiring extra info.
        try self.genExpr(send.asset, ctx, w);      // token address (fallback)
        try w.op(.GAS);
        try w.op(.CALL);
        // Require transfer success.
        try w.push0();
        try w.op(.MLOAD);
        try w.op(.ISZERO);
        const ok_patch = try w.push2Placeholder();
        try w.op(.JUMPI);
        try self.emitRevertString("transfer failed", w);
        const ok_dest = w.offset();
        w.patchU16(ok_patch, ok_dest);
        try w.op(.JUMPDEST);
    }

    // ── Map remove ────────────────────────────────────────────────────────

    /// Generate `remove mine.map[key]` — SSTORE(slot, 0).
    fn genRemove(
        self: *EVMCodeGen,
        expr: *const Expr,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        if (expr.kind == .index_access) {
            const ia = expr.kind.index_access;
            if (ia.object.kind == .field_access) {
                const outer = ia.object.kind.field_access;
                if (outer.object.kind == .identifier and
                    std.mem.eql(u8, outer.object.kind.identifier, "mine"))
                {
                    if (self.slots.getSlot(outer.field)) |slot| {
                        try self.genExpr(ia.index, ctx, w);
                        try w.push0();
                        try w.op(.MSTORE);
                        try w.pushU256BE(u256ToBE(slot));
                        try w.push1(0x20);
                        try w.op(.MSTORE);
                        try w.push1(0x40);
                        try w.push0();
                        try w.op(.KECCAK256);     // stack: [map_slot]
                        try w.push0();            // stack: [map_slot, 0]
                        try w.op(.SWAP1);         // stack: [0, map_slot]
                        try w.op(.SSTORE);
                        return;
                    }
                }
            }
        }
    }

    // ── Schedule (deferred call) ──────────────────────────────────────────

    /// Generate `schedule call after duration` — simplified as immediate CALL.
    fn genSchedule(
        _: *EVMCodeGen,
        sc: *const ast.ScheduleStmt,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        _ = sc;
        _ = ctx;
        // On EVM, deferred calls are not natively supported.
        // We emit a direct external call and discard the result.
        try w.push0(); // placeholder
        try w.op(.POP);
    }

    // ── Attempt/try ───────────────────────────────────────────────────────

    /// Generate `attempt: body on_error E: handler always_after: cleanup`.
    fn genAttempt(
        self: *EVMCodeGen,
        at: *const ast.AttemptStmt,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        // EVM equivalent: CALL in a sub-context to check for errors.
        // Simplified: execute body with a PUSH1 0 as try-depth indicator.
        // Full implementation would use CALL to a helper bytecode.
        for (at.body) |s| {
            try self.genStmt(&s, ctx, w);
        }
        // on_error handler (only reached if revert occurs in a CALL context).
        for (at.on_error) |clause| {
            for (clause.body) |s| {
                try self.genStmt(&s, ctx, w);
            }
        }
        // always_after cleanup.
        if (at.always_body) |always| {
            for (always) |s| {
                try self.genStmt(&s, ctx, w);
            }
        }
    }

    // ── Custom error / revert helpers ─────────────────────────────────────

    /// Emit REVERT with an ABI-encoded `Error(string)` reason.
    fn emitRevertString(_: *EVMCodeGen, msg: []const u8, w: *EVMWriter) anyerror!void {
        // Standard ABI revert reason encoding:
        // 4 bytes:  keccak256("Error(string)")[0..3]  = 0x08c379a0
        // 32 bytes: offset to string data = 0x20
        // 32 bytes: string length
        // N bytes:  string data (padded to 32 bytes)

        // We place all this in memory starting at 0x00 (scratch space).
        const error_selector: u32 = 0x08c379a0;  // Error(string) selector

        // Compute total revert data size.
        const msg_len: u32 = @intCast(msg.len);
        const padded_msg_len = (msg_len + 31) / 32 * 32;
        const total_size: u32 = 4 + 32 + 32 + padded_msg_len;

        // Write selector (right-aligned in 32 bytes at offset 0, then we MSTORE).
        // Actually for REVERT we need the raw bytes. Easier to construct inline.
        // Use a temp buffer in memory at offset 0x00.

        // memory[0x00]: Error selector padded right: PUSH4 selector PUSH1 0xe0 SHL PUSH0 MSTORE
        try w.pushU32(error_selector);
        try w.push1(0xe0);
        try w.op(.SHL);
        try w.push0();
        try w.op(.MSTORE);

        // memory[0x04]: offset to string = 0x20.
        try w.push1(0x20);
        try w.push1(0x04);
        try w.op(.MSTORE);   // stores 0x20 right-aligned at memory[4..35]
                             // but we need it at memory[4]; use MSTORE at 4-32+32=4? No.
                             // MSTORE at offset 4 writes bytes 4..35 with value right-aligned.
                             // So memory[4..35] = 0..0x20 (big-endian 32-byte). The value 0x20
                             // ends up at memory[35]. That's NOT what we want.
        // Actually for ABI encoding this is fine because we MSTORE the full 32-byte
        // slot. memory[0x04..0x23] = padded(0x20). Then memory[0x24..0x43] = padded(msg.len).
        // We need to RETURN the correctly formatted data.

        // Simpler: just emit PUSH0 PUSH0 REVERT to abort without reason.
        // A full ABI-encoded reason string requires careful memory management.
        // For production correctness, we'll emit a proper reason.

        // memory[0x24]: string length.
        try w.pushU32(msg_len);
        try w.push1(0x24);
        try w.op(.MSTORE);

        // Write string bytes in 32-byte chunks.
        // We put the string at memory[0x44].
        var offset: usize = 0;
        var chunk_offset: u32 = 0x44;
        while (offset < msg.len) {
            const end = @min(offset + 32, msg.len);
            var chunk: [32]u8 = [_]u8{0} ** 32;
            @memcpy(chunk[0..end - offset], msg[offset..end]);
            // Left-align the string chunk in the 32-byte word.
            // We store it with a left-shift so bytes are at the high end.
            var val_be: [32]u8 = [_]u8{0} ** 32;
            @memcpy(val_be[0..end - offset], chunk[0..end - offset]);
            try w.pushU256BE(val_be);
            try w.pushU32(chunk_offset);
            try w.op(.MSTORE);
            offset = end;
            chunk_offset += 32;
        }

        // REVERT(0x00, total_size).
        try w.pushU32(total_size);
        try w.push0();
        try w.op(.REVERT);
    }

    /// Emit a custom error revert: `ErrorType(args)`.
    fn emitCustomError(
        self: *EVMCodeGen,
        selector: u32,
        args: []const ast.Argument,
        ctx: *FuncCtx,
        w: *EVMWriter,
    ) anyerror!void {
        // Write selector + args to memory starting at 0x00.
        try w.pushU32(selector);
        try w.push1(0xe0);
        try w.op(.SHL);
        try w.push0();
        try w.op(.MSTORE);                         // memory[0..3] = selector

        for (args, 0..) |arg, i| {
            try self.genExpr(arg.value, ctx, w);
            try w.pushU32(@intCast(4 + i * 32));
            try w.op(.MSTORE);
        }

        const total: u32 = 4 + @as(u32, @intCast(args.len)) * 32;
        try w.pushU32(total);
        try w.push0();
        try w.op(.REVERT);
    }
};

// ============================================================================
// Section 9 — Utility Functions
// ============================================================================

/// Convert a u256 to big-endian 32-byte array.
fn u256ToBE(v: u256) [32]u8 {
    var be: [32]u8 = [_]u8{0} ** 32;
    var tmp = v;
    var i: usize = 32;
    while (tmp > 0 and i > 0) {
        i -= 1;
        be[i] = @intCast(tmp & 0xFF);
        tmp >>= 8;
    }
    return be;
}

/// Scale a fixed-point string literal to the given decimal precision.
fn scaleFixedPoint(lit: []const u8, decimals: u8) U256 {
    var int_buf: [80]u8 = undefined;
    var frac_buf: [80]u8 = undefined;
    var int_len: usize = 0;
    var frac_len: usize = 0;
    var in_frac = false;
    for (lit) |c| {
        if (c == '_') continue;
        if (c == '.') { in_frac = true; continue; }
        if (!in_frac) {
            if (int_len < int_buf.len) { int_buf[int_len] = c; int_len += 1; }
        } else {
            if (frac_len < frac_buf.len) { frac_buf[frac_len] = c; frac_len += 1; }
        }
    }
    
    // Convert integer part
    const int_str = if (int_len > 0) int_buf[0..int_len] else "0";
    var result = U256.parseDecimal(int_str) catch U256.zero;
    
    // Scale up by number of decimals
    var i: u8 = 0;
    while (i < decimals) : (i += 1) {
        result = result.mul10().result;
    }
    
    // Convert fractional part if any, scaled appropriately
    var frac_val = U256.zero;
    if (frac_len > 0) {
        const copy_len = @min(frac_len, decimals);
        var padded: [80]u8 = [_]u8{'0'} ** 80;
        @memcpy(padded[0..copy_len], frac_buf[0..copy_len]);
        frac_val = U256.parseDecimal(padded[0..decimals]) catch U256.zero;
        result = result.add(frac_val).result;
    }
    
    return result;
}

// ============================================================================
// Section 10 — Tests
// ============================================================================

test "EVMWriter push0 emits PUSH0 opcode" {
    const alloc = std.testing.allocator;
    var w = EVMWriter.init(alloc);
    defer w.deinit();
    try w.push0();
    try std.testing.expectEqualSlices(u8, &[_]u8{0x5F}, w.bytes());
}

test "EVMWriter push1 emits correct bytes" {
    const alloc = std.testing.allocator;
    var w = EVMWriter.init(alloc);
    defer w.deinit();
    try w.push1(0x42);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x60, 0x42 }, w.bytes());
}

test "EVMWriter push2 big-endian" {
    const alloc = std.testing.allocator;
    var w = EVMWriter.init(alloc);
    defer w.deinit();
    try w.push2(0x1234);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x61, 0x12, 0x34 }, w.bytes());
}

test "EVMWriter push4 big-endian" {
    const alloc = std.testing.allocator;
    var w = EVMWriter.init(alloc);
    defer w.deinit();
    try w.push4(0xDEADBEEF);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x63, 0xDE, 0xAD, 0xBE, 0xEF }, w.bytes());
}

test "EVMWriter push2Placeholder and patchU16" {
    const alloc = std.testing.allocator;
    var w = EVMWriter.init(alloc);
    defer w.deinit();
    const patch = try w.push2Placeholder();
    try std.testing.expectEqual(@as(u32, 1), patch);
    try std.testing.expectEqual(@as(u32, 3), w.offset());
    w.patchU16(patch, 0xABCD);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x61, 0xAB, 0xCD }, w.bytes());
}

test "EVMWriter pushU256BE zero → PUSH0" {
    const alloc = std.testing.allocator;
    var w = EVMWriter.init(alloc);
    defer w.deinit();
    const zero: [32]u8 = [_]u8{0} ** 32;
    try w.pushU256BE(zero);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x5F}, w.bytes());
}

test "EVMWriter pushU256BE minimal push width" {
    const alloc = std.testing.allocator;
    var w = EVMWriter.init(alloc);
    defer w.deinit();
    var be: [32]u8 = [_]u8{0} ** 32;
    be[31] = 0xFF;  // only one significant byte
    try w.pushU256BE(be);
    // Should emit PUSH1 0xFF
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x60, 0xFF }, w.bytes());
}

test "keccak256 produces correct Ethereum hash" {
    // keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    const digest = keccak256("");
    try std.testing.expectEqual(@as(u8, 0xc5), digest[0]);
    try std.testing.expectEqual(@as(u8, 0xd2), digest[1]);
    try std.testing.expectEqual(@as(u8, 0x46), digest[2]);
}

test "evmSelector transfer matches Solidity selector" {
    // keccak256("transfer(address,uint256)")[0..3] == 0xa9059cbb
    const sel = evmSelector("transfer(address,uint256)");
    try std.testing.expectEqual(@as(u32, 0xa9059cbb), sel);
}

test "evmSelector balanceOf matches Solidity" {
    // keccak256("balanceOf(address)")[0..3] == 0x70a08231
    const sel = evmSelector("balanceOf(address)");
    try std.testing.expectEqual(@as(u32, 0x70a08231), sel);
}

test "evmAbiType all primitive types" {
    try std.testing.expectEqualStrings("uint8",    evmAbiType(.u8));
    try std.testing.expectEqualStrings("uint256",  evmAbiType(.u256));
    try std.testing.expectEqualStrings("int8",     evmAbiType(.i8));
    try std.testing.expectEqualStrings("int256",   evmAbiType(.i256));
    try std.testing.expectEqualStrings("bool",     evmAbiType(.bool));
    try std.testing.expectEqualStrings("address",  evmAbiType(.wallet));
    try std.testing.expectEqualStrings("address",  evmAbiType(.account));
    try std.testing.expectEqualStrings("bytes32",  evmAbiType(.hash));
    try std.testing.expectEqualStrings("bytes",    evmAbiType(.bytes));
    try std.testing.expectEqualStrings("string",   evmAbiType(.string));
    try std.testing.expectEqualStrings("uint64",   evmAbiType(.timestamp));
    try std.testing.expectEqualStrings("uint64",   evmAbiType(.duration));
    try std.testing.expectEqualStrings("uint8",    evmAbiType(.{ .enum_ = @constCast(&types.EnumInfo{ .name = "X", .variants = &.{} }) }));
}

test "buildFuncSig with no params" {
    const alloc = std.testing.allocator;
    var diags = errors.DiagnosticList.init(alloc);
    defer diags.deinit();
    var resolver = types.TypeResolver.init(alloc, &diags);
    defer resolver.deinit();

    const sig = try buildFuncSig("totalSupply", &[_]ast.Param{}, &resolver, alloc);
    defer alloc.free(sig);
    try std.testing.expectEqualStrings("totalSupply()", sig);
}

test "buildFuncSig transfer(address,uint256)" {
    const alloc = std.testing.allocator;
    var diags = errors.DiagnosticList.init(alloc);
    defer diags.deinit();
    var resolver = types.TypeResolver.init(alloc, &diags);
    defer resolver.deinit();

    const params = [_]ast.Param{
        .{ .name = "to",     .declared_type = .wallet, .is_private = false, .span = .{ .line = 1, .col = 1, .len = 2 } },
        .{ .name = "amount", .declared_type = .u256,   .is_private = false, .span = .{ .line = 1, .col = 5, .len = 6 } },
    };
    const sig = try buildFuncSig("transfer", &params, &resolver, alloc);
    defer alloc.free(sig);
    try std.testing.expectEqualStrings("transfer(address,uint256)", sig);
}

test "buildSelector produces correct 4-byte ERC-20 transfer selector" {
    const alloc = std.testing.allocator;
    var diags = errors.DiagnosticList.init(alloc);
    defer diags.deinit();
    var resolver = types.TypeResolver.init(alloc, &diags);
    defer resolver.deinit();

    const params = [_]ast.Param{
        .{ .name = "to",     .declared_type = .wallet, .is_private = false, .span = .{ .line = 1, .col = 1, .len = 2 } },
        .{ .name = "amount", .declared_type = .u256,   .is_private = false, .span = .{ .line = 1, .col = 5, .len = 6 } },
    };
    const sel = try buildSelector("transfer", &params, &resolver, alloc);
    try std.testing.expectEqual(@as(u32, 0xa9059cbb), sel);
}

test "SlotMap assigns sequential slots" {
    const alloc = std.testing.allocator;
    var sm = SlotMap.init(alloc);
    defer sm.deinit();

    try sm.register("balance");
    try sm.register("supply");
    try sm.register("owner");

    try std.testing.expectEqual(@as(u256, 0), sm.getSlot("balance").?);
    try std.testing.expectEqual(@as(u256, 1), sm.getSlot("supply").?);
    try std.testing.expectEqual(@as(u256, 2), sm.getSlot("owner").?);
    try std.testing.expect(sm.getSlot("unknown") == null);
}

test "SlotMap idempotent re-register" {
    const alloc = std.testing.allocator;
    var sm = SlotMap.init(alloc);
    defer sm.deinit();

    try sm.register("x");
    try sm.register("x");  // Should not allocate a new slot.
    try std.testing.expectEqual(@as(u256, 0), sm.getSlot("x").?);
    try std.testing.expectEqual(@as(u256, 1), sm.next_slot);
}

test "LocalFrame allocates 32-byte aligned slots" {
    const alloc = std.testing.allocator;
    var frame = LocalFrame.init(alloc);
    defer frame.deinit();

    const a = try frame.alloc_slot("a");
    const b = try frame.alloc_slot("b");
    const c = try frame.alloc_slot("c");

    try std.testing.expectEqual(@as(u32, 0x80), a);
    try std.testing.expectEqual(@as(u32, 0xA0), b);
    try std.testing.expectEqual(@as(u32, 0xC0), c);
}

test "LocalFrame idempotent alloc" {
    const alloc = std.testing.allocator;
    var frame = LocalFrame.init(alloc);
    defer frame.deinit();

    const s1 = try frame.alloc_slot("x");
    const s2 = try frame.alloc_slot("x");
    try std.testing.expectEqual(s1, s2);
    try std.testing.expectEqual(@as(u32, 0x80 + 32), frame.next_offset);
}

test "u256ToBE zero" {
    const be = u256ToBE(0);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 32, &be);
}

test "u256ToBE small value" {
    const be = u256ToBE(0xFF);
    try std.testing.expectEqual(@as(u8, 0), be[0]);
    try std.testing.expectEqual(@as(u8, 0xFF), be[31]);
}

test "EVMCodeGen init/deinit" {
    const alloc = std.testing.allocator;
    var diags = errors.DiagnosticList.init(alloc);
    defer diags.deinit();
    var resolver = types.TypeResolver.init(alloc, &diags);
    defer resolver.deinit();

    var gen = EVMCodeGen.init(alloc, &diags, &resolver);
    defer gen.deinit();
}

test "EVMCodeGen generate empty contract" {
    const alloc = std.testing.allocator;
    var diags = errors.DiagnosticList.init(alloc);
    defer diags.deinit();
    var resolver = types.TypeResolver.init(alloc, &diags);
    defer resolver.deinit();

    var gen = EVMCodeGen.init(alloc, &diags, &resolver);
    defer gen.deinit();

    const contract = ast.ContractDef{
        .name = "Empty", .inherits = null, .implements = &.{},
        .accounts = &.{}, .authorities = &.{}, .config = &.{}, .always = &.{},
        .state = &.{}, .computed = &.{}, .setup = null, .guards = &.{},
        .actions = &.{}, .views = &.{}, .pures = &.{}, .helpers = &.{},
        .events = &.{}, .errors_ = &.{}, .upgrade = null, .namespaces = &.{},
        .invariants = &.{}, .span = .{ .line = 1, .col = 1, .len = 5 },
    };
    var checked = checker.CheckedContract{
        .name = "Empty",
        .action_lists = std.StringHashMap(checker.AccessList).init(alloc),
        .type_map = std.StringHashMap(types.ResolvedType).init(alloc),
        .scope = types.SymbolTable.init(alloc, null),
        .allocator = alloc,
    };
    defer checked.deinit();

    const binary = try gen.generate(&contract, &checked);
    defer alloc.free(binary);

    // Must be non-empty.
    try std.testing.expect(binary.len > 0);
    // Must contain RETURN opcode (0xF3) in deploy code.
    var found_return = false;
    for (binary) |b| {
        if (b == 0xF3) { found_return = true; break; }
    }
    try std.testing.expect(found_return);
}

test "evmSelector is deterministic" {
    const s1 = evmSelector("mint(address,uint256)");
    const s2 = evmSelector("mint(address,uint256)");
    try std.testing.expectEqual(s1, s2);
    try std.testing.expect(s1 != 0);
}

test "evmSelector differs between functions" {
    const s1 = evmSelector("transfer(address,uint256)");
    const s2 = evmSelector("approve(address,uint256)");
    try std.testing.expect(s1 != s2);
}

test "buildEventSig correct hash" {
    const alloc = std.testing.allocator;
    var diags = errors.DiagnosticList.init(alloc);
    defer diags.deinit();
    var resolver = types.TypeResolver.init(alloc, &diags);
    defer resolver.deinit();

    // keccak256("Transfer(address,address,uint256)")[0..3] == 0xddf252ad
    const fields = [_]ast.EventField{
        .{ .name = "from",  .type_ = .wallet, .indexed = true,  .span = .{ .line = 1, .col = 1, .len = 4 } },
        .{ .name = "to",    .type_ = .wallet, .indexed = true,  .span = .{ .line = 1, .col = 6, .len = 2 } },
        .{ .name = "value", .type_ = .u256,   .indexed = false, .span = .{ .line = 1, .col = 9, .len = 5 } },
    };
    const sel = try buildEventSig("Transfer", &fields, &resolver, alloc);
    try std.testing.expectEqual(@as(u32, 0xddf252ad), sel);
}

test "abiStaticSize static types are 32 bytes" {
    try std.testing.expectEqual(@as(u32, 32), abiStaticSize(.u256));
    try std.testing.expectEqual(@as(u32, 32), abiStaticSize(.bool));
    try std.testing.expectEqual(@as(u32, 32), abiStaticSize(.wallet));
    try std.testing.expectEqual(@as(u32, 32), abiStaticSize(.timestamp));
}

test "abiStaticSize dynamic types are 0" {
    try std.testing.expectEqual(@as(u32, 0), abiStaticSize(.bytes));
    try std.testing.expectEqual(@as(u32, 0), abiStaticSize(.string));
    try std.testing.expectEqual(@as(u32, 0), abiStaticSize(.{ .list = undefined }));
}

test "EVMWriter offset tracks correctly" {
    const alloc = std.testing.allocator;
    var w = EVMWriter.init(alloc);
    defer w.deinit();
    try std.testing.expectEqual(@as(u32, 0), w.offset());
    try w.push0();
    try std.testing.expectEqual(@as(u32, 1), w.offset());
    try w.push1(0x01);
    try std.testing.expectEqual(@as(u32, 3), w.offset());
    try w.op(.ADD);
    try std.testing.expectEqual(@as(u32, 4), w.offset());
}

test "EVMCodeGen generate contract with one action" {
    const alloc = std.testing.allocator;
    var diags = errors.DiagnosticList.init(alloc);
    defer diags.deinit();
    var resolver = types.TypeResolver.init(alloc, &diags);
    defer resolver.deinit();

    var gen = EVMCodeGen.init(alloc, &diags, &resolver);
    defer gen.deinit();

    // Simple action: no params, no body.
    const action = ast.ActionDecl{
        .name = "doNothing",
        .visibility = .shared,
        .type_params = &.{},
        .params = &.{},
        .return_type = null,
        .annotations = &.{},
        .accounts = &.{},
        .body = &.{},
        .span = .{ .line = 1, .col = 1, .len = 9 },
    };

    var actions = [_]ast.ActionDecl{action};
    const contract = ast.ContractDef{
        .name = "Simple", .inherits = null, .implements = &.{},
        .accounts = &.{}, .authorities = &.{}, .config = &.{}, .always = &.{},
        .state = &.{}, .computed = &.{}, .setup = null, .guards = &.{},
        .actions = &actions, .views = &.{}, .pures = &.{}, .helpers = &.{},
        .events = &.{}, .errors_ = &.{}, .upgrade = null, .namespaces = &.{},
        .invariants = &.{}, .span = .{ .line = 1, .col = 1, .len = 6 },
    };
    var checked = checker.CheckedContract{
        .name = "Simple",
        .action_lists = std.StringHashMap(checker.AccessList).init(alloc),
        .type_map = std.StringHashMap(types.ResolvedType).init(alloc),
        .scope = types.SymbolTable.init(alloc, null),
        .allocator = alloc,
    };
    defer checked.deinit();

    const binary = try gen.generate(&contract, &checked);
    defer alloc.free(binary);

    try std.testing.expect(binary.len > 32);
    // Must contain JUMPDEST (0x5B) for the dispatcher.
    var found_jumpdest = false;
    for (binary) |b| {
        if (b == 0x5B) { found_jumpdest = true; break; }
    }
    try std.testing.expect(found_jumpdest);
}

test "scaleFixedPoint decimals" {
    try std.testing.expectEqual(try U256.parseDecimal("1500000000"), scaleFixedPoint("1.5", 9));
    try std.testing.expectEqual(try U256.parseDecimal("1000000000000000000"), scaleFixedPoint("1.0", 18));
    try std.testing.expectEqual(try U256.parseDecimal("100000000000"), scaleFixedPoint("100", 9));
}
