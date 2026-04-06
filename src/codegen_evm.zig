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
const mir_mod = @import("mir.zig");

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
        .capability => "bytes",
        .proof    => "bytes",
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

pub const LocalVar = struct {
    offset: u32,
    ty: ResolvedType,
};

/// Complete EVM code generator. Converts a Mid-Level IR (MIR) module into
/// EVM initcode (deploy + runtime combined).
/// This is the unified backend entry point for all EVM-compatible networks.
/// 
/// SPEC REFERENCE: Part 5 (Contract Anatomy), Part 14 (EVM ABI compatibility)
pub const EVMCodeGen = struct {
    allocator: std.mem.Allocator,
    diagnostics: *DiagnosticList,
    resolver: *TypeResolver,
    /// MIR data section reference.
    mir_data: ?[]const u8,
    /// MIR event descriptors.
    mir_events: []const mir_mod.EventDesc,
    /// Internal label counter for safety checks.
    next_label: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        diagnostics: *DiagnosticList,
        resolver: *TypeResolver,
    ) EVMCodeGen {
        return .{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .resolver = resolver,
            .mir_data = null,
            .mir_events = &.{},
            .next_label = 1000000,
        };
    }

    pub fn deinit(self: *EVMCodeGen) void {
        _ = self;
    }

    // ========================================================================
    // MIR-Based Code Generation (unified backend entry point)
    // ========================================================================

    /// SPEC: Part 5, Part 14 — Generate complete EVM initcode from a MirModule.
    /// This is the new unified entry point that replaces direct AST walking.
    /// All backends share the same MirModule; only this lowering layer is
    /// target-specific.
    pub fn generateFromMir(
        self: *EVMCodeGen,
        mir: *const mir_mod.MirModule,
    ) anyerror![]u8 {

        // Generate runtime bytecode from MIR functions.
        const runtime = try self.mirRuntime(mir);
        defer self.allocator.free(runtime);

        // Generate deploy (initcode) from MIR setup function.
        const deploy = try self.mirDeploy(mir, runtime);
        defer self.allocator.free(deploy);

        // Concatenate: [deploy][runtime]
        const total = deploy.len + runtime.len;
        const out = try self.allocator.alloc(u8, total);
        @memcpy(out[0..deploy.len], deploy);
        @memcpy(out[deploy.len..], runtime);
        return out;
    }

    /// SPEC: Part 5.1 — Generate EVM deploy (initcode) from MIR.
    fn mirDeploy(
        self: *EVMCodeGen,
        mir: *const mir_mod.MirModule,
        runtime: []const u8,
    ) anyerror![]u8 {
        var w = EVMWriter.init(self.allocator);
        defer w.deinit();

        // Init free-memory pointer: memory[0x40] = 0x80
        try w.push1(0x80);
        try w.push1(0x40);
        try w.op(.MSTORE);

        // Store deployer address.
        try w.op(.CALLER);
        try w.pushU256BE(keccak256("__deployer__"));
        try w.op(.SSTORE);

        // Initialize authorities from MIR metadata.
        for (mir.authorities) |auth| {
            if (auth.initial_holder) |holder| {
                try w.pushU256BE(holder);
            } else {
                // Default to CALLER if no initial holder specified.
                try w.op(.CALLER);
            }
            try w.pushU256BE(keccak256(auth.name));
            try w.op(.SSTORE);
        }

        // Find and emit setup function body.
        for (mir.functions) |func| {
            if (func.kind == .setup) {
                // ABI-decode constructor params from calldata (no selector).
                for (func.params, 0..) |_, i| {
                    const cd_offset: u32 = @intCast(i * 32);
                    try w.pushU32(cd_offset);
                    try w.op(.CALLDATALOAD);
                    const mem_slot: u32 = @intCast(LOCAL_START + i * 32);
                    try w.pushU32(mem_slot);
                    try w.op(.MSTORE);
                }
                // Emit MIR instructions for setup body. Pass is_initcode=true 
                // so that returns don't emit STOP.
                try self.mirEmitFuncBody(&func, &w, true);
                break;
            }
        }

        // CODECOPY runtime into memory[0x00] and RETURN it.
        // Use placeholders to avoid hardcoding size.
        const runtime_len_cc = try w.push2Placeholder();
        const src_off_cc = try w.push2Placeholder();
        try w.push0();
        try w.op(.CODECOPY);

        const runtime_len_ret = try w.push2Placeholder();
        try w.push0();
        try w.op(.RETURN);

        // Patch with final offsets.
        const final_deploy_len = w.offset();
        const runtime_len_u16: u16 = @intCast(runtime.len);

        w.patchU16(runtime_len_cc, runtime_len_u16);
        w.patchU16(src_off_cc, @intCast(final_deploy_len));
        w.patchU16(runtime_len_ret, runtime_len_u16);

        return w.toOwnedSlice();
    }

    /// SPEC: Part 5.2 — Generate EVM runtime bytecode from MIR.
    fn mirRuntime(
        self: *EVMCodeGen,
        mir: *const mir_mod.MirModule,
    ) anyerror![]u8 {
        var w = EVMWriter.init(self.allocator);
        defer w.deinit();

        // Init free-memory pointer.
        try w.push1(0x80);
        try w.push1(0x40);
        try w.op(.MSTORE);

        // Selector extraction: check calldatasize >= 4.
        try w.push1(4);
        try w.op(.CALLDATASIZE);
        try w.op(.LT);
        const fallback_patch = try w.push2Placeholder();
        try w.op(.JUMPI);

        // Extract 4-byte selector.
        try w.push0();
        try w.op(.CALLDATALOAD);
        try w.push1(0xe0);
        try w.op(.SHR);

        // Build dispatch table from MIR functions.
        const DispatchEntry = struct { patch: u32 };
        var dispatch_entries = std.ArrayListUnmanaged(DispatchEntry){};
        defer dispatch_entries.deinit(self.allocator);
        var dispatch_funcs = std.ArrayListUnmanaged(usize){};
        defer dispatch_funcs.deinit(self.allocator);

        for (mir.functions, 0..) |func, fi| {
            const is_dispatchable = switch (func.kind) {
                .action, .view, .pure => true,
                // Guards and helpers are internal; they are reachable via JUMP
                // inside action bodies (not via selector dispatch).
                .guard, .helper => false,
                else => false,
            };
            if (!is_dispatchable) continue;

            // Build EVM ABI selector from MIR function metadata.
            const sel = self.mirBuildSelector(&func);
            try w.op(.DUP1);
            try w.push4(sel);
            try w.op(.EQ);
            const patch = try w.push2Placeholder();
            try w.op(.JUMPI);
            try dispatch_entries.append(self.allocator, .{ .patch = patch });
            try dispatch_funcs.append(self.allocator, fi);
        }

        // Fallback: calldatasize < 4 or no selector match.
        const fallback_dest = w.offset();
        w.patchU16(fallback_patch, fallback_dest);
        try w.op(.JUMPDEST);

        // Look for receive handler (value > 0).
        var has_receive = false;
        var has_fallback = false;
        for (mir.functions) |func| {
            if (func.kind == .receive) has_receive = true;
            if (func.kind == .fallback) has_fallback = true;
        }

        if (has_receive) {
            try w.op(.CALLVALUE);
            const receive_patch = try w.push2Placeholder();
            try w.op(.JUMPI);
            // No value — fall through to fallback or revert.
            if (has_fallback) {
                for (mir.functions) |func| {
                    if (func.kind == .fallback) {
                        try self.mirEmitFuncBody(&func, &w, false);
                        break;
                    }
                }
            } else {
                try w.push0();
                try w.push0();
                try w.op(.REVERT);
            }
            // Receive handler.
            const receive_dest = w.offset();
            w.patchU16(receive_patch, receive_dest);
            try w.op(.JUMPDEST);
            for (mir.functions) |func| {
                if (func.kind == .receive) {
                    try self.mirEmitFuncBody(&func, &w, false);
                    break;
                }
            }
        } else if (has_fallback) {
            for (mir.functions) |func| {
                if (func.kind == .fallback) {
                    try self.mirEmitFuncBody(&func, &w, false);
                    break;
                }
            }
        } else {
            try w.push0();
            try w.push0();
            try w.op(.REVERT);
        }

        // No-match destination (selector dispatch exhaustion).
        const no_match_dest = w.offset();
        try w.op(.JUMPDEST);
        try w.op(.POP); // pop selector
        try w.push0();
        try w.push0();
        try w.op(.REVERT);
        _ = no_match_dest;

        // ── Internal function tables (populated during guard/helper emission) ───
        var internal_offsets = std.AutoHashMap(u32, u32).init(self.allocator);
        defer internal_offsets.deinit();
        var internal_patches = std.AutoHashMap(u32, std.ArrayListUnmanaged(u32)).init(self.allocator);
        defer {
            var it2 = internal_patches.valueIterator();
            while (it2.next()) |list| list.deinit(self.allocator);
            internal_patches.deinit();
        }

        // ── External-facing function handlers ─────────────────────────────
        for (dispatch_entries.items, 0..) |entry, di| {
            const fi = dispatch_funcs.items[di];
            const func = &mir.functions[fi];

            const handler_dest = w.offset();
            w.patchU16(entry.patch, handler_dest);
            try w.op(.JUMPDEST);
            try w.op(.POP); // pop selector

            // ABI-decode calldata params into memory.
            for (func.params, 0..) |_, pi| {
                const cd_off: u32 = @intCast(4 + pi * 32);
                try w.pushU32(cd_off);
                try w.op(.CALLDATALOAD);
                const mem_slot: u32 = @intCast(LOCAL_START + pi * 32);
                try w.pushU32(mem_slot);
                try w.op(.MSTORE);
            }

            try self.mirEmitFuncBodyWithInternals(func, &w, false, &internal_offsets, &internal_patches);

            if (func.kind == .view or func.kind == .pure) {
                try w.push0();
                try w.push1(0x00);
                try w.op(.MSTORE);
                try w.push1(32);
                try w.push0();
                try w.op(.RETURN);
            } else {
                try w.op(.STOP);
            }
        }

        // ── Internal functions (guards + helpers) ──────────────────────────
        // Emitted as JUMPDEST blocks after the public handlers.
        // call_internal uses fnvHash32(name) as selector; forward refs were
        // registered during external handler emission and are patched here.

        for (mir.functions) |func| {
            if (func.kind != .guard and func.kind != .helper) continue;

            // Record JUMPDEST offset for this function's selector.
            const dest = w.offset();
            try w.op(.JUMPDEST);
            try internal_offsets.put(func.selector, dest);

            // Back-patch any call_internal forward refs for this selector.
            if (internal_patches.getPtr(func.selector)) |patches| {
                for (patches.items) |p| w.patchU16(p, dest);
                patches.clearRetainingCapacity();
            }

            // Params are pre-loaded by the caller via memory slots; no decode needed.
            try self.mirEmitFuncBodyWithInternals(&func, &w, false, &internal_offsets, &internal_patches);

            // Return: JUMP back to caller (return address on stack).
            try w.op(.JUMP);
        }

        return w.toOwnedSlice();
    }

    /// Like mirEmitFuncBody but threads internal function offset maps for
    /// call_internal dispatch.
    fn mirEmitFuncBodyWithInternals(
        self: *EVMCodeGen,
        func: *const mir_mod.MirFunction,
        w: *EVMWriter,
        is_initcode: bool,
        internal_offsets: *std.AutoHashMap(u32, u32),
        internal_patches: *std.AutoHashMap(u32, std.ArrayListUnmanaged(u32)),
    ) anyerror!void {
        var reg_mem = std.AutoHashMap(mir_mod.Reg, u32).init(self.allocator);
        defer reg_mem.deinit();
        var next_mem: u32 = LOCAL_START;

        for (func.params, 0..) |_, i| {
            const reg: mir_mod.Reg = @intCast(i);
            try reg_mem.put(reg, @intCast(LOCAL_START + i * 32));
            next_mem = @intCast(LOCAL_START + (i + 1) * 32);
        }

        var label_offsets = std.AutoHashMap(mir_mod.LabelId, u32).init(self.allocator);
        defer label_offsets.deinit();
        var label_patches = std.AutoHashMap(mir_mod.LabelId, std.ArrayListUnmanaged(u32)).init(self.allocator);
        defer {
            var it = label_patches.valueIterator();
            while (it.next()) |list| list.deinit(self.allocator);
            label_patches.deinit();
        }

        const RegCtx = struct {
            reg_mem: *std.AutoHashMap(mir_mod.Reg, u32),
            next_mem: *u32,
            fn memOf(ctx: @This(), reg: mir_mod.Reg) u32 {
                if (ctx.reg_mem.get(reg)) |off| return off;
                const off = ctx.next_mem.*;
                ctx.reg_mem.put(reg, off) catch {};
                ctx.next_mem.* += 32;
                return off;
            }
        };
        var rctx = RegCtx{ .reg_mem = &reg_mem, .next_mem = &next_mem };

        for (func.body) |instr| {
            // Handle call_internal with the live offset maps.
            if (instr.op == .call_internal) {
                const ci = instr.op.call_internal;
                // Push args into consecutive memory slots above next_mem.
                for (ci.args, 0..) |arg, ai| {
                    try w.pushU32(rctx.memOf(arg));
                    try w.op(.MLOAD);
                    try w.pushU32(@intCast(next_mem + @as(u32, @intCast(ai)) * 32));
                    try w.op(.MSTORE);
                }
                // Push return address (current offset + 7 bytes for PUSH2 + JUMP).
                const ret_addr_offset = w.offset() + 7;
                try w.push2(@intCast(ret_addr_offset)); // return address
                // Jump to callee.
                if (internal_offsets.get(ci.selector)) |target| {
                    try w.push2(@intCast(target));
                } else {
                    const p = try w.push2Placeholder();
                    const entry = try internal_patches.getOrPut(ci.selector);
                    if (!entry.found_existing) entry.value_ptr.* = .{};
                    try entry.value_ptr.append(self.allocator, p);
                }
                try w.op(.JUMP);
                // JUMPDEST for return.
                const ret_dest = w.offset();
                _ = ret_dest;
                try w.op(.JUMPDEST);
                // Result is in memory[LOCAL_START + next_mem] — move to dst.
                try w.push0();
                try w.pushU32(rctx.memOf(ci.dst));
                try w.op(.MSTORE);
                continue;
            }
            try self.mirLowerInstr(&instr, w, &rctx, &label_offsets, &label_patches, is_initcode);
        }

        // Backpatch labels.
        var patch_it = label_patches.iterator();
        while (patch_it.next()) |entry| {
            if (label_offsets.get(entry.key_ptr.*)) |target| {
                for (entry.value_ptr.items) |patch_off| {
                    w.patchU16(patch_off, target);
                }
            }
        }
    }

    /// Build a MIR-derived EVM ABI selector: keccak256("name(type0,type1,...)")
    fn mirBuildSelector(self: *EVMCodeGen, func: *const mir_mod.MirFunction) u32 {
        var buf = std.ArrayListUnmanaged(u8){};
        defer buf.deinit(self.allocator);
        buf.appendSlice(self.allocator, func.name) catch return func.selector;
        buf.append(self.allocator, '(') catch return func.selector;
        for (func.params, 0..) |p, i| {
            if (i > 0) buf.append(self.allocator, ',') catch {};
            const abi_str = mirTypeToAbi(p.resolved);
            buf.appendSlice(self.allocator, abi_str) catch {};
        }
        buf.append(self.allocator, ')') catch return func.selector;
        return evmSelector(buf.items);
    }

    /// Map a ResolvedType (carried through MIR) to EVM ABI type string.
    fn mirTypeToAbi(rt: ResolvedType) []const u8 {
        return evmAbiType(rt);
    }

    /// SPEC: Part 5 — Emit EVM bytecode for one MIR function's instruction stream.
    fn mirEmitFuncBody(
        self: *EVMCodeGen,
        func: *const mir_mod.MirFunction,
        w: *EVMWriter,
        is_initcode: bool,
    ) anyerror!void {
        // Register file: map virtual MIR registers → memory offsets.
        var reg_mem = std.AutoHashMap(mir_mod.Reg, u32).init(self.allocator);
        defer reg_mem.deinit();
        var next_mem: u32 = LOCAL_START;

        // Allocate memory for parameters.
        for (func.params, 0..) |_, i| {
            const reg: mir_mod.Reg = @intCast(i);
            try reg_mem.put(reg, @intCast(LOCAL_START + i * 32));
            next_mem = @intCast(LOCAL_START + (i + 1) * 32);
        }

        // Label → bytecode offset map for jump resolution.
        var label_offsets = std.AutoHashMap(mir_mod.LabelId, u32).init(self.allocator);
        defer label_offsets.deinit();

        // Forward-reference patches: label → list of patch offsets.
        var label_patches = std.AutoHashMap(mir_mod.LabelId, std.ArrayListUnmanaged(u32)).init(self.allocator);
        defer {
            var it = label_patches.valueIterator();
            while (it.next()) |list| {
                list.deinit(self.allocator);
            }
            label_patches.deinit();
        }

        // Helper: get or allocate memory for a register.
        const RegCtx = struct {
            reg_mem: *std.AutoHashMap(mir_mod.Reg, u32),
            next_mem: *u32,

            fn memOf(ctx: @This(), reg: mir_mod.Reg) u32 {
                if (ctx.reg_mem.get(reg)) |off| return off;
                const off = ctx.next_mem.*;
                ctx.reg_mem.put(reg, off) catch {};
                ctx.next_mem.* += 32;
                return off;
            }
        };
        var rctx = RegCtx{ .reg_mem = &reg_mem, .next_mem = &next_mem };

        for (func.body) |instr| {
            try self.mirLowerInstr(&instr, w, &rctx, &label_offsets, &label_patches, is_initcode);
        }

        // Backpatch all forward label references.
        var patch_it = label_patches.iterator();
        while (patch_it.next()) |entry| {
            if (label_offsets.get(entry.key_ptr.*)) |target| {
                for (entry.value_ptr.items) |patch_off| {
                    w.patchU16(patch_off, target);
                }
            }
        }
    }

    /// SPEC: Part 5 — Lower one MIR instruction to EVM bytecode.
    fn mirLowerInstr(
        self: *EVMCodeGen,
        instr: *const mir_mod.MirInstr,
        w: *EVMWriter,
        rctx: anytype,
        label_offsets: *std.AutoHashMap(mir_mod.LabelId, u32),
        label_patches: *std.AutoHashMap(mir_mod.LabelId, std.ArrayListUnmanaged(u32)),
        is_initcode: bool,
    ) anyerror!void {
        switch (instr.op) {
            // ── Constants ─────────────────────────────────────────────────
            .const_i256 => |c| {
                try w.pushU256BE(c.bytes);
                const off = rctx.memOf(c.dst);
                try w.pushU32(off);
                try w.op(.MSTORE);
            },
            .const_bool => |c| {
                if (c.value) try w.push1(1) else try w.push0();
                const off = rctx.memOf(c.dst);
                try w.pushU32(off);
                try w.op(.MSTORE);
            },
            .const_data => |c| {
                // Push data offset and length as a packed value.
                try w.pushU64(@intCast(c.offset));
                const off = rctx.memOf(c.dst);
                try w.pushU32(off);
                try w.op(.MSTORE);
            },

            // ── Arithmetic ────────────────────────────────────────────────
            .add => |a| {
                const ok_label = self.next_label;
                self.next_label += 1;
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD);
                // Status: [rhs, lhs]
                try w.op(.ADD);
                // Status: [sum]
                try w.op(.DUP1);
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                // Status: [sum, sum, rhs]
                try w.op(.GT);
                try w.op(.ISZERO);
                // Status: [sum, sum >= rhs]
                if (label_offsets.get(ok_label)) |target_off| {
                    try w.push2(@intCast(target_off));
                } else {
                    const p = try w.push2Placeholder();
                    const entry = try label_patches.getOrPut(ok_label);
                    if (!entry.found_existing) entry.value_ptr.* = .{};
                    try entry.value_ptr.append(self.allocator, p);
                }
                try w.op(.JUMPI);
                try w.push0();
                try w.push0();
                try w.op(.REVERT);
                // Target Label
                const ok_off = w.offset();
                try label_offsets.put(ok_label, ok_off);
                try w.op(.JUMPDEST);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },
            .sub => |a| {
                const ok_label = self.next_label;
                self.next_label += 1;
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD);
                // Status: [rhs, lhs]
                try w.op(.DUP2);
                try w.op(.DUP2);
                // Status: [rhs, lhs, rhs, lhs]
                try w.op(.LT);
                try w.op(.ISZERO);
                // Status: [rhs, lhs, lhs >= rhs]
                if (label_offsets.get(ok_label)) |target_off| {
                    try w.push2(@intCast(target_off));
                } else {
                    const p = try w.push2Placeholder();
                    const entry = try label_patches.getOrPut(ok_label);
                    if (!entry.found_existing) entry.value_ptr.* = .{};
                    try entry.value_ptr.append(self.allocator, p);
                }
                try w.op(.JUMPI);
                try w.push0();
                try w.push0();
                try w.op(.REVERT);
                // Target Label
                const ok_off = w.offset();
                try label_offsets.put(ok_label, ok_off);
                try w.op(.JUMPDEST);
                try w.op(.SUB);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },
            .mul => |a| {
                const ok_label = self.next_label;
                self.next_label += 1;
                const zero_label = self.next_label;
                self.next_label += 1;

                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD);
                // Status: [rhs, lhs]
                try w.op(.DUP1);
                try w.op(.ISZERO);
                if (label_offsets.get(zero_label)) |target_off| {
                    try w.push2(@intCast(target_off));
                } else {
                    const p = try w.push2Placeholder();
                    const entry = try label_patches.getOrPut(zero_label);
                    if (!entry.found_existing) entry.value_ptr.* = .{};
                    try entry.value_ptr.append(self.allocator, p);
                }
                try w.op(.JUMPI);
                // lhs != 0: check product / lhs == rhs
                try w.op(.DUP2);
                try w.op(.DUP2);
                try w.op(.MUL);
                // Status: [lhs, rhs, product]
                try w.op(.DUP1);
                try w.op(.DUP4); // lhs
                try w.op(.DIV);
                // Status: [lhs, rhs, product, product/lhs]
                try w.op(.DUP3); // rhs
                try w.op(.EQ);
                if (label_offsets.get(ok_label)) |target_off| {
                    try w.push2(@intCast(target_off));
                } else {
                    const p = try w.push2Placeholder();
                    const entry = try label_patches.getOrPut(ok_label);
                    if (!entry.found_existing) entry.value_ptr.* = .{};
                    try entry.value_ptr.append(self.allocator, p);
                }
                try w.op(.JUMPI);
                try w.push0();
                try w.push0();
                try w.op(.REVERT);

                // Zero label dest
                const zero_off = w.offset();
                try label_offsets.put(zero_label, zero_off);
                try w.op(.JUMPDEST);
                try w.op(.POP);
                try w.op(.POP);
                try w.push0();

                // Ok label dest
                const ok_off = w.offset();
                try label_offsets.put(ok_label, ok_off);
                try w.op(.JUMPDEST);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },
            .div => |a| {
                const ok_label = self.next_label;
                self.next_label += 1;
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD); // divisor
                try w.op(.DUP1);
                try w.op(.ISZERO);
                try w.op(.ISZERO);
                if (label_offsets.get(ok_label)) |target_off| {
                    try w.push2(@intCast(target_off));
                } else {
                    const p = try w.push2Placeholder();
                    const entry = try label_patches.getOrPut(ok_label);
                    if (!entry.found_existing) entry.value_ptr.* = .{};
                    try entry.value_ptr.append(self.allocator, p);
                }
                try w.op(.JUMPI);
                try w.push0();
                try w.push0();
                try w.op(.REVERT);
                const ok_off = w.offset();
                try label_offsets.put(ok_label, ok_off);
                try w.op(.JUMPDEST);
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD); // dividend
                try w.op(.DIV);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },
            .mod => |a| {
                const ok_label = self.next_label;
                self.next_label += 1;
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                try w.op(.DUP1);
                try w.op(.ISZERO);
                try w.op(.ISZERO);
                if (label_offsets.get(ok_label)) |target_off| {
                    try w.push2(@intCast(target_off));
                } else {
                    const p = try w.push2Placeholder();
                    const entry = try label_patches.getOrPut(ok_label);
                    if (!entry.found_existing) entry.value_ptr.* = .{};
                    try entry.value_ptr.append(self.allocator, p);
                }
                try w.op(.JUMPI);
                try w.push0();
                try w.push0();
                try w.op(.REVERT);
                const ok_off = w.offset();
                try label_offsets.put(ok_label, ok_off);
                try w.op(.JUMPDEST);
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD);
                try w.op(.MOD);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },
            .negate => |u| {
                try w.push0();
                try w.pushU32(rctx.memOf(u.operand));
                try w.op(.MLOAD);
                try w.op(.SUB);
                try w.pushU32(rctx.memOf(u.dst));
                try w.op(.MSTORE);
            },

            // ── Comparison ────────────────────────────────────────────────
            .eq => |a| {
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD);
                try w.op(.EQ);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },
            .ne => |a| {
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD);
                try w.op(.EQ);
                try w.op(.ISZERO);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },
            .lt => |a| {
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD);
                try w.op(.LT);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },
            .gt => |a| {
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD);
                try w.op(.GT);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },
            .le => |a| {
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD);
                try w.op(.GT);
                try w.op(.ISZERO);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },
            .ge => |a| {
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD);
                try w.op(.LT);
                try w.op(.ISZERO);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },

            // ── Logic ─────────────────────────────────────────────────────
            .bool_and => |a| {
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                try w.op(.AND);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },
            .bool_or => |a| {
                try w.pushU32(rctx.memOf(a.lhs));
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(a.rhs));
                try w.op(.MLOAD);
                try w.op(.OR);
                try w.pushU32(rctx.memOf(a.dst));
                try w.op(.MSTORE);
            },
            .bool_not => |u| {
                try w.pushU32(rctx.memOf(u.operand));
                try w.op(.MLOAD);
                try w.op(.ISZERO);
                try w.pushU32(rctx.memOf(u.dst));
                try w.op(.MSTORE);
            },

            // ── Move ──────────────────────────────────────────────────────
            .mov => |m| {
                try w.pushU32(rctx.memOf(m.src));
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(m.dst));
                try w.op(.MSTORE);
            },

            // ── Control flow ──────────────────────────────────────────────
            .label => |l| {
                const off = w.offset();
                try label_offsets.put(l.id, off);
                try w.op(.JUMPDEST);
                // Backpatch any forward refs to this label.
                if (label_patches.getPtr(l.id)) |patches| {
                    for (patches.items) |p| {
                        w.patchU16(p, off);
                    }
                    patches.clearRetainingCapacity();
                }
            },
            .jump => |j| {
                if (label_offsets.get(j.target)) |target_off| {
                    try w.push2(@intCast(target_off));
                } else {
                    const p = try w.push2Placeholder();
                    const entry = try label_patches.getOrPut(j.target);
                    if (!entry.found_existing) {
                        entry.value_ptr.* = .{};
                    }
                    try entry.value_ptr.append(self.allocator, p);
                }
                try w.op(.JUMP);
            },
            .branch => |b| {
                try w.pushU32(rctx.memOf(b.cond));
                try w.op(.MLOAD);
                // Jump to then_ if condition is true.
                if (label_offsets.get(b.then_)) |target_off| {
                    try w.push2(@intCast(target_off));
                } else {
                    const p = try w.push2Placeholder();
                    const entry = try label_patches.getOrPut(b.then_);
                    if (!entry.found_existing) {
                        entry.value_ptr.* = .{};
                    }
                    try entry.value_ptr.append(self.allocator, p);
                }
                try w.op(.JUMPI);
                // Fall through = else_ path; emit jump to else_ label.
                if (label_offsets.get(b.else_)) |target_off| {
                    try w.push2(@intCast(target_off));
                } else {
                    const p = try w.push2Placeholder();
                    const entry = try label_patches.getOrPut(b.else_);
                    if (!entry.found_existing) {
                        entry.value_ptr.* = .{};
                    }
                    try entry.value_ptr.append(self.allocator, p);
                }
                try w.op(.JUMP);
            },

            // ── Return ────────────────────────────────────────────────────
            .ret => |r| {
                if (r.value) |val| {
                    try w.pushU32(rctx.memOf(val));
                    try w.op(.MLOAD);
                    try w.push1(0x00);
                    try w.op(.MSTORE);
                    try w.push1(32);
                    try w.push0();
                    try w.op(.RETURN);
                } else {
                    if (!is_initcode) {
                        try w.op(.STOP);
                    }
                }
            },

            // ── State access ──────────────────────────────────────────────
            .state_read => |sr| {
                if (sr.key) |key_reg| {
                    // Map access: slot = keccak256(key ++ base_slot)
                    try w.pushU32(rctx.memOf(key_reg));
                    try w.op(.MLOAD);
                    try w.push1(0x00);
                    try w.op(.MSTORE);
                    try w.pushU64(@intCast(sr.field_id));
                    try w.push1(0x20);
                    try w.op(.MSTORE);
                    try w.push1(0x40);
                    try w.push0();
                    try w.op(.KECCAK256);
                } else {
                    try w.pushU64(@intCast(sr.field_id));
                }
                try w.op(.SLOAD);
                try w.pushU32(rctx.memOf(sr.dst));
                try w.op(.MSTORE);
            },
            .state_write => |sw| {
                try w.pushU32(rctx.memOf(sw.value));
                try w.op(.MLOAD);
                if (sw.key) |key_reg| {
                    try w.pushU32(rctx.memOf(key_reg));
                    try w.op(.MLOAD);
                    try w.push1(0x00);
                    try w.op(.MSTORE);
                    try w.pushU64(@intCast(sw.field_id));
                    try w.push1(0x20);
                    try w.op(.MSTORE);
                    try w.push1(0x40);
                    try w.push0();
                    try w.op(.KECCAK256);
                } else {
                    try w.pushU64(@intCast(sw.field_id));
                }
                try w.op(.SSTORE);
            },
            .state_delete => |sd| {
                try w.push0(); // value = 0 to delete
                try w.pushU32(rctx.memOf(sd.key));
                try w.op(.MLOAD);
                try w.push1(0x00);
                try w.op(.MSTORE);
                try w.pushU64(@intCast(sd.field_id));
                try w.push1(0x20);
                try w.op(.MSTORE);
                try w.push1(0x40);
                try w.push0();
                try w.op(.KECCAK256);
                try w.op(.SSTORE);
            },

            // ── Events ────────────────────────────────────────────────────
            .emit_event => |ev| {
                // Find event descriptor for correct LOG opcode.
                var indexed_count: u32 = 0;
                var event_fields: []const mir_mod.EventFieldDesc = &.{};
                for (self.mir_events) |edesc| {
                    if (edesc.event_id == ev.event_id) {
                        event_fields = edesc.fields;
                        for (edesc.fields) |f| {
                            if (f.indexed) indexed_count += 1;
                        }
                        break;
                    }
                }
                // topic[0] = keccak256(event signature)
                // Store non-indexed args in memory, push indexed as topics.
                var mem_off: u32 = 0;
                var topic_regs = std.ArrayListUnmanaged(mir_mod.Reg){};
                defer topic_regs.deinit(self.allocator);

                for (event_fields, 0..) |f, fi| {
                    if (fi < ev.args.len) {
                        if (f.indexed) {
                            try topic_regs.append(self.allocator, ev.args[fi]);
                        } else {
                            try w.pushU32(rctx.memOf(ev.args[fi]));
                            try w.op(.MLOAD);
                            try w.pushU32(mem_off);
                            try w.op(.MSTORE);
                            mem_off += 32;
                        }
                    }
                }

                // Push data size and offset.
                try w.pushU32(mem_off); // data size
                try w.push0();          // data offset

                // Push indexed topics (reverse order for EVM stack).
                var ti = topic_regs.items.len;
                while (ti > 0) {
                    ti -= 1;
                    try w.pushU32(rctx.memOf(topic_regs.items[ti]));
                    try w.op(.MLOAD);
                }

                // topic[0] = event signature hash (always present).
                // Build event sig from name + fields.
                if (self.findEventName(ev.event_id)) |ename| {
                    const sig_hash = self.buildMirEventSig(ename, event_fields);
                    try w.pushU256BE(sig_hash);
                } else {
                    try w.push0();
                }

                // LOGn where n = 1 + indexed_count.
                const log_n = 1 + indexed_count;
                switch (log_n) {
                    1 => try w.op(.LOG1),
                    2 => try w.op(.LOG2),
                    3 => try w.op(.LOG3),
                    4 => try w.op(.LOG4),
                    else => try w.op(.LOG1),
                }
            },

            // ── Assertions ────────────────────────────────────────────────
            .need => |n| {
                // REQUIRE pattern: if cond == 0, revert with message.
                try w.pushU32(rctx.memOf(n.cond));
                try w.op(.MLOAD);
                const ok_patch = try w.push2Placeholder();
                try w.op(.JUMPI);
                // Revert path: store message in memory and revert.
                try self.mirEmitRevert(w, n.msg_offset, n.msg_len);
                // OK path:
                const ok_dest = w.offset();
                w.patchU16(ok_patch, ok_dest);
                try w.op(.JUMPDEST);
            },
            .ensure => |e| {
                // Same as need for EVM.
                try w.pushU32(rctx.memOf(e.cond));
                try w.op(.MLOAD);
                const ok_patch = try w.push2Placeholder();
                try w.op(.JUMPI);
                try self.mirEmitRevert(w, e.msg_offset, e.msg_len);
                const ok_dest = w.offset();
                w.patchU16(ok_patch, ok_dest);
                try w.op(.JUMPDEST);
            },
            .panic => |p| {
                try self.mirEmitRevert(w, p.msg_offset, p.msg_len);
            },

            // ── Native transfer ───────────────────────────────────────────
            .pay => |p| {
                // CALL(gas, to, value, inOff, inLen, outOff, outLen)
                try w.op(.GAS);                           // gas
                try w.pushU32(rctx.memOf(p.recipient));   // to
                try w.op(.MLOAD);
                try w.pushU32(rctx.memOf(p.amount));      // value
                try w.op(.MLOAD);
                try w.push0();                            // inOff
                try w.push0();                            // inLen
                try w.push0();                            // outOff
                try w.push0();                            // outLen
                try w.op(.CALL);
                try w.op(.POP);                           // pop success
            },

            // ── Caller / context builtins ─────────────────────────────────
            .get_caller => |gc| {
                try w.op(.CALLER);
                try w.pushU32(rctx.memOf(gc.dst));
                try w.op(.MSTORE);
            },
            .get_value => |gv| {
                try w.op(.CALLVALUE);
                try w.pushU32(rctx.memOf(gv.dst));
                try w.op(.MSTORE);
            },
            .get_timestamp => |gt| {
                try w.op(.TIMESTAMP);
                try w.pushU32(rctx.memOf(gt.dst));
                try w.op(.MSTORE);
            },
            .get_block => |gb| {
                try w.op(.NUMBER);
                try w.pushU32(rctx.memOf(gb.dst));
                try w.op(.MSTORE);
            },
            .get_gas => |gg| {
                try w.op(.GAS);
                try w.pushU32(rctx.memOf(gg.dst));
                try w.op(.MSTORE);
            },
            .get_this => |gt| {
                try w.op(.ADDRESS);
                try w.pushU32(rctx.memOf(gt.dst));
                try w.op(.MSTORE);
            },
            .get_deployer => |gd| {
                try w.pushU256BE(keccak256("__deployer__"));
                try w.op(.SLOAD);
                try w.pushU32(rctx.memOf(gd.dst));
                try w.op(.MSTORE);
            },
            .get_zero_addr => |gz| {
                try w.push0();
                try w.pushU32(rctx.memOf(gz.dst));
                try w.op(.MSTORE);
            },

            // ── Authority checks ──────────────────────────────────────────
            .auth_check => |ac| {
                // Load stored authority address, compare with CALLER.
                const name = self.getMirDataSlice(ac.name_offset, ac.name_len);
                try w.pushU256BE(keccak256(name));
                try w.op(.SLOAD);
                try w.op(.CALLER);
                try w.op(.EQ);
                const ok_patch = try w.push2Placeholder();
                try w.op(.JUMPI);
                try w.push0();
                try w.push0();
                try w.op(.REVERT);
                const ok_dest = w.offset();
                w.patchU16(ok_patch, ok_dest);
                try w.op(.JUMPDEST);
            },
            .auth_gate_begin => |ag| {
                const name = self.getMirDataSlice(ag.name_offset, ag.name_len);
                try w.pushU256BE(keccak256(name));
                try w.op(.SLOAD);
                try w.op(.CALLER);
                try w.op(.EQ);
                const ok_patch = try w.push2Placeholder();
                try w.op(.JUMPI);
                try w.push0();
                try w.push0();
                try w.op(.REVERT);
                const ok_dest = w.offset();
                w.patchU16(ok_patch, ok_dest);
                try w.op(.JUMPDEST);
            },
            .auth_gate_end => {},

            // ── Error throwing ─────────────────────────────────────────────
            .throw_error => |te| {
                // ABI-encode error and revert.
                for (te.args, 0..) |arg, i| {
                    try w.pushU32(rctx.memOf(arg));
                    try w.op(.MLOAD);
                    try w.pushU32(@intCast(4 + i * 32));
                    try w.op(.MSTORE);
                }
                const total: u32 = 4 + @as(u32, @intCast(te.args.len)) * 32;
                try w.pushU32(total);
                try w.push0();
                try w.op(.REVERT);
            },

            // ── Try/catch ─────────────────────────────────────────────────
            .attempt_begin => {},
            .attempt_end => {},

            // ── ZK ────────────────────────────────────────────────────────
            .zk_verify => {}, // No-op on EVM (ZK done off-chain).

            // ── Asset operations (ERC-20 interop — placeholder) ───────────
            .asset_send => {},
            .asset_mint => {},
            .asset_burn => {},
            .asset_split => {},
            .asset_merge => {},
            .asset_wrap => {},
            .asset_unwrap => {},

            // ── Account lifecycle (no-op on EVM) ──────────────────────────
            .expand_account => {},
            .close_account => {},
            .freeze_account => {},
            .unfreeze_account => {},
            .transfer_ownership => {},

            // ── Scheduling (no-op on EVM, requires keeper) ────────────────
            .schedule_call => {},

            // ── VM-specific extended (no-op/placeholder on EVM) ───────────
            .oracle_read => {},
            .vrf_random => {},
            .delegate_gas => {},
            .has_check => {},

            // ── const_i64 ─────────────────────────────────────────────────
            .const_i64 => |c| {
                var be: [32]u8 = [_]u8{0} ** 32;
                if (c.value >= 0) {
                    std.mem.writeInt(u64, be[24..32], @intCast(c.value), .big);
                } else {
                    // Sign-extend negative values to 256-bit.
                    be = [_]u8{0xFF} ** 32;
                    std.mem.writeInt(i64, @ptrCast(be[24..32]), c.value, .big);
                }
                try w.pushU256BE(be);
                try w.pushU32(rctx.memOf(c.dst));
                try w.op(.MSTORE);
            },

            // ── No-op / internal call ──────────────────────────────────────
            .nop => {},
            .call_internal => {},
            .call_external => {},
        }
    }

    /// Emit a REVERT with an Error(string) ABI-encoded reason.
    fn mirEmitRevert(self: *EVMCodeGen, w: *EVMWriter, msg_offset: u32, msg_len: u32) anyerror!void {
        // Error(string) selector = 0x08c379a0
        const err_sel: u32 = 0x08c379a0;
        try w.push4(err_sel);
        try w.push1(0xe0);
        try w.op(.SHL);
        try w.push0();
        try w.op(.MSTORE);
        // ABI offset to string data = 0x20
        try w.push1(0x20);
        try w.push1(0x04);
        try w.op(.MSTORE);
        // String length.
        try w.pushU32(msg_len);
        try w.push1(0x24);
        try w.op(.MSTORE);
        // String data (from MIR data section).
        if (msg_len > 0 and self.mir_data != null) {
            const data = self.mir_data.?;
            if (msg_offset + msg_len <= data.len) {
                var bytes32: [32]u8 = [_]u8{0} ** 32;
                const copy_len = @min(msg_len, 32);
                @memcpy(bytes32[0..copy_len], data[msg_offset..][0..copy_len]);
                try w.pushU256BE(bytes32);
                try w.push1(0x44);
                try w.op(.MSTORE);
            }
        }
        // Total revert data = 4 + 32 + 32 + padded_msg
        const padded = ((msg_len + 31) / 32) * 32;
        const total_len = 4 + 32 + 32 + padded;
        try w.pushU32(total_len);
        try w.push0();
        try w.op(.REVERT);
    }

    /// Find event name by ID.
    fn findEventName(self: *EVMCodeGen, event_id: u32) ?[]const u8 {
        for (self.mir_events) |ev| {
            if (ev.event_id == event_id) return ev.name;
        }
        return null;
    }

    /// Build keccak256 hash of event signature for topic[0].
    fn buildMirEventSig(self: *EVMCodeGen, name: []const u8, fields: []const mir_mod.EventFieldDesc) [32]u8 {
        var buf = std.ArrayListUnmanaged(u8){};
        defer buf.deinit(self.allocator);
        buf.appendSlice(self.allocator, name) catch return [_]u8{0} ** 32;
        buf.append(self.allocator, '(') catch return [_]u8{0} ** 32;
        for (fields, 0..) |f, i| {
            if (i > 0) buf.append(self.allocator, ',') catch {};
            buf.appendSlice(self.allocator, evmAbiType(f.resolved)) catch {};
        }
        buf.append(self.allocator, ')') catch return [_]u8{0} ** 32;
        return keccak256(buf.items);
    }

    /// Get a slice from the MIR data section.
    fn getMirDataSlice(self: *EVMCodeGen, offset: u32, len: u32) []const u8 {
        if (self.mir_data) |data| {
            if (offset + len <= data.len) {
                return data[offset..][0..len];
            }
        }
        return "";
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
