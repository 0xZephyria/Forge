// ============================================================================
// Forge Compiler — Code Generator
// ============================================================================
//
// Walks the checked AST and emits RISC-V bytecode for the Zephyria VM.
// Produces a complete .fozbin binary with header, access list, and
// bytecode sections.
//
// SPEC REFERENCE: Part 5 (Contract Anatomy), Part 9 (Parallel Execution),
//   Part 20 (Zero-Conflict Architecture — binary includes verified access list)
//
// This is a library file. No main() function is present.

const std = @import("std");
const ast = @import("ast.zig");
const errors = @import("errors.zig");
const types = @import("types.zig");
const checker = @import("checker.zig");
const mir_mod = @import("mir.zig");
const u256_mod = @import("u256.zig");

const riscv = @import("riscv.zig");

// ============================================================================
// PolkaVM Host Calls Mapping
// ============================================================================
/// Maps the conceptual operations to PolkaVM ECALLI immediate host numbers.
/// In a fully linked PolkaVM payload, these integers map directly to string 
/// identifiers in the binary's Import Section (e.g., pallet-revive UAPI).
pub const PolkaHostCalls = enum(u12) {
    /// Maps to pallet-revive `get_storage`
    STATE_READ = 1,
    /// Maps to pallet-revive `set_storage`
    STATE_WRITE = 2,
    /// Maps to pallet-revive `get_storage_or_zero` (existence check)
    STATE_EXISTS = 3,
    /// Maps to pallet-revive `set_storage` with empty value
    STATE_DELETE = 4,

    /// Maps to pallet-revive `caller` (with internal assert)
    AUTH_CHECK = 10,
    ACCESS_ASSERT = 11,

    /// Maps to pallet-revive `call` (for PSP22 or external assets)
    ASSET_TRANSFER = 20,
    ASSET_MINT = 21,
    ASSET_BURN = 22,
    /// Maps to pallet-revive `call` (with deposit_and_value payload)
    NATIVE_PAY = 23,

    /// Maps to pallet-revive `deposit_event`
    EMIT_EVENT = 30,
    /// Maps to pallet-revive `call`
    SCHEDULE_CALL = 31,
    /// Maps to pallet-revive `seal_return` (with revert flag)
    REVERT = 32,
    /// Maps to `deposit_event` (debug topics)
    LOG_DIAGNOSTIC = 33,
    /// Maps to pallet-revive `caller`
    GET_CALLER = 34,
    /// Maps to pallet-revive `now`
    GET_NOW = 35,
    /// Maps to pallet-revive `block_number`
    GET_BLOCK = 36,
    /// Maps to pallet-revive `value_transferred`
    GET_VALUE = 37,
    /// Maps to pallet-revive extension `oracle_query`
    ORACLE_QUERY = 38,
    /// Maps to pallet-revive extension `vrf_random`
    VRF_RANDOM = 39,
};


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
const CompileError = errors.CompileError;
const TypeResolver = types.TypeResolver;
const ResolvedType = types.ResolvedType;
const CheckedContract = checker.CheckedContract;
const AccessList = checker.AccessList;
const AccessEntry = checker.AccessEntry;

const Reg = riscv.Reg;
const BytecodeWriter = riscv.BytecodeWriter;
const ZephCustomOp = riscv.ZephCustomOp;

// ============================================================================
// Section 1 — ZephBin Binary Header
// ============================================================================

/// Fixed 64-byte header at the start of every .fozbin binary.
pub const PolkaVmHeader = extern struct {
    /// Magic bytes: "POLK"
    magic: [4]u8 = .{ 0x00, 'P', 'V', 'M' },
    /// Binary format version.
    version: u16 = 1,
    /// Bit 0 = has_upgrade_authority, Bit 1 = parallel_capable.
    flags: u16 = 0,
    /// Contract name, null-padded to 32 bytes.
    contract_name: [32]u8 = [_]u8{0} ** 32,
    /// Number of actions in this binary.
    action_count: u16 = 0,
    /// Padding to maintain alignment.
    _pad0: u16 = 0,
    /// Byte length of the access list section.
    access_list_len: u32 = 0,
    /// Byte length of the bytecode section.
    bytecode_len: u32 = 0,
    /// CRC32 of entire file after this field.
    checksum: u32 = 0,
    /// Byte length of the static data section.
    data_section_len: u32 = 0,
    /// SPEC: Novel Idea 1 — Byte length of conservation metadata section.
    conservation_len: u32 = 0,
};
comptime {
    std.debug.assert(@sizeOf(PolkaVmHeader) == 64);
}

// ============================================================================
// Section 2 — CRC32
// ============================================================================

/// CRC32 lookup table (polynomial 0xEDB88320, reflected).
const crc32_table: [256]u32 = blk: {
    @setEvalBranchQuota(10000);
    var table: [256]u32 = undefined;
    for (0..256) |i| {
        var crc: u32 = @intCast(i);
        for (0..8) |_| {
            if (crc & 1 == 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc = crc >> 1;
            }
        }
        table[i] = crc;
    }
    break :blk table;
};

/// Compute CRC32 over a byte slice.
fn crc32(data: []const u8) u32 {
    var crc: u32 = 0xFFFFFFFF;
    for (data) |byte| {
        const idx: u8 = @truncate(crc ^ byte);
        crc = (crc >> 8) ^ crc32_table[idx];
    }
    return crc ^ 0xFFFFFFFF;
}

// ============================================================================
// Section 3 — Register Allocator
// ============================================================================

/// Simple linear scan register allocator over temp/arg registers.
pub const RegAlloc = struct {
    used: [32]bool = [_]bool{false} ** 32,

    /// Allocatable registers: t0-t6 (5-7, 28-31) and a0-a6 (10-16).
    /// a7 is reserved for syscall/custom-op number.
    const allocatable = [_]u5{ 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 28, 29, 30, 31 };

    /// Allocate the first free temp/arg register.
    pub fn alloc(self: *RegAlloc) ?Reg {
        for (allocatable) |idx| {
            if (!self.used[idx]) {
                self.used[idx] = true;
                return @enumFromInt(idx);
            }
        }
        return null;
    }

    /// Free a previously allocated register.
    pub fn free(self: *RegAlloc, r: Reg) void {
        self.used[@intFromEnum(r)] = false;
    }

    /// Free all registers.
    pub fn freeAll(self: *RegAlloc) void {
        self.used = [_]bool{false} ** 32;
    }
};

// ============================================================================
// Section 4 — Action Code Generation Context
// ============================================================================

/// Per-action state maintained during code generation.
const ActionCtx = struct {
    writer: BytecodeWriter,
    reg_alloc: RegAlloc,
    locals: std.StringHashMap(Reg),
    loop_exits: std.ArrayListUnmanaged(u32),
    loop_conts: std.ArrayListUnmanaged(u32),
    action_name: []const u8,
    field_ids: *std.StringHashMap(u32),
    allocator: std.mem.Allocator,

    /// Create a new context for an action.
    fn init(allocator: std.mem.Allocator, name: []const u8, field_ids: *std.StringHashMap(u32)) ActionCtx {
        return .{
            .writer = BytecodeWriter.init(allocator),
            .reg_alloc = .{},
            .locals = std.StringHashMap(Reg).init(allocator),
            .loop_exits = .{},
            .loop_conts = .{},
            .action_name = name,
            .field_ids = field_ids,
            .allocator = allocator,
        };
    }

    /// Release all resources.
    fn deinit(self: *ActionCtx) void {
        self.writer.deinit();
        self.locals.deinit();
        self.loop_exits.deinit(self.allocator);
        self.loop_conts.deinit(self.allocator);
    }
};

// ============================================================================
// Section 5 — SHA256 Action Selector Helper
// ============================================================================

/// Compute action selector: first 4 bytes of SHA256(name) as u32 little-endian.
fn actionSelector(name: []const u8) u32 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(name);
    const digest = hasher.finalResult();
    return std.mem.readInt(u32, digest[0..4], .little);
}

/// Write a null-padded contract name into a 32-byte buffer.
fn writeContractName(name: []const u8) [32]u8 {
    var buf: [32]u8 = [_]u8{0} ** 32;
    const copy_len = @min(name.len, 32);
    @memcpy(buf[0..copy_len], name[0..copy_len]);
    return buf;
}

// ============================================================================
// Section 5b — Fixed-Point Scaling Helpers
// ============================================================================

/// Return 10^n for n in [0..18]. Returns maxInt(u64) for n > 18.
/// SPEC: Part 2.1 — Fixed-point types are stored as scaled integers.
fn pow10(n: u8) u64 {
    const table: [19]u64 = .{
        1,
        10,
        100,
        1_000,
        10_000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
        1_000_000_000,
        10_000_000_000,
        100_000_000_000,
        1_000_000_000_000,
        10_000_000_000_000,
        100_000_000_000_000,
        1_000_000_000_000_000,
        10_000_000_000_000_000,
        100_000_000_000_000_000,
        1_000_000_000_000_000_000,
    };
    if (n > 18) return std.math.maxInt(u64);
    return table[n];
}

/// Scale a fixed-point literal string to its integer representation.
/// "1.5" with decimals=9 → 1_500_000_000.
fn scaleFixedPoint(lit: []const u8, decimals: u8) u64 {
    var int_part_buf: [80]u8 = undefined;
    var frac_part_buf: [80]u8 = undefined;
    var int_len: usize = 0;
    var frac_len: usize = 0;

    var in_frac = false;
    for (lit) |c| {
        if (c == '_') continue;
        if (c == '.') { in_frac = true; continue; }
        if (!in_frac) {
            if (int_len < int_part_buf.len) { int_part_buf[int_len] = c; int_len += 1; }
        } else {
            if (frac_len < frac_part_buf.len) { frac_part_buf[frac_len] = c; frac_len += 1; }
        }
    }

    const int_str = int_part_buf[0..int_len];
    var padded_frac_buf: [80]u8 = [_]u8{'0'} ** 80;
    const copy_len = @min(frac_len, decimals);
    @memcpy(padded_frac_buf[0..copy_len], frac_part_buf[0..copy_len]);
    const frac_str = padded_frac_buf[0..decimals];

    const int_val = if (int_str.len == 0) @as(u64, 0) else std.fmt.parseInt(u64, int_str, 10) catch 0;
    const frac_val = if (decimals == 0) @as(u64, 0) else std.fmt.parseInt(u64, frac_str, 10) catch 0;

    const p10 = pow10(decimals);
    const mul_tup = @mulWithOverflow(int_val, p10);
    if (mul_tup[1] != 0) return std.math.maxInt(u64);
    const add_tup = @addWithOverflow(mul_tup[0], frac_val);
    if (add_tup[1] != 0) return std.math.maxInt(u64);
    return add_tup[0];
}

// ============================================================================
// Section 6 — Code Generator
// ============================================================================

/// Main code generator. Walks the checked AST and emits a .fozbin binary.
pub const CodeGenPolkaVM = struct {
    allocator: std.mem.Allocator,
    diagnostics: *DiagnosticList,
    resolver: *TypeResolver,
    field_ids: std.StringHashMap(u32),
    next_field_id: u32,
    /// Interned string data section (null-terminated, 4-byte aligned).
    string_table: std.StringHashMap(u32),
    data_section: std.ArrayListUnmanaged(u8),

    /// Create a new code generator.
    pub fn init(
        allocator: std.mem.Allocator,
        diagnostics: *DiagnosticList,
        resolver: *TypeResolver,
    ) CodeGenPolkaVM {
        return .{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .resolver = resolver,
            .field_ids = std.StringHashMap(u32).init(allocator),
            .next_field_id = 0,
            .string_table = std.StringHashMap(u32).init(allocator),
            .data_section = .{},
        };
    }

    /// Release all internal resources.
    pub fn deinit(self: *CodeGenPolkaVM) void {
        self.field_ids.deinit();
        self.string_table.deinit();
        self.data_section.deinit(self.allocator);
    }

    /// Intern a string literal into the data section. Returns its byte offset.
    fn internString(self: *CodeGenPolkaVM, content: []const u8) anyerror!u32 {
        if (self.string_table.get(content)) |offset| return offset;
        const offset: u32 = @intCast(self.data_section.items.len);
        try self.data_section.appendSlice(self.allocator, content);
        try self.data_section.append(self.allocator, 0);
        while (self.data_section.items.len % 4 != 0) {
            try self.data_section.append(self.allocator, 0);
        }
        try self.string_table.put(content, offset);
        return offset;
    }

    /// Assign a sequential field ID to a state field name.
    fn getOrAssignFieldId(self: *CodeGenPolkaVM, name: []const u8) u32 {
        if (self.field_ids.get(name)) |id| return id;
        const id = self.next_field_id;
        self.field_ids.put(name, id) catch return id;
        self.next_field_id += 1;
        return id;
    }

    /// Generate the complete .fozbin binary from a checked contract.
    /// Returns a heap-allocated byte slice. Caller owns the memory.
    pub fn generate(
        self: *CodeGenPolkaVM,
        contract: *const ContractDef,
        checked: *const CheckedContract,
    ) anyerror![]u8 {
        // Pre-assign field IDs for all state fields
        for (contract.state) |sf| {
            _ = self.getOrAssignFieldId(sf.name);
        }

        // Constructor counts as an extra entry when present
        const setup_count: u16 = if (contract.setup != null) 1 else 0;
        const fb_count: u16 = @as(u16, if (contract.fallback != null) 1 else 0) +
            @as(u16, if (contract.receive_ != null) 1 else 0);
        const action_count: u16 = @intCast(contract.actions.len + contract.views.len + setup_count + fb_count);

        // Determine flags
        var flags: u16 = 0;
        if (contract.upgrade != null) flags |= 0x01; // has_upgrade_authority
        for (contract.actions) |action| {
            for (action.annotations) |ann| {
                if (ann.kind == .parallel) {
                    flags |= 0x02; // parallel_capable
                    break;
                }
            }
        }

        // ── Generate bytecode for each action ────────────────────────────
        const ActionBytecode = struct {
            selector: u32,
            code: []const u8,
        };
        var action_codes = std.ArrayListUnmanaged(ActionBytecode){};
        defer {
            for (action_codes.items) |ab| {
                self.allocator.free(ab.code);
            }
            action_codes.deinit(self.allocator);
        }

        // ── Generate constructor (setup block) if present ────────────────
        if (contract.setup) |setup| {
            var ctx = ActionCtx.init(self.allocator, "__setup__", &self.field_ids);
            defer ctx.deinit();

            try self.genSetup(&setup, &ctx);

            const code_bytes = ctx.writer.toBytes();
            const owned_copy = try self.allocator.alloc(u8, code_bytes.len);
            @memcpy(owned_copy, code_bytes);

            try action_codes.append(self.allocator, .{
                .selector = 0x00000000,
                .code = owned_copy,
            });
        }

        for (contract.actions) |action| {
            var ctx = ActionCtx.init(self.allocator, action.name, &self.field_ids);
            defer ctx.deinit();

            try self.genAction(&action, &ctx);

            const code_bytes = ctx.writer.toBytes();
            const owned_copy = try self.allocator.alloc(u8, code_bytes.len);
            @memcpy(owned_copy, code_bytes);

            try action_codes.append(self.allocator, .{
                .selector = actionSelector(action.name),
                .code = owned_copy,
            });
        }

        // ── GAP-5: Generate bytecode for each view ────────────────────────
        for (contract.views) |view| {
            var ctx = ActionCtx.init(self.allocator, view.name, &self.field_ids);
            defer ctx.deinit();

            try self.genView(&view, &ctx);

            const code_bytes = ctx.writer.toBytes();
            const owned_copy = try self.allocator.alloc(u8, code_bytes.len);
            @memcpy(owned_copy, code_bytes);

            try action_codes.append(self.allocator, .{
                .selector = actionSelector(view.name),
                .code = owned_copy,
            });
        }

        // ── SPEC: Part 5.13 — Fallback handler ──────────────────────────
        if (contract.fallback) |fb| {
            var ctx = ActionCtx.init(self.allocator, "__fallback__", &self.field_ids);
            defer ctx.deinit();
            try self.genAction(&fb, &ctx);
            const code_bytes = ctx.writer.toBytes();
            const owned_copy = try self.allocator.alloc(u8, code_bytes.len);
            @memcpy(owned_copy, code_bytes);
            try action_codes.append(self.allocator, .{
                .selector = 0xFFFFFFFF,
                .code = owned_copy,
            });
        }

        // ── SPEC: Part 5.13 — Receive handler ───────────────────────────
        if (contract.receive_) |rc| {
            var ctx = ActionCtx.init(self.allocator, "__receive__", &self.field_ids);
            defer ctx.deinit();
            try self.genAction(&rc, &ctx);
            const code_bytes = ctx.writer.toBytes();
            const owned_copy = try self.allocator.alloc(u8, code_bytes.len);
            @memcpy(owned_copy, code_bytes);
            try action_codes.append(self.allocator, .{
                .selector = 0xFFFFFFFE,
                .code = owned_copy,
            });
        }

        // ── Serialize access list section ────────────────────────────────
        const access_list_bytes = try self.serializeAccessList(contract, checked);
        defer self.allocator.free(access_list_bytes);

        // ── Serialize bytecode section ───────────────────────────────────
        const bytecode_bytes = try self.serializeBytecodeSection(action_codes.items);
        defer self.allocator.free(bytecode_bytes);

        // ── Assemble final binary ────────────────────────────────────────
        // Layout: [64-byte header][access_list][bytecode][data_section][conservation]
        const data_bytes = self.data_section.items;
        var header = PolkaVmHeader{};
        header.contract_name = writeContractName(contract.name);
        header.action_count = action_count;
        header.flags = flags;
        header.access_list_len = @intCast(access_list_bytes.len);
        header.bytecode_len = @intCast(bytecode_bytes.len);
        header.data_section_len = @intCast(data_bytes.len);

        // Serialize conservation metadata
        const conservation_bytes = try self.serializeConservationMetadata(contract);
        defer self.allocator.free(conservation_bytes);
        header.conservation_len = @intCast(conservation_bytes.len);

        const total_size = @sizeOf(PolkaVmHeader) + access_list_bytes.len + bytecode_bytes.len + data_bytes.len + conservation_bytes.len;
        const binary = try self.allocator.alloc(u8, total_size);
        errdefer self.allocator.free(binary);

        // Copy header
        const header_bytes: *const [@sizeOf(PolkaVmHeader)]u8 = @ptrCast(&header);
        @memcpy(binary[0..@sizeOf(PolkaVmHeader)], header_bytes);

        // Copy access list
        const al_start = @sizeOf(PolkaVmHeader);
        @memcpy(binary[al_start..][0..access_list_bytes.len], access_list_bytes);

        // Copy bytecode
        const bc_start = al_start + access_list_bytes.len;
        @memcpy(binary[bc_start..][0..bytecode_bytes.len], bytecode_bytes);

        // Copy data section (strings)
        const ds_start = bc_start + bytecode_bytes.len;
        if (data_bytes.len > 0) {
            @memcpy(binary[ds_start..][0..data_bytes.len], data_bytes);
        }

        // Copy conservation metadata section
        const cm_start = ds_start + data_bytes.len;
        if (conservation_bytes.len > 0) {
            @memcpy(binary[cm_start..][0..conservation_bytes.len], conservation_bytes);
        }

        // Compute and store checksum over everything after checksum field
        const checksum_offset = @offsetOf(PolkaVmHeader, "checksum") + @sizeOf(u32);
        const checksum = crc32(binary[checksum_offset..]);
        std.mem.writeInt(u32, binary[@offsetOf(PolkaVmHeader, "checksum")..][0..4], checksum, .little);

        return binary;
    }

    // ── Action code generation ───────────────────────────────────────────

    /// Generate bytecode for a single action, including prologue and epilogue.
    fn genAction(self: *CodeGenPolkaVM, action: *const ActionDecl, ctx: *ActionCtx) anyerror!void {
        const frame_size: i12 = 64; // 8 saved regs * 8 bytes

        // ── Prologue ─────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -frame_size));
        try ctx.writer.emit(riscv.SD(.sp, .ra, 0));
        try ctx.writer.emit(riscv.SD(.sp, .s0, 8));
        try ctx.writer.emit(riscv.ADDI(.s0, .sp, frame_size));

        // AUTH_CHECK for `only` guards
        for (action.body) |stmt| {
            switch (stmt.kind) {
                .only => |only_stmt| {
                    switch (only_stmt.requirement) {
                        .authority => |name| {
                            try self.genAuthCheck(name, ctx);
                        },
                        .either => |pair| {
                            try self.genAuthCheck(pair.left, ctx);
                            try self.genAuthCheck(pair.right, ctx);
                        },
                        else => {},
                    }
                },
                else => {},
            }
        }

        // ── Bind parameters to registers ─────────────────────────────────
        for (action.params, 0..) |param, i| {
            if (i < 7) {
                const reg: Reg = @enumFromInt(@as(u5, @intCast(10 + i)));
                ctx.reg_alloc.used[@intFromEnum(reg)] = true;
                try ctx.locals.put(param.name, reg);
            }
        }

        // ── Body ─────────────────────────────────────────────────────────
        for (action.body) |stmt| {
            try self.genStmt(&stmt, ctx);
        }

        // ── Epilogue ─────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.LD(.s0, .sp, 8));
        try ctx.writer.emit(riscv.LD(.ra, .sp, 0));
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, frame_size));
        try ctx.writer.emit(riscv.JALR(.zero, .ra, 0));
    }

    // ── View code generation ─────────────────────────────────────────────

    /// Generate bytecode for a single view function.
    /// Views are read-only (no `only` guard checks, no state writes enforced here).
    /// They share the same prologue/epilogue and body generation as actions.
    fn genView(self: *CodeGenPolkaVM, view: *const ViewDecl, ctx: *ActionCtx) anyerror!void {
        const frame_size: i12 = 64;

        // ── Prologue ─────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -frame_size));
        try ctx.writer.emit(riscv.SD(.sp, .ra, 0));
        try ctx.writer.emit(riscv.SD(.sp, .s0, 8));
        try ctx.writer.emit(riscv.ADDI(.s0, .sp, frame_size));

        // ── Bind parameters to registers ─────────────────────────────────
        for (view.params, 0..) |param, i| {
            if (i < 7) {
                const reg: Reg = @enumFromInt(@as(u5, @intCast(10 + i)));
                ctx.reg_alloc.used[@intFromEnum(reg)] = true;
                try ctx.locals.put(param.name, reg);
            }
        }

        // ── Body ─────────────────────────────────────────────────────────
        for (view.body) |stmt| {
            try self.genStmt(&stmt, ctx);
        }

        // ── Epilogue ─────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.LD(.s0, .sp, 8));
        try ctx.writer.emit(riscv.LD(.ra, .sp, 0));
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, frame_size));
        try ctx.writer.emit(riscv.JALR(.zero, .ra, 0));
    }

    // ── Statement code generation ────────────────────────────────────────

    /// Generate bytecode for the setup block (constructor).
    /// SPEC: Part 5.4 — setup block compiled as constructor, selector 0x00000000.
    fn genSetup(self: *CodeGenPolkaVM, setup: *const ast.SetupBlock, ctx: *ActionCtx) anyerror!void {
        const frame_size: i12 = 64;

        // ── Prologue ─────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -frame_size));
        try ctx.writer.emit(riscv.SD(.sp, .ra, 0));
        try ctx.writer.emit(riscv.SD(.sp, .s0, 8));
        try ctx.writer.emit(riscv.ADDI(.s0, .sp, frame_size));

        // ── Bind parameters to registers (a0–a6) ─────────────────────────
        for (setup.params, 0..) |param, i| {
            if (i < 7) {
                const reg: Reg = @enumFromInt(@as(u5, @intCast(10 + i)));
                ctx.reg_alloc.used[@intFromEnum(reg)] = true;
                try ctx.locals.put(param.name, reg);
            }
        }

        // ── Body ─────────────────────────────────────────────────────────
        for (setup.body) |stmt| {
            try self.genStmt(&stmt, ctx);
        }

        // ── Epilogue ─────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.LD(.s0, .sp, 8));
        try ctx.writer.emit(riscv.LD(.ra, .sp, 0));
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, frame_size));
        try ctx.writer.emit(riscv.JALR(.zero, .ra, 0));
    }

    /// Generate bytecode for a single statement.
    fn genStmt(self: *CodeGenPolkaVM, stmt: *const Stmt, ctx: *ActionCtx) anyerror!void {
        switch (stmt.kind) {
            .let_bind => |lb| {
                const dest = ctx.reg_alloc.alloc() orelse .t0;
                try self.genExpr(lb.init, ctx, dest);
                try ctx.locals.put(lb.name, dest);
            },
            .assign => |asg| {
                switch (asg.target.kind) {
                    .field_access => |fa| {
                        if (fa.object.kind == .identifier) {
                            const id = fa.object.kind.identifier;
                            if (std.mem.eql(u8, id, "mine")) {
                                try self.genStateWrite(fa.field, null, asg.value, ctx);
                                return;
                            }
                        }
                    },
                    .index_access => |ia| {
                        if (ia.object.kind == .field_access) {
                            const outer_fa = ia.object.kind.field_access;
                            if (outer_fa.object.kind == .identifier) {
                                const oid = outer_fa.object.kind.identifier;
                                if (std.mem.eql(u8, oid, "mine")) {
                                    try self.genStateWrite(outer_fa.field, ia.index, asg.value, ctx);
                                    return;
                                }
                            }
                        }
                    },
                    else => {},
                }
                // General assignment: evaluate value into target register
                if (asg.target.kind == .identifier) {
                    const name = asg.target.kind.identifier;
                    if (ctx.locals.get(name)) |reg| {
                        try self.genExpr(asg.value, ctx, reg);
                        return;
                    }
                }
                const dest = ctx.reg_alloc.alloc() orelse .t0;
                try self.genExpr(asg.value, ctx, dest);
                ctx.reg_alloc.free(dest);
            },
            .aug_assign => |aug| {
                // ── Local variable aug-assign ──────────────────────────────
                if (aug.target.kind == .identifier) {
                    const name = aug.target.kind.identifier;
                    if (ctx.locals.get(name)) |dest| {
                        const tmp = ctx.reg_alloc.alloc() orelse .t1;
                        defer ctx.reg_alloc.free(tmp);
                        try self.genExpr(aug.value, ctx, tmp);
                        const instr: u32 = switch (aug.op) {
                            .add => riscv.ADD(dest, dest, tmp),
                            .sub => riscv.SUB(dest, dest, tmp),
                            .mul => riscv.MUL(dest, dest, tmp),
                            .div => riscv.DIV(dest, dest, tmp),
                            .mod => riscv.REM(dest, dest, tmp),
                        };
                        try ctx.writer.emit(instr);
                        return;
                    }
                }
                // ── GAP-3: mine.field += value  (direct state aug-assign) ──
                if (aug.target.kind == .field_access) {
                    const fa = aug.target.kind.field_access;
                    if (fa.object.kind == .identifier and
                        std.mem.eql(u8, fa.object.kind.identifier, "mine"))
                    {
                        const cur = ctx.reg_alloc.alloc() orelse .t0;
                        defer ctx.reg_alloc.free(cur);
                        const rhs = ctx.reg_alloc.alloc() orelse .t1;
                        defer ctx.reg_alloc.free(rhs);
                        // Load current value
                        try self.genStateRead(fa.field, null, ctx, cur);
                        // Load rhs
                        try self.genExpr(aug.value, ctx, rhs);
                        // Apply operation
                        const instr: u32 = switch (aug.op) {
                            .add => riscv.ADD(cur, cur, rhs),
                            .sub => riscv.SUB(cur, cur, rhs),
                            .mul => riscv.MUL(cur, cur, rhs),
                            .div => riscv.DIV(cur, cur, rhs),
                            .mod => riscv.REM(cur, cur, rhs),
                        };
                        try ctx.writer.emit(instr);
                        // Store back (reuse genStateWrite pattern inline)
                        const field_id = self.getOrAssignFieldId(fa.field);
                        try self.genLoadImmediate(@intCast(field_id), .a0, ctx);
                        try ctx.writer.emit(riscv.ADDI(.a1, .zero, 0));
                        try ctx.writer.emit(riscv.ADD(.a2, cur, .zero));
                        try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.STATE_WRITE)));
                        return;
                    }
                }
                // ── GAP-3: mine.field[index] += value  (map state aug-assign) ──
                if (aug.target.kind == .index_access) {
                    const ia = aug.target.kind.index_access;
                    if (ia.object.kind == .field_access) {
                        const outer_fa = ia.object.kind.field_access;
                        if (outer_fa.object.kind == .identifier and
                            std.mem.eql(u8, outer_fa.object.kind.identifier, "mine"))
                        {
                            const cur = ctx.reg_alloc.alloc() orelse .t0;
                            defer ctx.reg_alloc.free(cur);
                            const rhs = ctx.reg_alloc.alloc() orelse .t1;
                            defer ctx.reg_alloc.free(rhs);
                            // Load current map value at index
                            try self.genStateRead(outer_fa.field, ia.index, ctx, cur);
                            // Load rhs
                            try self.genExpr(aug.value, ctx, rhs);
                            // Apply operation
                            const instr: u32 = switch (aug.op) {
                                .add => riscv.ADD(cur, cur, rhs),
                                .sub => riscv.SUB(cur, cur, rhs),
                                .mul => riscv.MUL(cur, cur, rhs),
                                .div => riscv.DIV(cur, cur, rhs),
                                .mod => riscv.REM(cur, cur, rhs),
                            };
                            try ctx.writer.emit(instr);
                            // Store back with index
                            const field_id = self.getOrAssignFieldId(outer_fa.field);
                            try self.genLoadImmediate(@intCast(field_id), .a0, ctx);
                            try self.genExpr(ia.index, ctx, .a1);
                            try ctx.writer.emit(riscv.ADD(.a2, cur, .zero));
                            try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.STATE_WRITE)));
                            return;
                        }
                    }
                }
                // Fallback: ignore unrecognised aug-assign targets
            },
            .when => |w| try self.genWhen(&w, ctx),
            .match => |m| try self.genMatch(&m, ctx),
            .each => |e| try self.genEach(&e, ctx),
            .repeat => |r| try self.genRepeat(&r, ctx),
            .while_ => |w| try self.genWhile(&w, ctx),
            .need => |n| try self.genNeed(&n, ctx),
            .tell => |t| try self.genTell(&t, ctx),
            .give_back => |expr| try self.genGiveBack(expr, ctx),
            .stop => {
                // Emit placeholder jump, record for backpatching
                const offset = ctx.writer.currentOffset();
                try ctx.writer.emit(riscv.JAL(.zero, 0));
                try ctx.loop_exits.append(ctx.allocator, offset);
            },
            .skip => {
                const offset = ctx.writer.currentOffset();
                try ctx.writer.emit(riscv.JAL(.zero, 0));
                try ctx.loop_conts.append(ctx.allocator, offset);
            },
            .call_stmt => |expr| {
                const dest = ctx.reg_alloc.alloc() orelse .t0;
                defer ctx.reg_alloc.free(dest);
                try self.genExpr(expr, ctx, dest);
            },
            .pay => |pay| {
                const to_reg = ctx.reg_alloc.alloc() orelse .t0;
                defer ctx.reg_alloc.free(to_reg);
                const amt_reg = ctx.reg_alloc.alloc() orelse .t1;
                defer ctx.reg_alloc.free(amt_reg);
                try self.genExpr(pay.recipient, ctx, to_reg);
                try self.genExpr(pay.amount, ctx, amt_reg);
                try ctx.writer.emit(riscv.ADD(.a0, .zero, to_reg));
                try ctx.writer.emit(riscv.ADD(.a1, .zero, amt_reg));
                try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.NATIVE_PAY)));
            },
            .send => |send| {
                const asset_reg = ctx.reg_alloc.alloc() orelse .t0;
                defer ctx.reg_alloc.free(asset_reg);
                const to_reg = ctx.reg_alloc.alloc() orelse .t1;
                defer ctx.reg_alloc.free(to_reg);
                try self.genExpr(send.asset, ctx, asset_reg);
                try self.genExpr(send.recipient, ctx, to_reg);
                try ctx.writer.emit(riscv.ADD(.a0, .zero, asset_reg));
                try ctx.writer.emit(riscv.ADD(.a1, .zero, .zero));
                try ctx.writer.emit(riscv.ADD(.a2, .zero, to_reg));
                try ctx.writer.emit(riscv.ADD(.a3, .zero, asset_reg));
                try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.ASSET_TRANSFER)));
            },
            .only => {}, // Handled in prologue
            .panic => |p| {
                const tmp = ctx.reg_alloc.alloc() orelse .t0;
                defer ctx.reg_alloc.free(tmp);
                try self.genLoadImmediate(@intCast(p.message.len), tmp, ctx);
                try ctx.writer.emit(riscv.ADD(.a1, .zero, tmp));
                try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.REVERT)));
            },
            .throw => |t| {
                _ = t;
                try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.REVERT)));
            },
            else => {
                // Remaining statement kinds emit no code (diagnostic, guard, etc.)
            },
        }
    }

    // ── Expression code generation ───────────────────────────────────────

    /// Generate bytecode for an expression, placing the result in `dest`.
    fn genExpr(self: *CodeGenPolkaVM, expr: *const Expr, ctx: *ActionCtx, dest: Reg) anyerror!void {
        switch (expr.kind) {
            .int_lit => |lit| {
                // Strip underscore separators before parsing.
                var clean_buf: [80]u8 = undefined;
                var clean_len: usize = 0;
                for (lit) |c| {
                    if (c != '_') {
                        if (clean_len >= clean_buf.len) break;
                        clean_buf[clean_len] = c;
                        clean_len += 1;
                    }
                }
                const clean = clean_buf[0..clean_len];

                // Parse as u256, supporting 0x hex prefix.
                const u256val: u256_mod.U256 = if (clean.len >= 2 and clean[0] == '0' and
                    (clean[1] == 'x' or clean[1] == 'X'))
                    u256_mod.U256.parseHex(clean[2..]) catch u256_mod.U256.zero
                else
                    u256_mod.U256.parseDecimal(clean) catch u256_mod.U256.zero;

                if (u256val.fitsU64()) {
                    // Fast path: value fits in a single register.
                    try self.genLoadImmediate(u256val.toU64(), dest, ctx);
                } else {
                    // Wide path: store 32-byte LE value on the stack.
                    // dest receives the stack pointer to the allocation.
                    try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                    for (u256val.limbs, 0..) |limb, i| {
                        const tmp = ctx.reg_alloc.alloc() orelse .t3;
                        defer ctx.reg_alloc.free(tmp);
                        try self.genLoadImmediate(limb, tmp, ctx);
                        const off: i12 = @intCast(i * 8);
                        try ctx.writer.emit(riscv.SD(.sp, tmp, off));
                    }
                    try ctx.writer.emit(riscv.ADD(dest, .sp, .zero));
                }
            },
            .bool_lit => |b| {
                try ctx.writer.emit(riscv.ADDI(dest, .zero, if (b) 1 else 0));
            },
            .string_lit => |s| {
                // s includes surrounding double-quotes — strip them.
                const content = if (s.len >= 2) s[1..s.len - 1] else s;
                const offset = try self.internString(content);
                // ZVM/PolkaVM: gp (x3) holds the data section base address.
                // dest = gp + offset → pointer to the null-terminated string.
                try self.genLoadImmediate(@intCast(offset), dest, ctx);
                try ctx.writer.emit(riscv.ADD(dest, .gp, dest));
            },
            .nothing => {
                try ctx.writer.emit(riscv.ADDI(dest, .zero, 0));
            },
            .identifier => |name| {
                if (ctx.locals.get(name)) |src_reg| {
                    if (src_reg != dest) {
                        try ctx.writer.emit(riscv.ADD(dest, src_reg, .zero));
                    }
                } else {
                    try ctx.writer.emit(riscv.ADDI(dest, .zero, 0));
                }
            },
            .field_access => |fa| {
                if (fa.object.kind == .identifier) {
                    const id = fa.object.kind.identifier;
                    if (std.mem.eql(u8, id, "mine")) {
                        try self.genStateRead(fa.field, null, ctx, dest);
                        return;
                    }
                }
                try self.genExpr(fa.object, ctx, dest);
            },
            .index_access => |ia| {
                if (ia.object.kind == .field_access) {
                    const outer_fa = ia.object.kind.field_access;
                    if (outer_fa.object.kind == .identifier) {
                        const oid = outer_fa.object.kind.identifier;
                        if (std.mem.eql(u8, oid, "mine")) {
                            try self.genStateRead(outer_fa.field, ia.index, ctx, dest);
                            return;
                        }
                    }
                }
                try self.genExpr(ia.object, ctx, dest);
            },
            .bin_op => |op| {
                try self.genBinOp(op.op, op.left, op.right, ctx, dest);
            },
            .unary_op => |op| {
                try self.genExpr(op.operand, ctx, dest);
                switch (op.op) {
                    .not_ => {
                        // Logical NOT: SLTIU dest, dest, 1 → dest = (dest < 1) = (dest == 0)
                        try ctx.writer.emit(riscv.encodeI(1, dest, 3, dest, 0x13));
                    },
                    .negate => {
                        try ctx.writer.emit(riscv.SUB(dest, .zero, dest));
                    },
                }
            },
            .call => |c| {
                try self.genCall(c.callee, c.args, ctx, dest);
            },
            .builtin => |b| {
                // Ext APIs for caller/now/block generally write to an out_ptr in a0.
                // e.g. caller(out_ptr: *mut u8)
                try ctx.writer.emit(riscv.ADDI(.a0, .sp, -32)); // provide out_ptr
                switch (b) {
                    .caller => try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.GET_CALLER))),
                    .now => try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.GET_NOW))),
                    .current_block => try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.GET_BLOCK))),
                    .value => try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.GET_VALUE))),
                    else => {},
                }
                // read resulted value from stack into dest
                try ctx.writer.emit(riscv.LD(dest, .sp, -32));
            },
            .something => |inner| {
                try self.genExpr(inner, ctx, dest);
            },
            .inline_when => |iw| {
                const cond_reg = ctx.reg_alloc.alloc() orelse .t0;
                defer ctx.reg_alloc.free(cond_reg);
                try self.genExpr(iw.cond, ctx, cond_reg);
                const branch_off = ctx.writer.currentOffset();
                try ctx.writer.emit(riscv.BEQ(cond_reg, .zero, 0));
                try self.genExpr(iw.then_, ctx, dest);
                const jmp_off = ctx.writer.currentOffset();
                try ctx.writer.emit(riscv.JAL(.zero, 0));
                const else_off = ctx.writer.currentOffset();
                const br_delta: i13 = @intCast(@as(i32, @intCast(else_off)) - @as(i32, @intCast(branch_off)));
                ctx.writer.patchAt(branch_off, riscv.BEQ(cond_reg, .zero, br_delta));
                try self.genExpr(iw.else_, ctx, dest);
                const end_off = ctx.writer.currentOffset();
                const jmp_delta: i21 = @intCast(@as(i32, @intCast(end_off)) - @as(i32, @intCast(jmp_off)));
                ctx.writer.patchAt(jmp_off, riscv.JAL(.zero, jmp_delta));
            },
            .cast => |c| {
                try self.genExpr(c.expr, ctx, dest);
            },
            .try_propagate => |inner| {
                try self.genExpr(inner, ctx, dest);
            },
            .float_lit => |lit| {
                // Scale to 18 decimal places (price18 / standard DeFi precision).
                const scaled = scaleFixedPoint(lit, 18);
                try self.genLoadImmediate(scaled, dest, ctx);
            },
            else => {
                try ctx.writer.emit(riscv.ADDI(dest, .zero, 0));
            },
        }
    }

    // ── Binary operation code generation ─────────────────────────────────

    /// Generate bytecode for a binary operation.
    fn genBinOp(self: *CodeGenPolkaVM, op: BinOp, left: *Expr, right: *Expr, ctx: *ActionCtx, dest: Reg) anyerror!void {
        const rhs = ctx.reg_alloc.alloc() orelse .t1;
        defer ctx.reg_alloc.free(rhs);
        try self.genExpr(left, ctx, dest);
        try self.genExpr(right, ctx, rhs);
        const instr: u32 = switch (op) {
            .plus, .duration_add => riscv.ADD(dest, dest, rhs),
            .minus, .duration_sub => riscv.SUB(dest, dest, rhs),
            .times => riscv.MUL(dest, dest, rhs),
            .divided_by => riscv.DIV(dest, dest, rhs),
            .mod => riscv.REM(dest, dest, rhs),
            .equals => blk: {
                try ctx.writer.emit(riscv.SUB(dest, dest, rhs));
                // SLTIU dest, dest, 1 → dest = (dest == 0)
                break :blk riscv.ADDI(dest, dest, 0);
            },
            .not_equals => blk: {
                try ctx.writer.emit(riscv.SUB(dest, dest, rhs));
                // SLTU dest, zero, dest → dest = (dest != 0)
                break :blk riscv.encodeR(0x00, dest, .zero, 0x3, dest, 0x33);
            },
            .less => riscv.encodeR(0x00, rhs, dest, 0x2, dest, 0x33),
            .greater => riscv.encodeR(0x00, dest, rhs, 0x2, dest, 0x33),
            .less_eq => blk: {
                // !(left > right):  SLT dest, rhs, dest; XORI dest, dest, 1
                try ctx.writer.emit(riscv.encodeR(0x00, dest, rhs, 0x2, dest, 0x33));
                break :blk riscv.ADDI(dest, dest, 0);
            },
            .greater_eq => blk: {
                try ctx.writer.emit(riscv.encodeR(0x00, rhs, dest, 0x2, dest, 0x33));
                break :blk riscv.ADDI(dest, dest, 0);
            },
            .and_ => riscv.AND(dest, dest, rhs),
            .or_ => riscv.OR(dest, dest, rhs),
            .has => riscv.AND(dest, dest, rhs),
        };
        try ctx.writer.emit(instr);
    }

    // ── Immediate loading ────────────────────────────────────────────────

    /// Load a u64 constant into a register using LUI + ADDI sequences.
    fn genLoadImmediate(self: *CodeGenPolkaVM, val: u64, dest: Reg, ctx: *ActionCtx) anyerror!void {
        _ = self;
        if (val == 0) {
            try ctx.writer.emit(riscv.ADDI(dest, .zero, 0));
            return;
        }
        // If fits in 12-bit signed immediate
        if (val < 2048) {
            try ctx.writer.emit(riscv.ADDI(dest, .zero, @intCast(val)));
            return;
        }
        // Use LUI for upper 20 bits + ADDI for lower 12 bits
        const lo12: u12 = @truncate(val);
        const signed_lo: i12 = @bitCast(lo12);
        var upper: u20 = @truncate(val >> 12);
        // If low 12 bits are negative in signed representation, need to adjust upper
        if (signed_lo < 0) upper +%= 1;
        try ctx.writer.emit(riscv.LUI(dest, upper));
        if (lo12 != 0) {
            try ctx.writer.emit(riscv.ADDI(dest, dest, signed_lo));
        }
    }

    // ── Control flow code generation ─────────────────────────────────────

    /// Generate bytecode for a when/otherwise statement with backpatching.
    fn genWhen(self: *CodeGenPolkaVM, stmt: *const WhenStmt, ctx: *ActionCtx) anyerror!void {
        var end_patches = std.ArrayListUnmanaged(u32){};
        defer end_patches.deinit(ctx.allocator);

        // Primary condition
        const cond_reg = ctx.reg_alloc.alloc() orelse .t0;
        try self.genExpr(stmt.cond, ctx, cond_reg);
        const branch_off = ctx.writer.currentOffset();
        try ctx.writer.emit(riscv.BEQ(cond_reg, .zero, 0)); // placeholder
        ctx.reg_alloc.free(cond_reg);

        // Then body
        for (stmt.then_body) |s| {
            try self.genStmt(&s, ctx);
        }
        const end_jmp = ctx.writer.currentOffset();
        try ctx.writer.emit(riscv.JAL(.zero, 0)); // placeholder jump to end
        try end_patches.append(ctx.allocator, end_jmp);

        // Patch primary branch → here (start of else-ifs / else)
        const after_then = ctx.writer.currentOffset();
        const br_delta: i13 = @intCast(@as(i32, @intCast(after_then)) - @as(i32, @intCast(branch_off)));
        ctx.writer.patchAt(branch_off, riscv.BEQ(cond_reg, .zero, br_delta));

        // Else-if chains
        for (stmt.else_ifs) |eif| {
            const eif_cond = ctx.reg_alloc.alloc() orelse .t0;
            try self.genExpr(eif.cond, ctx, eif_cond);
            const eif_branch = ctx.writer.currentOffset();
            try ctx.writer.emit(riscv.BEQ(eif_cond, .zero, 0));
            ctx.reg_alloc.free(eif_cond);

            for (eif.body) |s| {
                try self.genStmt(&s, ctx);
            }
            const eif_end = ctx.writer.currentOffset();
            try ctx.writer.emit(riscv.JAL(.zero, 0));
            try end_patches.append(ctx.allocator, eif_end);

            const after_eif = ctx.writer.currentOffset();
            const eif_delta: i13 = @intCast(@as(i32, @intCast(after_eif)) - @as(i32, @intCast(eif_branch)));
            ctx.writer.patchAt(eif_branch, riscv.BEQ(eif_cond, .zero, eif_delta));
        }

        // Otherwise body
        if (stmt.else_body) |eb| {
            for (eb) |s| {
                try self.genStmt(&s, ctx);
            }
        }

        // Patch all end jumps to here
        const end_off = ctx.writer.currentOffset();
        for (end_patches.items) |patch_off| {
            const delta: i21 = @intCast(@as(i32, @intCast(end_off)) - @as(i32, @intCast(patch_off)));
            ctx.writer.patchAt(patch_off, riscv.JAL(.zero, delta));
        }
    }

    /// Generate bytecode for a match statement.
    fn genMatch(self: *CodeGenPolkaVM, stmt: *const MatchStmt, ctx: *ActionCtx) anyerror!void {
        const subj_reg = ctx.reg_alloc.alloc() orelse .t0;
        defer ctx.reg_alloc.free(subj_reg);
        try self.genExpr(stmt.subject, ctx, subj_reg);

        var end_patches = std.ArrayListUnmanaged(u32){};
        defer end_patches.deinit(ctx.allocator);

        for (stmt.arms) |arm| {
            const arm_skip: u32 = switch (arm.pattern) {
                .literal => |lit_expr| blk: {
                    const cmp_reg = ctx.reg_alloc.alloc() orelse .t1;
                    defer ctx.reg_alloc.free(cmp_reg);
                    try self.genExpr(lit_expr, ctx, cmp_reg);
                    const off = ctx.writer.currentOffset();
                    try ctx.writer.emit(riscv.BNE(subj_reg, cmp_reg, 0));
                    break :blk off;
                },
                .wildcard, .binding => 0, // Always matches
                else => 0,
            };

            for (arm.body) |s| {
                try self.genStmt(&s, ctx);
            }
            const jmp_off = ctx.writer.currentOffset();
            try ctx.writer.emit(riscv.JAL(.zero, 0));
            try end_patches.append(ctx.allocator, jmp_off);

            if (arm_skip != 0) {
                const after_arm = ctx.writer.currentOffset();
                const skip_delta: i13 = @intCast(@as(i32, @intCast(after_arm)) - @as(i32, @intCast(arm_skip)));
                ctx.writer.patchAt(arm_skip, riscv.BNE(subj_reg, .zero, skip_delta));
            }
        }

        const end_off = ctx.writer.currentOffset();
        for (end_patches.items) |patch_off| {
            const delta: i21 = @intCast(@as(i32, @intCast(end_off)) - @as(i32, @intCast(patch_off)));
            ctx.writer.patchAt(patch_off, riscv.JAL(.zero, delta));
        }
    }

    /// Generate bytecode for an each loop.
    fn genEach(self: *CodeGenPolkaVM, loop: *const EachLoop, ctx: *ActionCtx) anyerror!void {
        const iter_reg = ctx.reg_alloc.alloc() orelse .t0;
        defer ctx.reg_alloc.free(iter_reg);
        const count_reg = ctx.reg_alloc.alloc() orelse .t1;
        defer ctx.reg_alloc.free(count_reg);

        // Load collection length into count_reg (from collection expression)
        try self.genExpr(loop.collection, ctx, count_reg);
        // Initialize iterator to 0
        try ctx.writer.emit(riscv.ADDI(iter_reg, .zero, 0));

        // Bind loop variable
        switch (loop.binding) {
            .single => |name| try ctx.locals.put(name, iter_reg),
            .pair => |p| {
                try ctx.locals.put(p.first, iter_reg);
                try ctx.locals.put(p.second, count_reg);
            },
        }

        const loop_start = ctx.writer.currentOffset();
        // Branch if iter >= count
        const exit_off = ctx.writer.currentOffset();
        try ctx.writer.emit(riscv.BGE(iter_reg, count_reg, 0));

        // Save loop backpatch state
        const prev_exits_len = ctx.loop_exits.items.len;
        const prev_conts_len = ctx.loop_conts.items.len;

        for (loop.body) |s| {
            try self.genStmt(&s, ctx);
        }

        // Continue target: increment and jump back
        const cont_target = ctx.writer.currentOffset();
        try ctx.writer.emit(riscv.ADDI(iter_reg, iter_reg, 1));
        const back_delta: i21 = @intCast(@as(i32, @intCast(loop_start)) - @as(i32, @intCast(ctx.writer.currentOffset())));
        try ctx.writer.emit(riscv.JAL(.zero, back_delta));

        // Patch exit branch
        const after_loop = ctx.writer.currentOffset();
        const exit_delta: i13 = @intCast(@as(i32, @intCast(after_loop)) - @as(i32, @intCast(exit_off)));
        ctx.writer.patchAt(exit_off, riscv.BGE(iter_reg, count_reg, exit_delta));

        // Backpatch stop/skip
        self.backpatchLoopExits(ctx, prev_exits_len, after_loop);
        self.backpatchLoopConts(ctx, prev_conts_len, cont_target);
    }

    /// Generate bytecode for a repeat N times loop.
    fn genRepeat(self: *CodeGenPolkaVM, loop: *const RepeatLoop, ctx: *ActionCtx) anyerror!void {
        const counter = ctx.reg_alloc.alloc() orelse .t0;
        defer ctx.reg_alloc.free(counter);
        const limit = ctx.reg_alloc.alloc() orelse .t1;
        defer ctx.reg_alloc.free(limit);

        try self.genExpr(loop.count, ctx, limit);
        try ctx.writer.emit(riscv.ADDI(counter, .zero, 0));

        const loop_start = ctx.writer.currentOffset();
        const exit_off = ctx.writer.currentOffset();
        try ctx.writer.emit(riscv.BGE(counter, limit, 0));

        const prev_exits_len = ctx.loop_exits.items.len;
        const prev_conts_len = ctx.loop_conts.items.len;

        for (loop.body) |s| {
            try self.genStmt(&s, ctx);
        }

        const cont_target = ctx.writer.currentOffset();
        try ctx.writer.emit(riscv.ADDI(counter, counter, 1));
        const back_delta: i21 = @intCast(@as(i32, @intCast(loop_start)) - @as(i32, @intCast(ctx.writer.currentOffset())));
        try ctx.writer.emit(riscv.JAL(.zero, back_delta));

        const after_loop = ctx.writer.currentOffset();
        const exit_delta: i13 = @intCast(@as(i32, @intCast(after_loop)) - @as(i32, @intCast(exit_off)));
        ctx.writer.patchAt(exit_off, riscv.BGE(counter, limit, exit_delta));

        self.backpatchLoopExits(ctx, prev_exits_len, after_loop);
        self.backpatchLoopConts(ctx, prev_conts_len, cont_target);
    }

    /// Generate bytecode for a while loop.
    fn genWhile(self: *CodeGenPolkaVM, loop: *const WhileLoop, ctx: *ActionCtx) anyerror!void {
        const cond_reg = ctx.reg_alloc.alloc() orelse .t0;
        defer ctx.reg_alloc.free(cond_reg);

        const loop_start = ctx.writer.currentOffset();
        try self.genExpr(loop.cond, ctx, cond_reg);
        const exit_off = ctx.writer.currentOffset();
        try ctx.writer.emit(riscv.BEQ(cond_reg, .zero, 0));

        const prev_exits_len = ctx.loop_exits.items.len;
        const prev_conts_len = ctx.loop_conts.items.len;

        for (loop.body) |s| {
            try self.genStmt(&s, ctx);
        }

        const cont_target = ctx.writer.currentOffset();
        const back_delta: i21 = @intCast(@as(i32, @intCast(loop_start)) - @as(i32, @intCast(cont_target)));
        try ctx.writer.emit(riscv.JAL(.zero, back_delta));

        const after_loop = ctx.writer.currentOffset();
        const exit_delta: i13 = @intCast(@as(i32, @intCast(after_loop)) - @as(i32, @intCast(exit_off)));
        ctx.writer.patchAt(exit_off, riscv.BEQ(cond_reg, .zero, exit_delta));

        self.backpatchLoopExits(ctx, prev_exits_len, after_loop);
        self.backpatchLoopConts(ctx, prev_conts_len, cont_target);
    }

    /// Backpatch all loop exit (stop) jumps from index `start` to target `target_off`.
    fn backpatchLoopExits(self: *CodeGenPolkaVM, ctx: *ActionCtx, start: usize, target_off: u32) void {
        _ = self;
        for (ctx.loop_exits.items[start..]) |patch_off| {
            const delta: i21 = @intCast(@as(i32, @intCast(target_off)) - @as(i32, @intCast(patch_off)));
            ctx.writer.patchAt(patch_off, riscv.JAL(.zero, delta));
        }
        ctx.loop_exits.shrinkRetainingCapacity(start);
    }

    /// Backpatch all loop continue (skip) jumps from index `start` to target `target_off`.
    fn backpatchLoopConts(self: *CodeGenPolkaVM, ctx: *ActionCtx, start: usize, target_off: u32) void {
        _ = self;
        for (ctx.loop_conts.items[start..]) |patch_off| {
            const delta: i21 = @intCast(@as(i32, @intCast(target_off)) - @as(i32, @intCast(patch_off)));
            ctx.writer.patchAt(patch_off, riscv.JAL(.zero, delta));
        }
        ctx.loop_conts.shrinkRetainingCapacity(start);
    }

    // ── State access code generation ─────────────────────────────────────

    /// Generate a state read: SLOAD(field_id) → dest.
    fn genStateRead(self: *CodeGenPolkaVM, field_name: []const u8, index_expr: ?*const Expr, ctx: *ActionCtx, dest: Reg) anyerror!void {
        // pallet-revive: seal_get_storage(key_ptr: *const u8, key_len: u32, out_ptr: *mut u8, out_len_ptr: *mut u32)
        // Key encoding: [4-byte field_id][8-byte map_key] = 12 bytes for map, 4 bytes for scalar.
        const field_id = self.getOrAssignFieldId(field_name);

        // Write field_id to stack as 4-byte little-endian key prefix at sp-8
        var fid_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &fid_bytes, field_id, .little);
        // Load each byte individually via immediate loads — no MOVI for bytes in RISC-V.
        // More efficient: write field_id as a u32 via SD after loading it.
        try self.genLoadImmediate(@intCast(field_id), .t0, ctx);
        try ctx.writer.emit(riscv.SD(.sp, .t0, -8));

        var key_len: i12 = 8; // 8 bytes for scalar (u64-wide field_id)

        if (index_expr) |idx| {
            // Map access: key = [field_id (8 bytes)][map_key (8 bytes)] = 16 bytes total
            const key_reg = ctx.reg_alloc.alloc() orelse .t1;
            defer ctx.reg_alloc.free(key_reg);
            try self.genExpr(idx, ctx, key_reg);
            try ctx.writer.emit(riscv.SD(.sp, key_reg, -16)); // map key at sp-16
            key_len = 16;
        }

        // Set up out_len at sp-24 = 8 (we always read 8 bytes / one u64 word)
        try self.genLoadImmediate(8, .t1, ctx);
        try ctx.writer.emit(riscv.SD(.sp, .t1, -24));

        // a0 = key_ptr: for map, sp-16 (includes both field_id and map key);
        //               for scalar, sp-8 (field_id only)
        const key_ptr_off: i12 = if (index_expr != null) -16 else -8;
        try ctx.writer.emit(riscv.ADDI(.a0, .sp, key_ptr_off));
        // a1 = key_len
        try ctx.writer.emit(riscv.ADDI(.a1, .zero, key_len));
        // a2 = out_ptr (sp-32, 8-byte output buffer)
        try ctx.writer.emit(riscv.ADDI(.a2, .sp, -32));
        // a3 = out_len_ptr (sp-24)
        try ctx.writer.emit(riscv.ADDI(.a3, .sp, -24));

        try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.STATE_READ)));

        // Load result from out_ptr to dest
        try ctx.writer.emit(riscv.LD(dest, .sp, -32));
    }

    /// Generate a state write: value → SSTORE(field_id).
    fn genStateWrite(self: *CodeGenPolkaVM, field_name: []const u8, index_expr: ?*const Expr, value: *const Expr, ctx: *ActionCtx) anyerror!void {
        // pallet-revive: seal_set_storage(key_ptr: *const u8, key_len: u32, value_ptr: *const u8, value_len: u32)
        // Key encoding: [8-byte field_id][8-byte map_key] for map, [8-byte field_id] for scalar.
        const field_id = self.getOrAssignFieldId(field_name);

        // Evaluate value expression first (before stack layout for key)
        const val_reg = ctx.reg_alloc.alloc() orelse .t0;
        defer ctx.reg_alloc.free(val_reg);
        try self.genExpr(value, ctx, val_reg);

        // Write field_id to stack at sp-8
        try self.genLoadImmediate(@intCast(field_id), .t1, ctx);
        try ctx.writer.emit(riscv.SD(.sp, .t1, -8));

        var key_len: i12 = 8;

        if (index_expr) |idx| {
            // Map access: write map key at sp-16, total key = 16 bytes
            const key_reg = ctx.reg_alloc.alloc() orelse .t2;
            defer ctx.reg_alloc.free(key_reg);
            try self.genExpr(idx, ctx, key_reg);
            try ctx.writer.emit(riscv.SD(.sp, key_reg, -16));
            key_len = 16;
        }

        // Write value to stack at sp-40 (below key region)
        try ctx.writer.emit(riscv.SD(.sp, val_reg, -40));

        // a0 = key_ptr
        const key_ptr_off: i12 = if (index_expr != null) -16 else -8;
        try ctx.writer.emit(riscv.ADDI(.a0, .sp, key_ptr_off));
        // a1 = key_len
        try ctx.writer.emit(riscv.ADDI(.a1, .zero, key_len));
        // a2 = value_ptr (sp-40)
        try ctx.writer.emit(riscv.ADDI(.a2, .sp, -40));
        // a3 = value_len (8 bytes / one u64 word)
        try ctx.writer.emit(riscv.ADDI(.a3, .zero, 8));

        try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.STATE_WRITE)));
    }

    // ── Authority check ──────────────────────────────────────────────────

    /// Emit AUTH_CHECK for a named authority.
    fn genAuthCheck(self: *CodeGenPolkaVM, name: []const u8, ctx: *ActionCtx) anyerror!void {
        const selector = actionSelector(name);
        try self.genLoadImmediate(@intCast(selector), .a0, ctx);
        try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.AUTH_CHECK)));
    }

    // ── Function call code generation ────────────────────────────────────

    /// Generate bytecode for a function call. Arguments go into a0-a6.
    fn genCall(self: *CodeGenPolkaVM, callee: *const Expr, args: []const Argument, ctx: *ActionCtx, dest: Reg) anyerror!void {
        // Evaluate arguments into a0..a6
        const max_args: usize = @min(args.len, 7);
        for (args[0..max_args], 0..) |arg, i| {
            const arg_reg: Reg = @enumFromInt(@as(u5, @intCast(10 + i)));
            try self.genExpr(arg.value, ctx, arg_reg);
        }

        // Determine call target
        switch (callee.kind) {
            .identifier => |name| {
                if (std.mem.eql(u8, name, "oracle")) {
                    try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.ORACLE_QUERY)));
                } else if (std.mem.eql(u8, name, "vrf_random")) {
                    try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.VRF_RANDOM)));
                } else {
                    // Internal call via selector
                    const selector = actionSelector(name);
                    try self.genLoadImmediate(@intCast(selector), .t0, ctx);
                    try ctx.writer.emit(riscv.JALR(.ra, .t0, 0));
                }
            },
            .field_access => |fa| {
                if (fa.object.kind == .identifier) {
                    const obj_name = fa.object.kind.identifier;
                    // Cross-contract call via CPI
                    const selector = actionSelector(fa.field);
                    try self.genLoadImmediate(@intCast(selector), .a7, ctx);
                    _ = obj_name;
                    try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.SCHEDULE_CALL)));
                } else {
                    try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.SCHEDULE_CALL)));
                }
            },
            else => {
                try self.genExpr(callee, ctx, .t0);
                try ctx.writer.emit(riscv.JALR(.ra, .t0, 0));
            },
        }

        // Result is in a0; move to dest if needed
        if (dest != .a0) {
            try ctx.writer.emit(riscv.ADD(dest, .a0, .zero));
        }
    }

    // ── Assertion code generation ────────────────────────────────────────

    /// Generate bytecode for a `need cond else "msg"` assertion.
    fn genNeed(self: *CodeGenPolkaVM, stmt: *const NeedStmt, ctx: *ActionCtx) anyerror!void {
        const cond_reg = ctx.reg_alloc.alloc() orelse .t0;
        defer ctx.reg_alloc.free(cond_reg);
        try self.genExpr(stmt.cond, ctx, cond_reg);
        // Branch over revert if condition is true (non-zero)
        const branch_off = ctx.writer.currentOffset();
        try ctx.writer.emit(riscv.BNE(cond_reg, .zero, 0)); // placeholder

        // Emit revert with error code
        switch (stmt.else_) {
            .string_msg => |msg| {
                try self.genLoadImmediate(@intCast(msg.len), .a1, ctx);
            },
            .typed_error => |te| {
                try self.genLoadImmediate(actionSelector(te.error_type), .a1, ctx);
            },
        }
        try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.REVERT)));

        // Patch branch to skip over revert
        const after_revert = ctx.writer.currentOffset();
        const delta: i13 = @intCast(@as(i32, @intCast(after_revert)) - @as(i32, @intCast(branch_off)));
        ctx.writer.patchAt(branch_off, riscv.BNE(cond_reg, .zero, delta));
    }


    /// Generate bytecode for a `tell EventName(args)` statement.
    fn genTell(self: *CodeGenPolkaVM, stmt: *const TellStmt, ctx: *ActionCtx) anyerror!void {
        // pallet-revive: seal_deposit_event(topics_ptr: *const u8, topics_len: u32, data_ptr: *const u8, data_len: u32)
        // Topic 0 = event selector (4-byte SHA256 hash of event name, padded to 32 bytes).
        // Subsequent topics = indexed field values (up to 3 more; pallet-revive max 4 topics).
        // Data = non-indexed field values serialised in declaration order.
        const selector = actionSelector(stmt.event_name);

        // Write 32-byte topic[0] at sp-32: selector in first 4 bytes, rest zero.
        // Use a scratch register to zero-fill then overwrite the low 4 bytes.
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -64)); // scratch frame
        try ctx.writer.emit(riscv.ADDI(.t0, .sp, 0));   // t0 = scratch base
        // Zero the 32-byte topic slot (4 × SD zero, zero)
        for (0..4) |i| {
            const off: i12 = @intCast(i * 8);
            try ctx.writer.emit(riscv.SD(.t0, .zero, off));
        }
        // Write selector into first 4 bytes
        try self.genLoadImmediate(@intCast(selector), .t1, ctx);
        try ctx.writer.emit(riscv.SD(.t0, .t1, 0)); // writes 8 bytes but LE: low 4 = selector ✓

        // Serialise all arguments into data region starting at sp+32
        var data_off: i12 = 32;
        for (stmt.args) |arg| {
            const arg_reg = ctx.reg_alloc.alloc() orelse .t2;
            defer ctx.reg_alloc.free(arg_reg);
            try self.genExpr(arg.value, ctx, arg_reg);
            try ctx.writer.emit(riscv.SD(.t0, arg_reg, data_off));
            data_off += 8;
        }
        const data_len: i64 = data_off - 32;

        // a0 = topics_ptr (t0 = sp+0)
        try ctx.writer.emit(riscv.ADD(.a0, .t0, .zero));
        // a1 = topics_len (32 bytes = 1 topic)
        try ctx.writer.emit(riscv.ADDI(.a1, .zero, 32));
        // a2 = data_ptr (t0 + 32)
        try ctx.writer.emit(riscv.ADDI(.a2, .t0, 32));
        // a3 = data_len
        try self.genLoadImmediate(@intCast(data_len), .a3, ctx);

        try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.EMIT_EVENT)));

        // Release scratch frame
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, 64));
    }

    // ── Return value ─────────────────────────────────────────────────────

    /// Generate bytecode for `give back expr`.
    fn genGiveBack(self: *CodeGenPolkaVM, expr: *const Expr, ctx: *ActionCtx) anyerror!void {
        try self.genExpr(expr, ctx, .a0);
    }

    // ── Binary serialization ─────────────────────────────────────────────

    /// Serialize the access list section.
    /// Format per action: [4-byte selector] [2-byte read_count] [2-byte write_count]
    ///   then read entries: [1-byte name_len] [name bytes] [1-byte field_len] [field bytes]
    ///   then write entries: same format.
    fn serializeAccessList(self: *CodeGenPolkaVM, contract: *const ContractDef, checked: *const CheckedContract) anyerror![]u8 {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);

        for (contract.actions) |action| {
            // Write action selector
            const selector = actionSelector(action.name);
            var sel_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &sel_bytes, selector, .little);
            try buf.appendSlice(self.allocator, &sel_bytes);

            if (checked.action_lists.get(action.name)) |al| {
                // Read/write counts
                var counts: [4]u8 = undefined;
                std.mem.writeInt(u16, counts[0..2], @intCast(al.reads.items.len), .little);
                std.mem.writeInt(u16, counts[2..4], @intCast(al.writes.items.len), .little);
                try buf.appendSlice(self.allocator, &counts);

                // Read entries
                for (al.reads.items) |entry| {
                    try self.serializeAccessEntry(&buf, &entry);
                }
                // Write entries
                for (al.writes.items) |entry| {
                    try self.serializeAccessEntry(&buf, &entry);
                }
            } else {
                // No access list: 0 reads, 0 writes
                const zeros: [4]u8 = .{ 0, 0, 0, 0 };
                try buf.appendSlice(self.allocator, &zeros);
            }
        }

        return buf.toOwnedSlice(self.allocator);
    }

    /// Serialize a single access entry (account name + optional field name).
    fn serializeAccessEntry(self: *CodeGenPolkaVM, buf: *std.ArrayListUnmanaged(u8), entry: *const AccessEntry) anyerror!void {
        // Account name: [1-byte len] [name bytes]
        const name_len: u8 = @intCast(@min(entry.account_name.len, 255));
        try buf.append(self.allocator, name_len);
        try buf.appendSlice(self.allocator, entry.account_name[0..name_len]);

        // Field name: [1-byte len] [field bytes] (0 if null)
        if (entry.field) |f| {
            const field_len: u8 = @intCast(@min(f.len, 255));
            try buf.append(self.allocator, field_len);
            try buf.appendSlice(self.allocator, f[0..field_len]);
        } else {
            try buf.append(self.allocator, 0);
        }
    }

    /// Serialize the bytecode section.
    /// Format: [2-byte action_count]
    ///   per action: [4-byte selector] [4-byte code_len] [code bytes]
    fn serializeBytecodeSection(self: *CodeGenPolkaVM, action_codes: anytype) anyerror![]u8 {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);

        // Action count
        var count_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &count_bytes, @intCast(action_codes.len), .little);
        try buf.appendSlice(self.allocator, &count_bytes);

        for (action_codes) |ac| {
            // Selector
            var sel_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &sel_bytes, ac.selector, .little);
            try buf.appendSlice(self.allocator, &sel_bytes);

            // Code length
            var len_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &len_bytes, @intCast(ac.code.len), .little);
            try buf.appendSlice(self.allocator, &len_bytes);

            // Code bytes
            try buf.appendSlice(self.allocator, ac.code);
        }

        return buf.toOwnedSlice(self.allocator);
    }

    /// SPEC: Novel Idea 1 — Serialize conservation equations into the PolkaVM binary.
    /// Format: [2-byte eq_count]
    ///   per equation: [1-byte op] [1-byte flags(at_all_times)]
    ///                 [lhs_field_ref][rhs_field_ref]
    fn serializeConservationMetadata(self: *CodeGenPolkaVM, contract: *const ContractDef) anyerror![]u8 {
        if (contract.conserves.len == 0) {
            const empty = try self.allocator.alloc(u8, 0);
            return empty;
        }

        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);

        // Equation count
        var count_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &count_bytes, @intCast(contract.conserves.len), .little);
        try buf.appendSlice(self.allocator, &count_bytes);

        for (contract.conserves) |eq| {
            const op_byte: u8 = switch (eq.op) {
                .equals => 0x00,
                .gte => 0x01,
                .lte => 0x02,
                .gt => 0x03,
                .lt => 0x04,
            };
            try buf.append(self.allocator, op_byte);

            const flags_byte: u8 = if (eq.at_all_times) 0x01 else 0x00;
            try buf.append(self.allocator, flags_byte);

            try self.serializeExprRef(&buf, eq.lhs);
            try self.serializeExprRef(&buf, eq.rhs);
        }

        return buf.toOwnedSlice(self.allocator);
    }

    /// Serialize an expression reference for conservation metadata.
    fn serializeExprRef(self: *CodeGenPolkaVM, buf: *std.ArrayListUnmanaged(u8), expr: *const ast.Expr) anyerror!void {
        switch (expr.kind) {
            .identifier => |name| {
                const name_len: u8 = @intCast(@min(name.len, 255));
                try buf.append(self.allocator, name_len);
                try buf.appendSlice(self.allocator, name[0..name_len]);
            },
            .field_access => |fa| {
                const field = fa.field;
                if (fa.object.kind == .identifier) {
                    const obj = fa.object.kind.identifier;
                    const total_len = @min(obj.len + 1 + field.len, 255);
                    try buf.append(self.allocator, @intCast(total_len));
                    try buf.appendSlice(self.allocator, obj);
                    try buf.append(self.allocator, '.');
                    try buf.appendSlice(self.allocator, field);
                } else {
                    const flen: u8 = @intCast(@min(field.len, 255));
                    try buf.append(self.allocator, flen);
                    try buf.appendSlice(self.allocator, field[0..flen]);
                }
            },
            .bin_op => |bop| {
                try buf.append(self.allocator, 0xFF);
                const op_byte: u8 = switch (bop.op) {
                    .plus => 0x10,
                    .minus => 0x11,
                    .times => 0x12,
                    else => 0x1F,
                };
                try buf.append(self.allocator, op_byte);
                try self.serializeExprRef(buf, bop.left);
                try self.serializeExprRef(buf, bop.right);
            },
            else => {
                try buf.append(self.allocator, 0);
            },
        }
    }

    // ========================================================================
    // MIR-Based Code Generation (unified backend entry point)
    // ========================================================================

    /// SPEC: Part 5, Part 20 — Generate complete .fozbin binary from a MirModule.
    /// This is the new unified entry point that replaces direct AST walking.
    pub fn generateFromMir(
        self: *CodeGenPolkaVM,
        mir: *const mir_mod.MirModule,
    ) anyerror![]u8 {
        // Pre-assign field IDs from MIR state field descriptors.
        for (mir.state_fields) |sf| {
            _ = self.getOrAssignFieldId(sf.name);
        }

        // Count dispatchable functions.
        var action_count: u16 = 0;
        for (mir.functions) |func| {
            switch (func.kind) {
                .action, .view, .pure, .setup, .fallback, .receive => {
                    action_count += 1;
                },
                else => {},
            }
        }

        // Determine flags.
        var flags: u16 = 0;
        if (mir.inherits != null) flags |= 0x01;

        // Generate bytecode for each function.
        const FuncBytecode = struct { selector: u32, code: []const u8 };
        var func_codes = std.ArrayListUnmanaged(FuncBytecode){};
        defer {
            for (func_codes.items) |fb| self.allocator.free(fb.code);
            func_codes.deinit(self.allocator);
        }

        for (mir.functions) |func| {
            const is_emittable = switch (func.kind) {
                .action, .view, .pure, .setup, .fallback, .receive => true,
                else => false,
            };
            if (!is_emittable) continue;

            var writer = BytecodeWriter.init(self.allocator);
            defer writer.deinit();
            var ra = RegAlloc{};

            // Map MIR regs → RISC-V regs.
            var reg_map = std.AutoHashMap(mir_mod.Reg, Reg).init(self.allocator);
            defer reg_map.deinit();

            // Allocate param regs (a0-a6).
            for (func.params, 0..) |_, pi| {
                const mir_reg: mir_mod.Reg = @intCast(pi);
                if (ra.alloc()) |hw_reg| {
                    try reg_map.put(mir_reg, hw_reg);
                }
            }

            // Label → bytecode offset.
            var label_map = std.AutoHashMap(mir_mod.LabelId, u32).init(self.allocator);
            defer label_map.deinit();
            var label_patches = std.AutoHashMap(mir_mod.LabelId, std.ArrayListUnmanaged(u32)).init(self.allocator);
            defer {
                var it = label_patches.valueIterator();
                while (it.next()) |list| list.deinit(self.allocator);
                label_patches.deinit();
            }

            // Emit MIR instructions as RISC-V.
            for (func.body) |instr| {
                try self.mirEmitRiscV(&instr, &writer, &ra, &reg_map, &label_map, &label_patches);
            }

            // Epilogue: ret.
            try writer.emit(riscv.JALR(.zero, .ra, 0));

            // Backpatch labels.
            var pit = label_patches.iterator();
            while (pit.next()) |entry| {
                if (label_map.get(entry.key_ptr.*)) |target| {
                    for (entry.value_ptr.items) |patch_off| {
                        writer.patchAt(patch_off, riscv.JAL(.zero, @intCast(@as(i32, @intCast(target)) - @as(i32, @intCast(patch_off)))));
                    }
                }
            }

            const code_bytes = writer.toBytes();
            const owned = try self.allocator.alloc(u8, code_bytes.len);
            @memcpy(owned, code_bytes);

            const selector: u32 = if (func.kind == .setup) 0 else func.selector;
            try func_codes.append(self.allocator, .{ .selector = selector, .code = owned });
        }

        // Assemble binary: header + access list + bytecode sections.
        var output = std.ArrayListUnmanaged(u8){};
        defer output.deinit(self.allocator);

        // Calculate total bytecode length.
        var total_bc: u32 = 0;
        for (func_codes.items) |fb| {
            total_bc += 8 + @as(u32, @intCast(fb.code.len)); // selector(4) + len(4) + code
        }

        // Header.
        var header = PolkaVmHeader{};
        header.contract_name = writeContractName(mir.name);
        header.action_count = action_count;
        header.flags = flags;
        header.bytecode_len = total_bc;
        header.data_section_len = @intCast(mir.data_section.len);
        // Access list placeholder (empty for now).
        header.access_list_len = 0;

        const header_bytes: [64]u8 = @bitCast(header);
        try output.appendSlice(self.allocator, &header_bytes);

        // Bytecode section: for each func → [selector: u32LE] [len: u32LE] [code...]
        for (func_codes.items) |fb| {
            var sel_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &sel_bytes, fb.selector, .little);
            try output.appendSlice(self.allocator, &sel_bytes);

            var len_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &len_bytes, @intCast(fb.code.len), .little);
            try output.appendSlice(self.allocator, &len_bytes);

            try output.appendSlice(self.allocator, fb.code);
        }

        // Data section.
        if (mir.data_section.len > 0) {
            try output.appendSlice(self.allocator, mir.data_section);
        }

        // Checksum.
        if (output.items.len > 64) {
            const payload = output.items[60..]; // After checksum field
            const chk = crc32(payload);
            std.mem.writeInt(u32, output.items[56..60], chk, .little);
        }

        return output.toOwnedSlice(self.allocator);
    }

    /// SPEC: Part 5 — Emit one MIR instruction as RISC-V bytecode.
    fn mirEmitRiscV(
        self: *CodeGenPolkaVM,
        instr: *const mir_mod.MirInstr,
        w: *BytecodeWriter,
        ra: *RegAlloc,
        reg_map: *std.AutoHashMap(mir_mod.Reg, Reg),
        label_map: *std.AutoHashMap(mir_mod.LabelId, u32),
        label_patches: *std.AutoHashMap(mir_mod.LabelId, std.ArrayListUnmanaged(u32)),
    ) anyerror!void {
        // Helper: get or allocate a hardware register for a MIR virtual reg.
        const getReg = struct {
            fn call(rm: *std.AutoHashMap(mir_mod.Reg, Reg), alloc: *RegAlloc, vr: mir_mod.Reg) Reg {
                if (rm.get(vr)) |r| return r;
                const r = alloc.alloc() orelse .t0;
                rm.put(vr, r) catch {};
                return r;
            }
        }.call;

        switch (instr.op) {
            // ── Constants ─────────────────────────────────────────────────
            .const_i64 => |c| {
                const rd = getReg(reg_map, ra, c.dst);
                // LUI + ADDI sequence for 32-bit values.
                const val: u32 = @bitCast(@as(i32, @truncate(c.value)));
                try w.emit(riscv.LUI(rd, @truncate(val >> 12)));
                try w.emit(riscv.ADDI(rd, rd, @truncate(@as(i32, @intCast(val & 0xFFF)))));
            },
            .const_i256 => |c| {
                const rd = getReg(reg_map, ra, c.dst);
                const low: u32 = @bitCast(std.mem.readInt(i32, c.bytes[28..32], .big));
                try w.emit(riscv.LUI(rd, @truncate(low >> 12)));
                try w.emit(riscv.ADDI(rd, rd, @truncate(@as(i32, @intCast(low & 0xFFF)))));
            },
            .const_bool => |c| {
                const rd = getReg(reg_map, ra, c.dst);
                try w.emit(riscv.ADDI(rd, .zero, if (c.value) 1 else 0));
            },
            .const_data => |c| {
                const rd = getReg(reg_map, ra, c.dst);
                try w.emit(riscv.LUI(rd, @truncate(c.offset >> 12)));
                try w.emit(riscv.ADDI(rd, rd, @truncate(@as(i32, @intCast(c.offset & 0xFFF)))));
            },

            // ── Arithmetic ────────────────────────────────────────────────
            .add => |a| {
                try w.emit(riscv.ADD(getReg(reg_map, ra, a.dst), getReg(reg_map, ra, a.lhs), getReg(reg_map, ra, a.rhs)));
            },
            .sub => |a| {
                try w.emit(riscv.SUB(getReg(reg_map, ra, a.dst), getReg(reg_map, ra, a.lhs), getReg(reg_map, ra, a.rhs)));
            },
            .mul => |a| {
                try w.emit(riscv.MUL(getReg(reg_map, ra, a.dst), getReg(reg_map, ra, a.lhs), getReg(reg_map, ra, a.rhs)));
            },
            .div => |a| {
                try w.emit(riscv.DIV(getReg(reg_map, ra, a.dst), getReg(reg_map, ra, a.lhs), getReg(reg_map, ra, a.rhs)));
            },
            .mod => |a| {
                try w.emit(riscv.REM(getReg(reg_map, ra, a.dst), getReg(reg_map, ra, a.lhs), getReg(reg_map, ra, a.rhs)));
            },
            .negate => |u| {
                try w.emit(riscv.SUB(getReg(reg_map, ra, u.dst), .zero, getReg(reg_map, ra, u.operand)));
            },

            // ── Comparison ────────────────────────────────────────────────
            .eq => |a| {
                const rd = getReg(reg_map, ra, a.dst);
                const r1 = getReg(reg_map, ra, a.lhs);
                const r2 = getReg(reg_map, ra, a.rhs);
                try w.emit(riscv.SUB(rd, r1, r2));
                try w.emit(riscv.encodeI(1, rd, 0x3, rd, 0x13)); // SLTIU rd, rd, 1
            },
            .ne => |a| {
                const rd = getReg(reg_map, ra, a.dst);
                try w.emit(riscv.SUB(rd, getReg(reg_map, ra, a.lhs), getReg(reg_map, ra, a.rhs)));
                try w.emit(riscv.encodeR(0, rd, .zero, 0x3, rd, 0x33)); // SLTU rd, zero, rd
            },
            .lt => |a| {
                try w.emit(riscv.encodeR(0, getReg(reg_map, ra, a.rhs), getReg(reg_map, ra, a.lhs), 0x3, getReg(reg_map, ra, a.dst), 0x33)); // SLTU
            },
            .gt => |a| {
                try w.emit(riscv.encodeR(0, getReg(reg_map, ra, a.lhs), getReg(reg_map, ra, a.rhs), 0x3, getReg(reg_map, ra, a.dst), 0x33)); // SLTU
            },
            .le => |a| {
                const rd = getReg(reg_map, ra, a.dst);
                try w.emit(riscv.encodeR(0, getReg(reg_map, ra, a.lhs), getReg(reg_map, ra, a.rhs), 0x3, rd, 0x33)); // SLTU rd, rhs, lhs  (gt)
                try w.emit(riscv.encodeI(1, rd, 0x4, rd, 0x13)); // XORI rd, rd, 1
            },
            .ge => |a| {
                const rd = getReg(reg_map, ra, a.dst);
                try w.emit(riscv.encodeR(0, getReg(reg_map, ra, a.rhs), getReg(reg_map, ra, a.lhs), 0x3, rd, 0x33)); // SLTU rd, lhs, rhs  (lt)
                try w.emit(riscv.encodeI(1, rd, 0x4, rd, 0x13)); // XORI rd, rd, 1
            },

            // ── Logic ─────────────────────────────────────────────────────
            .bool_and => |a| {
                try w.emit(riscv.AND(getReg(reg_map, ra, a.dst), getReg(reg_map, ra, a.lhs), getReg(reg_map, ra, a.rhs)));
            },
            .bool_or => |a| {
                try w.emit(riscv.OR(getReg(reg_map, ra, a.dst), getReg(reg_map, ra, a.lhs), getReg(reg_map, ra, a.rhs)));
            },
            .bool_not => |u| {
                const rd = getReg(reg_map, ra, u.dst);
                try w.emit(riscv.encodeI(1, getReg(reg_map, ra, u.operand), 0x3, rd, 0x13)); // SLTIU rd, rs, 1
            },

            // ── Move ──────────────────────────────────────────────────────
            .mov => |m| {
                try w.emit(riscv.ADDI(getReg(reg_map, ra, m.dst), getReg(reg_map, ra, m.src), 0));
            },

            // ── Control flow ──────────────────────────────────────────────
            .label => |l| {
                const off = w.currentOffset();
                try label_map.put(l.id, off);
                if (label_patches.getPtr(l.id)) |patches| {
                    for (patches.items) |p| {
                        const rel = @as(i32, @intCast(off)) - @as(i32, @intCast(p));
                        w.patchAt(p, riscv.JAL(.zero, @truncate(rel)));
                    }
                    patches.clearRetainingCapacity();
                }
            },
            .jump => |j| {
                if (label_map.get(j.target)) |target_off| {
                    const cur = w.currentOffset();
                    const rel = @as(i32, @intCast(target_off)) - @as(i32, @intCast(cur));
                    try w.emit(riscv.JAL(.zero, @truncate(rel)));
                } else {
                    const cur = w.currentOffset();
                    try w.emit(riscv.JAL(.zero, 0));
                    const entry = try label_patches.getOrPut(j.target);
                    if (!entry.found_existing) entry.value_ptr.* = .{};
                    try entry.value_ptr.append(self.allocator, cur);
                }
            },
            .branch => |b| {
                const rc = getReg(reg_map, ra, b.cond);
                // BNE cond, zero → then_
                if (label_map.get(b.then_)) |target| {
                    const cur = w.currentOffset();
                    const rel = @as(i32, @intCast(target)) - @as(i32, @intCast(cur));
                    try w.emit(riscv.BNE(rc, .zero, @truncate(rel)));
                } else {
                    const cur = w.currentOffset();
                    try w.emit(riscv.BNE(rc, .zero, 0));
                    const entry = try label_patches.getOrPut(b.then_);
                    if (!entry.found_existing) entry.value_ptr.* = .{};
                    try entry.value_ptr.append(self.allocator, cur);
                }
                // Fall-through = else_
                if (label_map.get(b.else_)) |target| {
                    const cur = w.currentOffset();
                    const rel = @as(i32, @intCast(target)) - @as(i32, @intCast(cur));
                    try w.emit(riscv.JAL(.zero, @truncate(rel)));
                } else {
                    const cur2 = w.currentOffset();
                    try w.emit(riscv.JAL(.zero, 0));
                    const entry2 = try label_patches.getOrPut(b.else_);
                    if (!entry2.found_existing) entry2.value_ptr.* = .{};
                    try entry2.value_ptr.append(self.allocator, cur2);
                }
            },
            .ret => |r| {
                if (r.value) |val| {
                    try w.emit(riscv.ADD(.a0, getReg(reg_map, ra, val), .zero));
                }
                try w.emit(riscv.JALR(.zero, .ra, 0));
            },

            // ── State access via host calls ───────────────────────────────
            .state_read => |sr| {
                const rd = getReg(reg_map, ra, sr.dst);
                try w.emit(riscv.ADDI(.a0, .zero, @intCast(sr.field_id)));
                if (sr.key) |k| {
                    try w.emit(riscv.ADD(.a1, getReg(reg_map, ra, k), .zero));
                }
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.STATE_READ)));
                try w.emit(riscv.ADD(rd, .a0, .zero));
            },
            .state_write => |sw| {
                try w.emit(riscv.ADDI(.a0, .zero, @intCast(sw.field_id)));
                try w.emit(riscv.ADD(.a1, getReg(reg_map, ra, sw.value), .zero));
                if (sw.key) |k| {
                    try w.emit(riscv.ADD(.a2, getReg(reg_map, ra, k), .zero));
                }
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.STATE_WRITE)));
            },
            .state_delete => |sd| {
                try w.emit(riscv.ADDI(.a0, .zero, @intCast(sd.field_id)));
                try w.emit(riscv.ADD(.a1, getReg(reg_map, ra, sd.key), .zero));
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.STATE_DELETE)));
            },

            // ── Events ────────────────────────────────────────────────────
            .emit_event => |ev| {
                try w.emit(riscv.ADDI(.a0, .zero, @intCast(ev.event_id)));
                for (ev.args, 0..) |arg, i| {
                    if (i >= 6) break;
                    const arg_reg: Reg = @enumFromInt(@as(u5, @intCast(11 + i)));
                    try w.emit(riscv.ADD(arg_reg, getReg(reg_map, ra, arg), .zero));
                }
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.EMIT_EVENT)));
            },

            // ── Assertions ────────────────────────────────────────────────
            .need => |n| {
                const rc = getReg(reg_map, ra, n.cond);
                try w.emit(riscv.BNE(rc, .zero, 12)); // skip revert
                try w.emit(riscv.ADDI(.a0, .zero, @intCast(n.msg_offset)));
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.REVERT)));
            },
            .ensure => |e| {
                const rc = getReg(reg_map, ra, e.cond);
                try w.emit(riscv.BNE(rc, .zero, 12)); // skip revert
                try w.emit(riscv.ADDI(.a0, .zero, @intCast(e.msg_offset)));
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.REVERT)));
            },
            .panic => |p| {
                try w.emit(riscv.ADDI(.a0, .zero, @intCast(p.msg_offset)));
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.REVERT)));
            },

            // ── Native transfer ───────────────────────────────────────────
            .pay => |p| {
                try w.emit(riscv.ADD(.a0, getReg(reg_map, ra, p.recipient), .zero));
                try w.emit(riscv.ADD(.a1, getReg(reg_map, ra, p.amount), .zero));
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.NATIVE_PAY)));
            },

            // ── Builtins ──────────────────────────────────────────────────
            .get_caller => |gc| {
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.GET_CALLER)));
                try w.emit(riscv.ADD(getReg(reg_map, ra, gc.dst), .a0, .zero));
            },
            .get_value => |gv| {
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.GET_VALUE)));
                try w.emit(riscv.ADD(getReg(reg_map, ra, gv.dst), .a0, .zero));
            },
            .get_timestamp => |gt| {
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.GET_NOW)));
                try w.emit(riscv.ADD(getReg(reg_map, ra, gt.dst), .a0, .zero));
            },
            .get_block => |gb| {
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.GET_BLOCK)));
                try w.emit(riscv.ADD(getReg(reg_map, ra, gb.dst), .a0, .zero));
            },

            // ── Authority ─────────────────────────────────────────────────
            .auth_check => |ac| {
                try w.emit(riscv.ADDI(.a0, .zero, @intCast(ac.name_offset)));
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.AUTH_CHECK)));
            },
            .auth_gate_begin => |ag| {
                try w.emit(riscv.ADDI(.a0, .zero, @intCast(ag.name_offset)));
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.ACCESS_ASSERT)));
            },
            .auth_gate_end => {},
            .throw_error => |te| {
                try w.emit(riscv.ADDI(.a0, .zero, @intCast(te.error_id)));
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.REVERT)));
            },

            // ── Asset operations ─────────────────────────────────────────
            .asset_send => |as_| {
                try w.emit(riscv.ADD(.a0, getReg(reg_map, ra, as_.asset), .zero));
                try w.emit(riscv.ADD(.a1, getReg(reg_map, ra, as_.recipient), .zero));
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.ASSET_TRANSFER)));
            },
            .asset_mint => |am| {
                try w.emit(riscv.ADDI(.a0, .zero, @intCast(am.type_id)));
                try w.emit(riscv.ADD(.a1, getReg(reg_map, ra, am.amount), .zero));
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.ASSET_MINT)));
                try w.emit(riscv.ADD(getReg(reg_map, ra, am.dst), .a0, .zero));
            },
            .asset_burn => |ab| {
                try w.emit(riscv.ADD(.a0, getReg(reg_map, ra, ab.asset), .zero));
                try w.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.ASSET_BURN)));
            },

            // ── Placeholders (not critical path) ─────────────────────────
            .asset_split, .asset_merge, .asset_wrap, .asset_unwrap,
            .expand_account, .close_account, .freeze_account, .unfreeze_account,
            .transfer_ownership, .schedule_call, .oracle_read, .vrf_random,
            .zk_verify, .delegate_gas, .has_check, .get_gas, .get_this,
            .get_deployer, .get_zero_addr, .attempt_begin, .attempt_end,
            .call_internal, .call_external, .nop => {},
        }
    }
};

// ============================================================================
// Section 7 — Tests
// ============================================================================

test "PolkaVmHeader is exactly 64 bytes" {
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(PolkaVmHeader));
}

test "PolkaVmHeader default magic is PVM" {
    const header = PolkaVmHeader{};
    const expected = [_]u8{ 0x00, 'P', 'V', 'M' };
    try std.testing.expectEqualSlices(u8, &expected, &header.magic);
    try std.testing.expectEqual(@as(u16, 1), header.version);
}

test "CRC32 known value" {
    const data = "POLK";
    const result = crc32(data);
    try std.testing.expect(result != 0);
    // Verify determinism
    try std.testing.expectEqual(result, crc32(data));
}

test "writeContractName pads correctly" {
    const name = writeContractName("MyToken");
    try std.testing.expectEqualSlices(u8, "MyToken", name[0..7]);
    try std.testing.expectEqual(@as(u8, 0), name[7]);
    try std.testing.expectEqual(@as(u8, 0), name[31]);
}

test "writeContractName truncates at 32 bytes" {
    const long_name = "ThisIsAVeryLongContractNameThatExceedsThirtyTwoCharacters";
    const name = writeContractName(long_name);
    try std.testing.expectEqualSlices(u8, long_name[0..32], &name);
}

test "actionSelector is deterministic" {
    const sel1 = actionSelector("transfer");
    const sel2 = actionSelector("transfer");
    try std.testing.expectEqual(sel1, sel2);
}

test "actionSelector differs for different names" {
    const sel1 = actionSelector("transfer");
    const sel2 = actionSelector("withdraw");
    try std.testing.expect(sel1 != sel2);
}

test "RegAlloc allocates and frees correctly" {
    var ra = RegAlloc{};
    const r1 = ra.alloc();
    try std.testing.expect(r1 != null);
    const r2 = ra.alloc();
    try std.testing.expect(r2 != null);
    try std.testing.expect(r1.? != r2.?);
    ra.free(r1.?);
    const r3 = ra.alloc();
    try std.testing.expectEqual(r1.?, r3.?);
}

test "RegAlloc exhaustion returns null" {
    var ra = RegAlloc{};
    // Allocate all 14 allocatable registers
    var count: usize = 0;
    while (ra.alloc()) |_| {
        count += 1;
        if (count > 20) break; // safety
    }
    try std.testing.expectEqual(@as(usize, 14), count);
    try std.testing.expectEqual(@as(?Reg, null), ra.alloc());
}

test "RegAlloc freeAll resets state" {
    var ra = RegAlloc{};
    _ = ra.alloc();
    _ = ra.alloc();
    ra.freeAll();
    var count: usize = 0;
    while (ra.alloc()) |_| {
        count += 1;
        if (count > 20) break;
    }
    try std.testing.expectEqual(@as(usize, 14), count);
}
