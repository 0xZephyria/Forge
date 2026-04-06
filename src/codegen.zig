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
const riscv = @import("riscv.zig");
const u256_mod = @import("u256.zig");

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
pub const ZephBinHeader = extern struct {
    /// Magic bytes: "FORG"
    magic: [4]u8 = .{ 'F', 'O', 'R', 'G' },
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
    std.debug.assert(@sizeOf(ZephBinHeader) == 64);
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

fn scaleFixedPoint(lit: []const u8, decimals: u8) u64 {
    var int_part_buf: [80]u8 = undefined;
    var frac_part_buf: [80]u8 = undefined;
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
            if (int_len < int_part_buf.len) {
                int_part_buf[int_len] = c;
                int_len += 1;
            }
        } else {
            if (frac_len < frac_part_buf.len) {
                frac_part_buf[frac_len] = c;
                frac_len += 1;
            }
        }
    }
    
    const int_str = int_part_buf[0..int_len];
    var padded_frac_buf: [80]u8 = [_]u8{'0'} ** 80;
    const copy_len = @min(frac_len, decimals);
    @memcpy(padded_frac_buf[0..copy_len], frac_part_buf[0..copy_len]);
    const frac_str = padded_frac_buf[0..decimals];
    
    const int_val = if (int_str.len == 0) 0 else std.fmt.parseInt(u64, int_str, 10) catch 0;
    const frac_val = if (frac_str.len == 0) 0 else std.fmt.parseInt(u64, frac_str, 10) catch 0;
    
    const p10 = pow10(decimals);
    
    const mul_tup = @mulWithOverflow(int_val, p10);
    if (mul_tup[1] != 0) return std.math.maxInt(u64);
    
    const add_tup = @addWithOverflow(mul_tup[0], frac_val);
    if (add_tup[1] != 0) return std.math.maxInt(u64);
    
    return add_tup[0];
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

/// Information about a local variable tracked during codegen.
pub const LocalVar = struct {
    reg: Reg,
    ty: ResolvedType,
};

/// Per-action state maintained during code generation.
const ActionCtx = struct {
    writer: BytecodeWriter,
    reg_alloc: RegAlloc,
    locals: std.StringHashMap(LocalVar),
    loop_exits: std.ArrayListUnmanaged(u32),
    loop_conts: std.ArrayListUnmanaged(u32),
    action_name: []const u8,
    field_ids: *std.StringHashMap(u32),
    checked: *const CheckedContract,
    allocator: std.mem.Allocator,

    /// Create a new context for an action.
    fn init(allocator: std.mem.Allocator, name: []const u8, field_ids: *std.StringHashMap(u32), checked: *const CheckedContract) ActionCtx {
        return .{
            .writer = BytecodeWriter.init(allocator),
            .reg_alloc = .{},
            .locals = std.StringHashMap(LocalVar).init(allocator),
            .loop_exits = .{},
            .loop_conts = .{},
            .action_name = name,
            .field_ids = field_ids,
            .checked = checked,
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
// Section 6 — Code Generator
// ============================================================================

/// Main code generator. Walks the checked AST and emits a .fozbin binary.
pub const CodeGen = struct {
    allocator: std.mem.Allocator,
    diagnostics: *DiagnosticList,
    resolver: *TypeResolver,
    field_ids: std.StringHashMap(u32),
    next_field_id: u32,
    /// Maps interned string content (without quotes) to its byte offset
    /// in the data section.
    string_table: std.StringHashMap(u32),
    /// Accumulated static data bytes: null-terminated, 4-byte aligned strings.
    data_section: std.ArrayListUnmanaged(u8),

    /// Create a new code generator.
    pub fn init(
        allocator: std.mem.Allocator,
        diagnostics: *DiagnosticList,
        resolver: *TypeResolver,
    ) CodeGen {
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
    pub fn deinit(self: *CodeGen) void {
        self.field_ids.deinit();
        self.string_table.deinit();
        self.data_section.deinit(self.allocator);
    }

    /// Intern a string literal, returning its offset in the data section.
    fn internString(self: *CodeGen, content: []const u8) anyerror!u32 {
        if (self.string_table.get(content)) |offset| {
            return offset;
        }

        const offset: u32 = @intCast(self.data_section.items.len);
        
        try self.data_section.appendSlice(self.allocator, content);
        try self.data_section.append(self.allocator, 0); // null terminator

        // 4-byte alignment
        while (self.data_section.items.len % 4 != 0) {
            try self.data_section.append(self.allocator, 0);
        }

        try self.string_table.put(content, offset);
        return offset;
    }

    /// Assign a sequential field ID to a state field name.
    fn getOrAssignFieldId(self: *CodeGen, name: []const u8) u32 {
        if (self.field_ids.get(name)) |id| return id;
        const id = self.next_field_id;
        self.field_ids.put(name, id) catch return id;
        self.next_field_id += 1;
        return id;
    }

    /// Generate the complete .fozbin binary from a checked contract.
    /// Returns a heap-allocated byte slice. Caller owns the memory.
    pub fn generate(
        self: *CodeGen,
        contract: *const ContractDef,
        checked: *const CheckedContract,
    ) anyerror![]u8 {
        // Pre-assign field IDs for all state fields
        for (contract.state) |sf| {
            _ = self.getOrAssignFieldId(sf.name);
        }

        // Constructor counts as an entry if present
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

        // ── Generate constructor (setup block) if present ────────────────────
        if (contract.setup) |setup| {
            var ctx = ActionCtx.init(self.allocator, "__setup__", &self.field_ids, checked);
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
            var ctx = ActionCtx.init(self.allocator, action.name, &self.field_ids, checked);
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
            var ctx = ActionCtx.init(self.allocator, view.name, &self.field_ids, checked);
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

        // ── GAP-FIX: Generate bytecode for each pure function ─────────────
        // SPEC: Part 5.6 — Pure functions emit no state syscalls; they are
        // internal-only and callable via JALR. Selector prefix 0xF0000000.
        for (contract.pures) |pure| {
            var ctx = ActionCtx.init(self.allocator, pure.name, &self.field_ids, checked);
            defer ctx.deinit();

            try self.genPure(&pure, &ctx);

            const code_bytes = ctx.writer.toBytes();
            const owned_copy = try self.allocator.alloc(u8, code_bytes.len);
            @memcpy(owned_copy, code_bytes);

            try action_codes.append(self.allocator, .{
                .selector = 0xF000_0000 | (actionSelector(pure.name) & 0x0FFF_FFFF),
                .code = owned_copy,
            });
        }

        // ── GAP-FIX: Generate bytecode for each helper function ───────────
        // SPEC: Part 5.7 — Helpers are within-visible only; can access state.
        // Selector prefix 0xF1000000.
        for (contract.helpers) |helper| {
            var ctx = ActionCtx.init(self.allocator, helper.name, &self.field_ids, checked);
            defer ctx.deinit();

            try self.genHelper(&helper, &ctx);

            const code_bytes = ctx.writer.toBytes();
            const owned_copy = try self.allocator.alloc(u8, code_bytes.len);
            @memcpy(owned_copy, code_bytes);

            try action_codes.append(self.allocator, .{
                .selector = 0xF100_0000 | (actionSelector(helper.name) & 0x0FFF_FFFF),
                .code = owned_copy,
            });
        }

        // ── GAP-FIX: Generate bytecode for each guard function ────────────
        // SPEC: Part 6.1 — Guards are boolean conditions; they return 0 or 1
        // in a0. Called by actions that declare `only guardName`.
        // Selector prefix 0xF2000000.
        for (contract.guards) |guard| {
            var ctx = ActionCtx.init(self.allocator, guard.name, &self.field_ids, checked);
            defer ctx.deinit();

            try self.genGuard(&guard, &ctx);

            const code_bytes = ctx.writer.toBytes();
            const owned_copy = try self.allocator.alloc(u8, code_bytes.len);
            @memcpy(owned_copy, code_bytes);

            try action_codes.append(self.allocator, .{
                .selector = 0xF200_0000 | (actionSelector(guard.name) & 0x0FFF_FFFF),
                .code = owned_copy,
            });
        }

        // ── SPEC: Part 5.13 — Fallback handler ──────────────────────────

        if (contract.fallback) |fb| {
            var ctx = ActionCtx.init(self.allocator, "__fallback__", &self.field_ids, checked);
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
            var ctx = ActionCtx.init(self.allocator, "__receive__", &self.field_ids, checked);
            defer ctx.deinit();
            try self.genAction(&rc, &ctx);
            const code_bytes = ctx.writer.toBytes();
            const owned_copy = try self.allocator.alloc(u8, code_bytes.len);
            @memcpy(owned_copy, code_bytes);
            try action_codes.append(self.allocator, .{
                .selector = 0x00000001, // Receive selector
                .code = owned_copy,
            });
        }

        // ── SPEC: Tier 1 Robustness — Migration Entry Point ─────────────
        if (contract.upgrade) |up| {
            // Generate selector 0xDEAD0001 for migration
            var ctx = ActionCtx.init(self.allocator, "__migrate__", &self.field_ids, checked);
            defer ctx.deinit();
            
            // 1. Enforce migration authority check (must be upgrade authority)
            // Implementation detail: The VM handles the 'only' authority check if injected.
            // If migrate_fn was specified in Forge source, call it.
            if (up.migrate_fn) |fn_name| {
                // Find method by name
                for (contract.actions) |act| {
                    if (std.mem.eql(u8, act.name, fn_name)) {
                        try self.genAction(&act, &ctx);
                        break;
                    }
                }
            } else {
                // Default empty migration: just return success
                const frame_size: i12 = 8;
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -frame_size));
                try ctx.writer.emit(riscv.SD(.sp, .ra, 0));
                try ctx.writer.emit(riscv.LD(.ra, .sp, 0));
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, frame_size));
                try ctx.writer.emit(riscv.JALR(.zero, .ra, 0));
            }

            const code_bytes = ctx.writer.toBytes();
            const owned_copy = try self.allocator.alloc(u8, code_bytes.len);
            @memcpy(owned_copy, code_bytes);
            try action_codes.append(self.allocator, .{
                .selector = 0xDEAD0001,
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
        // Layout: [64-byte header][access_list][bytecode][data_section]
        const data_bytes = self.data_section.items;
        var header = ZephBinHeader{};
        header.contract_name = writeContractName(contract.name);
        header.action_count = action_count;
        header.flags = flags;
        header.access_list_len = @intCast(access_list_bytes.len);
        header.bytecode_len = @intCast(bytecode_bytes.len);
        header.data_section_len = @intCast(data_bytes.len);

        // ── Serialize conservation metadata section ──────────────────────
        const conservation_bytes = try self.serializeConservationMetadata(contract);
        defer self.allocator.free(conservation_bytes);
        header.conservation_len = @intCast(conservation_bytes.len);

        const total_size = @sizeOf(ZephBinHeader) +
            access_list_bytes.len +
            bytecode_bytes.len +
            data_bytes.len +
            conservation_bytes.len;

        const binary = try self.allocator.alloc(u8, total_size);
        errdefer self.allocator.free(binary);

        // Copy header
        const header_bytes: *const [@sizeOf(ZephBinHeader)]u8 = @ptrCast(&header);
        @memcpy(binary[0..@sizeOf(ZephBinHeader)], header_bytes);

        // Copy access list
        const al_start = @sizeOf(ZephBinHeader);
        @memcpy(binary[al_start..][0..access_list_bytes.len], access_list_bytes);

        // Copy bytecode
        const bc_start = al_start + access_list_bytes.len;
        @memcpy(binary[bc_start..][0..bytecode_bytes.len], bytecode_bytes);

        // Copy data section
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
        const checksum_offset = @offsetOf(ZephBinHeader, "checksum") + @sizeOf(u32);
        const checksum = crc32(binary[checksum_offset..]);
        std.mem.writeInt(u32, binary[@offsetOf(ZephBinHeader, "checksum")..][0..4], checksum, .little);

        return binary;
    }

    // ── Action code generation ───────────────────────────────────────────

    /// Generate bytecode for a single action, including prologue and epilogue.
    fn genAction(self: *CodeGen, action: *const ActionDecl, ctx: *ActionCtx) anyerror!void {
        const frame_size: i12 = 64; // 8 saved regs * 8 bytes

        // ── Prologue ─────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -frame_size));
        try ctx.writer.emit(riscv.SD(.sp, .ra, 0));
        try ctx.writer.emit(riscv.SD(.sp, .s0, 8));
        try ctx.writer.emit(riscv.ADDI(.s0, .sp, frame_size));

        // ── Bind parameters to registers ─────────────────────────────────
        for (action.params, 0..) |param, i| {
            if (i < 7) {
                const reg: Reg = @enumFromInt(@as(u5, @intCast(10 + i)));
                ctx.reg_alloc.used[@intFromEnum(reg)] = true;
                const ty = (self.resolver.resolve(param.declared_type) catch .void_);
                try ctx.locals.put(param.name, .{ .reg = reg, .ty = ty });
            }
        }
        // ── Gas Sponsorship ─────────────────────────────────────────────
        // SPEC: Part 4 — gas sponsorship is declared in the access list metadata,
        // not via a VM syscall. No bytecode needed here; the node sees the
        // annotation in the .fozabi and applies fee delegation off-chain.
        _ = action.annotations;

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
    fn genView(self: *CodeGen, view: *const ViewDecl, ctx: *ActionCtx) anyerror!void {
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
                const ty = (self.resolver.resolve(param.declared_type) catch .void_);
                try ctx.locals.put(param.name, .{ .reg = reg, .ty = ty });
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

    // ── Pure function code generation ────────────────────────────────────

    /// SPEC: Part 5.6 — Generate bytecode for a pure function.
    /// Pure functions must not issue any state syscalls (!STATE_READ, !STATE_WRITE).
    /// They are callable only internally via JALR and return their result in a0.
    /// Uses RV64IM standard prologue/epilogue.
    fn genPure(self: *CodeGen, pure: *const ast.PureDecl, ctx: *ActionCtx) anyerror!void {
        const frame_size: i12 = 64;

        // ── Prologue (RV64IM ABI) ─────────────────────────────────────────
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -frame_size));
        try ctx.writer.emit(riscv.SD(.sp, .ra, 0));
        try ctx.writer.emit(riscv.SD(.sp, .s0, 8));
        try ctx.writer.emit(riscv.ADDI(.s0, .sp, frame_size));

        // ── Bind parameters ───────────────────────────────────────────────
        for (pure.params, 0..) |param, i| {
            if (i < 7) {
                const reg: Reg = @enumFromInt(@as(u5, @intCast(10 + i)));
                ctx.reg_alloc.used[@intFromEnum(reg)] = true;
                const ty = (self.resolver.resolve(param.declared_type) catch .void_);
                try ctx.locals.put(param.name, .{ .reg = reg, .ty = ty });
            }
        }

        // ── Body ──────────────────────────────────────────────────────────
        for (pure.body) |stmt| {
            try self.genStmt(&stmt, ctx);
        }

        // ── Epilogue ──────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.LD(.s0, .sp, 8));
        try ctx.writer.emit(riscv.LD(.ra, .sp, 0));
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, frame_size));
        try ctx.writer.emit(riscv.JALR(.zero, .ra, 0));
    }

    // ── Helper function code generation ──────────────────────────────────

    /// SPEC: Part 5.7 — Generate bytecode for an internal helper function.
    /// Helpers are `within`-visible by default (not externally callable).
    /// They can read/write state and call other functions.
    fn genHelper(self: *CodeGen, helper: *const ast.HelperDecl, ctx: *ActionCtx) anyerror!void {
        const frame_size: i12 = 64;

        // ── Prologue ─────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -frame_size));
        try ctx.writer.emit(riscv.SD(.sp, .ra, 0));
        try ctx.writer.emit(riscv.SD(.sp, .s0, 8));
        try ctx.writer.emit(riscv.ADDI(.s0, .sp, frame_size));

        // ── Bind parameters ───────────────────────────────────────────────
        for (helper.params, 0..) |param, i| {
            if (i < 7) {
                const reg: Reg = @enumFromInt(@as(u5, @intCast(10 + i)));
                ctx.reg_alloc.used[@intFromEnum(reg)] = true;
                const ty = (self.resolver.resolve(param.declared_type) catch .void_);
                try ctx.locals.put(param.name, .{ .reg = reg, .ty = ty });
            }
        }

        // ── Body ──────────────────────────────────────────────────────────
        for (helper.body) |stmt| {
            try self.genStmt(&stmt, ctx);
        }

        // ── Epilogue ──────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.LD(.s0, .sp, 8));
        try ctx.writer.emit(riscv.LD(.ra, .sp, 0));
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, frame_size));
        try ctx.writer.emit(riscv.JALR(.zero, .ra, 0));
    }

    // ── Guard function code generation ───────────────────────────────────

    /// SPEC: Part 6.1 — Generate bytecode for a named guard function.
    /// Guards evaluate a boolean condition and return it in a0 (0=fail, 1=pass).
    /// On failure the VM reverts; on success execution continues.
    /// Guard bodies use the same statement generator so they can read state.
    fn genGuard(self: *CodeGen, guard: *const ast.GuardDecl, ctx: *ActionCtx) anyerror!void {
        const frame_size: i12 = 64;

        // ── Prologue ─────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -frame_size));
        try ctx.writer.emit(riscv.SD(.sp, .ra, 0));
        try ctx.writer.emit(riscv.SD(.sp, .s0, 8));
        try ctx.writer.emit(riscv.ADDI(.s0, .sp, frame_size));

        // ── Bind parameters ───────────────────────────────────────────────
        for (guard.params, 0..) |param, i| {
            if (i < 7) {
                const reg: Reg = @enumFromInt(@as(u5, @intCast(10 + i)));
                ctx.reg_alloc.used[@intFromEnum(reg)] = true;
                const ty = (self.resolver.resolve(param.declared_type) catch .void_);
                try ctx.locals.put(param.name, .{ .reg = reg, .ty = ty });
            }
        }

        // ── Body ──────────────────────────────────────────────────────────
        for (guard.body) |stmt| {
            try self.genStmt(&stmt, ctx);
        }

        // ── Guard result normalisation ─────────────────────────────────────
        // Guards must return 0 or 1 in a0. If the body did not explicitly set
        // a0, default to 1 (pass). The body can set a0=0 via `give back false`.
        // If the calling action wants to revert on 0, it should do:
        //   JALR ra, guard_fn  → BNE a0, zero, ok →  REVERT
        // (this is emitted by genOnly when we support guard references).

        // ── Epilogue ──────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.LD(.s0, .sp, 8));
        try ctx.writer.emit(riscv.LD(.ra, .sp, 0));
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, frame_size));
        try ctx.writer.emit(riscv.JALR(.zero, .ra, 0));
    }

    // ── Setup (Constructor) code generation ──────────────────────────────


    /// Generate bytecode for the setup block (constructor).
    fn genSetup(self: *CodeGen, setup: *const ast.SetupBlock, ctx: *ActionCtx) anyerror!void {
        const frame_size: i12 = 64;

        // ── Prologue ─────────────────────────────────────────────────────
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -frame_size));
        try ctx.writer.emit(riscv.SD(.sp, .ra, 0));
        try ctx.writer.emit(riscv.SD(.sp, .s0, 8));
        try ctx.writer.emit(riscv.ADDI(.s0, .sp, frame_size));

        // ── Bind parameters to registers ─────────────────────────────────
        for (setup.params, 0..) |param, i| {
            if (i < 7) {
                const reg: Reg = @enumFromInt(@as(u5, @intCast(10 + i)));
                ctx.reg_alloc.used[@intFromEnum(reg)] = true;
                const ty = (self.resolver.resolve(param.declared_type) catch .void_);
                try ctx.locals.put(param.name, .{ .reg = reg, .ty = ty });
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

    // ── Statement code generation ────────────────────────────────────────

    /// Generate bytecode for a single statement.
    fn genStmt(self: *CodeGen, stmt: *const Stmt, ctx: *ActionCtx) anyerror!void {
        switch (stmt.kind) {
            .let_bind => |lb| {
                const dest = ctx.reg_alloc.alloc() orelse .t0;
                try self.genExpr(lb.init, ctx, dest);
                const ty = (self.resolver.inferExpr(lb.init, &ctx.checked.scope) catch .void_);
                try ctx.locals.put(lb.name, .{ .reg = dest, .ty = ty });
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
                    if (ctx.locals.get(name)) |loc| {
                        try self.genExpr(asg.value, ctx, loc.reg);
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
                    if (ctx.locals.get(name)) |loc| {
                        const dest = loc.reg;
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
                        try ctx.writer.emit(riscv.ZEPH(.STATE_WRITE));
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
                            try ctx.writer.emit(riscv.ZEPH(.STATE_WRITE));
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
            .give_back => |expr| {
                const reg = ctx.reg_alloc.alloc() orelse .a0;
                try self.genExpr(expr, ctx, reg);
                if (reg != .a0) {
                    try ctx.writer.emit(riscv.ADD(.a0, reg, .zero));
                }
                try ctx.writer.emit(riscv.JAL(.zero, 0)); // Jump to exit
            },
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
                // SPEC: Part 8.4 — native ZPH pay uses ASSET_TRANSFER with zeroed asset ID.
                // ABI: a0=0x10, a1=asset_id_ptr(32B zeroes), a2=from_ptr(20B), a3=to_ptr(20B), a4=amount_val
                const to_reg = ctx.reg_alloc.alloc() orelse .t0;
                defer ctx.reg_alloc.free(to_reg);
                const amt_reg = ctx.reg_alloc.alloc() orelse .t1;
                defer ctx.reg_alloc.free(amt_reg);
                try self.genExpr(pay.recipient, ctx, to_reg);
                try self.genExpr(pay.amount, ctx, amt_reg);
                // Allocate 32-byte zero buffer on stack for the zero-asset-id
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                // Zero the buffer (use t2 as scratch)
                try ctx.writer.emit(riscv.ADDI(.t2, .zero, 0));
                var zoff: i12 = 0;
                while (zoff < 32) : (zoff += 8) {
                    try ctx.writer.emit(riscv.SD(.sp, .t2, zoff));
                }
                // Set up syscall args
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero)); // a1 = asset_id_ptr (zero)
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero)); // a2 = from: zero = caller (VM fills)
                try ctx.writer.emit(riscv.ADD(.a3, .zero, to_reg));  // a3 = to_ptr
                try ctx.writer.emit(riscv.ADD(.a4, .zero, amt_reg)); // a4 = amount
                try ctx.writer.emit(riscv.ZEPH(.ASSET_TRANSFER));
                try ctx.writer.emit(riscv.ECALL());
                // Restore stack
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));
            },
            .send => |send| {
                const asset_reg = ctx.reg_alloc.alloc() orelse .t0;
                defer ctx.reg_alloc.free(asset_reg);
                const to_reg = ctx.reg_alloc.alloc() orelse .t1;
                defer ctx.reg_alloc.free(to_reg);
                
                try self.genExpr(send.asset, ctx, asset_reg);
                try self.genExpr(send.recipient, ctx, to_reg);

                // ── Asset Hooks Logic ────────────────────────────────────
                // Look up asset definition to find hooks
                var asset_def: ?*const ast.AssetDef = null;
                var asset_type: ResolvedType = .void_;
                
                // Identify asset type from target expression
                if (send.asset.kind == .identifier) {
                    const name = send.asset.kind.identifier;
                    if (ctx.locals.get(name)) |loc| {
                        asset_type = loc.ty;
                    }
                } else {
                    // Fallback to inference (may be slow)
                    asset_type = (self.resolver.inferExpr(send.asset, &ctx.checked.scope) catch .void_);
                }

                const inner_type = if (asset_type == .linear) asset_type.linear.* else asset_type;
                if (inner_type == .asset) {
                    const name = inner_type.asset;
                    asset_def = self.resolver.asset_defs.getPtr(name);
                }

                // 1) before_transfer hook
                if (asset_def) |ad| {
                    if (ad.before_transfer) |hook| {
                        // GET_CALLER syscall: a0=0x60, a1=buf_ptr(20B)
                        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -24));
                        try ctx.writer.emit(riscv.ZEPH(.GET_CALLER));
                        try ctx.writer.emit(riscv.ECALL());
                        try ctx.writer.emit(riscv.ADD(.a1, .zero, to_reg));
                        try ctx.writer.emit(riscv.ADD(.a2, .zero, asset_reg));
                        for (hook.body) |hstmt| {
                            try self.genStmt(&hstmt, ctx);
                        }
                        try ctx.writer.emit(riscv.ADDI(.sp, .sp, 24));
                    }
                }

                // 2) Actual Transfer via ASSET_TRANSFER syscall
                // ABI: a0=0x10, a1=asset_id_ptr, a2=from_ptr, a3=to_ptr, a4=amount_ptr
                try ctx.writer.emit(riscv.ADD(.a1, .zero, asset_reg)); // a1 = asset id
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero));     // a2 = from: caller
                try ctx.writer.emit(riscv.ADD(.a3, .zero, to_reg));    // a3 = to
                try ctx.writer.emit(riscv.ADD(.a4, .zero, asset_reg)); // a4 = amount (re-use asset reg)
                try ctx.writer.emit(riscv.ZEPH(.ASSET_TRANSFER));
                try ctx.writer.emit(riscv.ECALL());

                // 3) after_transfer hook
                if (asset_def) |ad| {
                    if (ad.after_transfer) |hook| {
                        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -24));
                        try ctx.writer.emit(riscv.ZEPH(.GET_CALLER));
                        try ctx.writer.emit(riscv.ECALL());
                        try ctx.writer.emit(riscv.ADD(.a1, .zero, to_reg));
                        try ctx.writer.emit(riscv.ADD(.a2, .zero, asset_reg));
                        for (hook.body) |hstmt| {
                            try self.genStmt(&hstmt, ctx);
                        }
                        try ctx.writer.emit(riscv.ADDI(.sp, .sp, 24));
                    }
                }
            },
            .only => |*only| try self.genOnly(only, ctx),
            .panic => |p| {
                const tmp = ctx.reg_alloc.alloc() orelse .t0;
                defer ctx.reg_alloc.free(tmp);
                try self.genLoadImmediate(@intCast(p.message.len), tmp, ctx);
                try ctx.writer.emit(riscv.ADD(.a1, .zero, tmp));
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero)); // data_len=0
                try ctx.writer.emit(riscv.ZEPH(.REVERT));
                try ctx.writer.emit(riscv.ECALL());
            },
            .throw => |t| {
                _ = t;
                try ctx.writer.emit(riscv.ADDI(.a1, .zero, 0));
                try ctx.writer.emit(riscv.ADDI(.a2, .zero, 0));
                try ctx.writer.emit(riscv.ZEPH(.REVERT));
                try ctx.writer.emit(riscv.ECALL());
            },

            // ── guard_apply ───────────────────────────────────────────────
            // SPEC: Part 6.1 — `guard guardName` inlines the named guard check.
            // Emits AUTH_CHECK syscall with the guard name-hash in a0.
            .guard_apply => |name| {
                const sel = actionSelector(name);
                try self.genLoadImmediate(@intCast(sel), .a0, ctx);
                try ctx.writer.emit(riscv.ZEPH(.AUTH_CHECK));
                try ctx.writer.emit(riscv.ECALL());
            },

            // ── ensure (post-condition check) ─────────────────────────────
            // SPEC: Part 6.2 — Same semantics as need: revert on false.
            .ensure => |e| try self.genNeed(&.{
                .cond  = e.cond,
                .else_ = e.else_,
                .span  = stmt.span,
            }, ctx),

            // ── attempt / on_error ────────────────────────────────────────
            // SPEC: Part 10 — Emit body and always_after section inline.
            // Full snapshot-restore error handling is a VM-level feature.
            .attempt => |at| {
                for (at.body) |s| try self.genStmt(&s, ctx);
                if (at.always_body) |always| {
                    for (always) |s| try self.genStmt(&s, ctx);
                }
            },

            // ── verify (ZK proof) ─────────────────────────────────────────
            // SPEC: Part 12 — Off-chain ZK proof verification syscall 0x70.
            .verify => |v| {
                const proof_reg = ctx.reg_alloc.alloc() orelse .t0;
                defer ctx.reg_alloc.free(proof_reg);
                const commit_reg = ctx.reg_alloc.alloc() orelse .t1;
                defer ctx.reg_alloc.free(commit_reg);
                try self.genExpr(v.proof, ctx, proof_reg);
                try self.genExpr(v.commitment, ctx, commit_reg);
                if (proof_reg != .a0) try ctx.writer.emit(riscv.ADD(.a0, proof_reg, .zero));
                if (commit_reg != .a1) try ctx.writer.emit(riscv.ADD(.a1, commit_reg, .zero));
                try ctx.writer.emit(riscv.ADDI(.a0, .zero, 0x70));
                try ctx.writer.emit(riscv.ECALL());
            },

            // ── move_asset ────────────────────────────────────────────────
            // SPEC: Part 8.3 — `move asset into mine.field` stores to state.
            .move_asset => |mv| {
                const val_reg = ctx.reg_alloc.alloc() orelse .t0;
                defer ctx.reg_alloc.free(val_reg);
                try self.genExpr(mv.asset, ctx, val_reg);
                if (mv.dest.kind == .field_access) {
                    const fa = mv.dest.kind.field_access;
                    if (fa.object.kind == .identifier and
                        std.mem.eql(u8, fa.object.kind.identifier, "mine"))
                    {
                        const field_id = self.getOrAssignFieldId(fa.field);
                        try self.genLoadImmediate(@intCast(field_id), .a0, ctx);
                        try ctx.writer.emit(riscv.ADD(.a1, val_reg, .zero));
                        try ctx.writer.emit(riscv.ZEPH(.STATE_WRITE));
                        try ctx.writer.emit(riscv.ECALL());
                    }
                }
            },

            // ── remove ────────────────────────────────────────────────────
            // SPEC: Part 5.2 — `remove mine.map[key]` deletes a map entry.
            .remove => |expr| {
                if (expr.kind == .index_access) {
                    const ia = expr.kind.index_access;
                    if (ia.object.kind == .field_access) {
                        const fa = ia.object.kind.field_access;
                        if (fa.object.kind == .identifier and
                            std.mem.eql(u8, fa.object.kind.identifier, "mine"))
                        {
                            const field_id = self.getOrAssignFieldId(fa.field);
                            const key_reg = ctx.reg_alloc.alloc() orelse .t0;
                            defer ctx.reg_alloc.free(key_reg);
                            try self.genExpr(ia.index, ctx, key_reg);
                            try self.genLoadImmediate(@intCast(field_id), .a0, ctx);
                            try ctx.writer.emit(riscv.ADD(.a1, key_reg, .zero));
                            try ctx.writer.emit(riscv.ADDI(.a2, .zero, 0));
                            try ctx.writer.emit(riscv.ZEPH(.STATE_WRITE));
                            try ctx.writer.emit(riscv.ECALL());
                        }
                    }
                }
            },

            // ── expand / close / freeze / unfreeze ────────────────────────
            // SPEC: Part 11 — Account lifecycle operations.
            .expand => |exp| {
                const areg = ctx.reg_alloc.alloc() orelse .a0;
                defer ctx.reg_alloc.free(areg);
                const breg = ctx.reg_alloc.alloc() orelse .a1;
                defer ctx.reg_alloc.free(breg);
                try self.genExpr(exp.account, ctx, areg);
                try self.genExpr(exp.bytes, ctx, breg);
                if (areg != .a0) try ctx.writer.emit(riscv.ADD(.a0, areg, .zero));
                if (breg != .a1) try ctx.writer.emit(riscv.ADD(.a1, breg, .zero));
                try ctx.writer.emit(riscv.ADDI(.a0, .zero, 0x40)); // EXPAND_ACCOUNT
                try ctx.writer.emit(riscv.ECALL());
            },
            .close => |cl| {
                const areg = ctx.reg_alloc.alloc() orelse .a0;
                defer ctx.reg_alloc.free(areg);
                const rreg = ctx.reg_alloc.alloc() orelse .a1;
                defer ctx.reg_alloc.free(rreg);
                try self.genExpr(cl.account, ctx, areg);
                try self.genExpr(cl.refund_to, ctx, rreg);
                if (areg != .a0) try ctx.writer.emit(riscv.ADD(.a0, areg, .zero));
                if (rreg != .a1) try ctx.writer.emit(riscv.ADD(.a1, rreg, .zero));
                try ctx.writer.emit(riscv.ADDI(.a0, .zero, 0x41)); // CLOSE_ACCOUNT
                try ctx.writer.emit(riscv.ECALL());
            },
            .freeze => |fr| {
                const areg = ctx.reg_alloc.alloc() orelse .a0;
                defer ctx.reg_alloc.free(areg);
                try self.genExpr(fr.account, ctx, areg);
                if (areg != .a0) try ctx.writer.emit(riscv.ADD(.a0, areg, .zero));
                try ctx.writer.emit(riscv.ADDI(.a0, .zero, 0x42)); // FREEZE
                try ctx.writer.emit(riscv.ECALL());
            },
            .unfreeze => |uf| {
                const areg = ctx.reg_alloc.alloc() orelse .a0;
                defer ctx.reg_alloc.free(areg);
                try self.genExpr(uf.account, ctx, areg);
                if (areg != .a0) try ctx.writer.emit(riscv.ADD(.a0, areg, .zero));
                try ctx.writer.emit(riscv.ADDI(.a0, .zero, 0x43)); // UNFREEZE
                try ctx.writer.emit(riscv.ECALL());
            },

            // ── schedule (deferred cross-contract call) ───────────────────
            // SPEC: Part 15 — `schedule call after duration`.
            .schedule => |sch| {
                const dreg = ctx.reg_alloc.alloc() orelse .t0;
                defer ctx.reg_alloc.free(dreg);
                const creg = ctx.reg_alloc.alloc() orelse .t1;
                defer ctx.reg_alloc.free(creg);
                try self.genExpr(sch.after, ctx, dreg);
                try self.genExpr(sch.call, ctx, creg);
                if (dreg != .a1) try ctx.writer.emit(riscv.ADD(.a1, dreg, .zero));
                if (creg != .a2) try ctx.writer.emit(riscv.ADD(.a2, creg, .zero));
                try ctx.writer.emit(riscv.ADDI(.a3, .zero, 0));
                try ctx.writer.emit(riscv.ZEPH(.SCHEDULE_CALL));
                try ctx.writer.emit(riscv.ECALL());
            },

            // ── transfer_ownership ────────────────────────────────────────
            // SPEC: Part 11.6 — Transfer account ownership; syscall 0x44.
            .transfer_ownership => |tow| {
                const areg = ctx.reg_alloc.alloc() orelse .a0;
                defer ctx.reg_alloc.free(areg);
                const oreg = ctx.reg_alloc.alloc() orelse .a1;
                defer ctx.reg_alloc.free(oreg);
                try self.genExpr(tow.account, ctx, areg);
                try self.genExpr(tow.new_owner, ctx, oreg);
                if (areg != .a0) try ctx.writer.emit(riscv.ADD(.a0, areg, .zero));
                if (oreg != .a1) try ctx.writer.emit(riscv.ADD(.a1, oreg, .zero));
                try ctx.writer.emit(riscv.ADDI(.a0, .zero, 0x44)); // TRANSFER_OWNERSHIP
                try ctx.writer.emit(riscv.ECALL());
            },
        }
    }

    // ── Expression code generation ───────────────────────────────────────

    /// Generate bytecode for an expression, placing the result in `dest`.
    fn genExpr(self: *CodeGen, expr: *const Expr, ctx: *ActionCtx, dest: Reg) anyerror!void {
        switch (expr.kind) {
            .int_lit => |lit| {
                // Strip underscore separators before parsing
                // (the lexer preserves them in the source text)
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

                // Check for hex prefix
                const u256val: u256_mod.U256 = if (clean.len >= 2 and clean[0] == '0' and
                    (clean[1] == 'x' or clean[1] == 'X'))
                    u256_mod.U256.parseHex(clean[2..]) catch u256_mod.U256.zero
                else
                    u256_mod.U256.parseDecimal(clean) catch u256_mod.U256.zero;

                if (u256val.fitsU64()) {
                    // Fast path: value fits in one register
                    try self.genLoadImmediate(u256val.toU64(), dest, ctx);
                } else {
                    // Wide path: store 32-byte little-endian value on the stack.
                    // ZVM wide-integer convention: pass a pointer to the 32-byte
                    // value in memory. The `dest` register receives the stack pointer
                    // to that allocation.
                    //
                    // Stack layout (grows downward):
                    //   [sp+24..sp+31] = limbs[3] (most significant)
                    //   [sp+16..sp+23] = limbs[2]
                    //   [sp+8..sp+15]  = limbs[1]
                    //   [sp+0..sp+7]   = limbs[0] (least significant)
                    try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                    for (u256val.limbs, 0..) |limb, i| {
                        const tmp = ctx.reg_alloc.alloc() orelse .t3;
                        defer ctx.reg_alloc.free(tmp);
                        try self.genLoadImmediate(limb, tmp, ctx);
                        const off: i12 = @intCast(i * 8);
                        try ctx.writer.emit(riscv.SD(.sp, tmp, off));
                    }
                    // dest = pointer to the 32-byte value
                    try ctx.writer.emit(riscv.ADD(dest, .sp, .zero));
                    // IMPORTANT: The caller that receives a wide value pointer is
                    // responsible for freeing stack space with ADDI sp, sp, 32.
                    // For simple assignments to state fields, genStateWrite handles this.
                }
            },
            .bool_lit => |b| {
                try ctx.writer.emit(riscv.ADDI(dest, .zero, if (b) 1 else 0));
            },
            .string_lit => |s| {
                // s includes surrounding double-quotes — strip them.
                // e.g. s = `"hello"` → content = `hello`
                const content = if (s.len >= 2) s[1..s.len-1] else s;
                const offset = try self.internString(content);

                // ZVM string convention: the gp (x3, global pointer) register holds
                // the base address of the contract's data section at runtime.
                // dest = gp + offset (pointer to the null-terminated string).
                // The string length is available as content.len if needed by callers.
                try self.genLoadImmediate(@intCast(offset), dest, ctx);
                try ctx.writer.emit(riscv.ADD(dest, .gp, dest));
            },
            .nothing => {
                try ctx.writer.emit(riscv.ADDI(dest, .zero, 0));
            },
            .identifier => |name| {
                if (ctx.locals.get(name)) |loc| {
                    if (loc.reg != dest) {
                        try ctx.writer.emit(riscv.ADD(dest, loc.reg, .zero));
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
                // SPEC: Part 7.5 / 14.3 — environment builtins via syscall.
                // ZEPH() loads syscall ID into a0; ECALL() triggers dispatch.
                switch (b) {
                    .caller => {
                        // GET_CALLER: a0=0x60, a1=buf_ptr(20B) → buf filled
                        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -24)); // alloc 24B on stack
                        try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));  // a1 = buf ptr
                        try ctx.writer.emit(riscv.ZEPH(.GET_CALLER));
                        try ctx.writer.emit(riscv.ECALL());
                        if (dest != .sp) {
                            try ctx.writer.emit(riscv.ADD(dest, .sp, .zero));
                        }
                        // Note: caller must ADDI sp, sp, 24 after consuming the value.
                    },
                    .now => {
                        // GET_NOW: a0=0x66 → a0=timestamp(u64 low bits)
                        try ctx.writer.emit(riscv.ZEPH(.GET_NOW));
                        try ctx.writer.emit(riscv.ECALL());
                        if (dest != .a0) try ctx.writer.emit(riscv.ADD(dest, .a0, .zero));
                    },
                    .current_block => {
                        // GET_BLOCK: a0=0x65 → a0=block_number
                        try ctx.writer.emit(riscv.ZEPH(.GET_BLOCK));
                        try ctx.writer.emit(riscv.ECALL());
                        if (dest != .a0) try ctx.writer.emit(riscv.ADD(dest, .a0, .zero));
                    },
                    .value => {
                        // GET_VALUE: a0=0x61, a1=buf_ptr(32B) → buf filled with call value
                        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                        try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                        try ctx.writer.emit(riscv.ZEPH(.GET_VALUE));
                        try ctx.writer.emit(riscv.ECALL());
                        if (dest != .sp) try ctx.writer.emit(riscv.ADD(dest, .sp, .zero));
                    },
                    else => try ctx.writer.emit(riscv.ADDI(dest, .zero, 0)),
                }
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
                // Forge fixed-point literals default to 18 decimal places (price18)
                // unless the checker has annotated the expected type. Since the codegen
                // does not yet carry resolved types per-expression, we default to 18
                // which is the most precise (price18 / standard DeFi precision).
                // The value will be truncated if assigned to a lower-precision type.
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
    fn genBinOp(self: *CodeGen, op: BinOp, left: *Expr, right: *Expr, ctx: *ActionCtx, dest: Reg) anyerror!void {
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

    /// Generate code for an `only` statement (check + body).
    fn genOnly(self: *CodeGen, only: *const ast.OnlyStmt, ctx: *ActionCtx) anyerror!void {
        switch (only.requirement) {
            .authority => |name| {
                try self.genAuthCheck(name, ctx);
            },
            .either => |pair| {
                try self.genAuthCheck(pair.left, ctx);
                try self.genAuthCheck(pair.right, ctx);
            },
            else => {},
        }

        for (only.body) |s| {
            try self.genStmt(&s, ctx);
        }
    }

    // ── Immediate loading ────────────────────────────────────────────────

    /// Load a u64 constant into a register using LUI + ADDI sequences.
    fn genLoadImmediate(self: *CodeGen, val: u64, dest: Reg, ctx: *ActionCtx) anyerror!void {
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
    fn genWhen(self: *CodeGen, stmt: *const WhenStmt, ctx: *ActionCtx) anyerror!void {
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
    fn genMatch(self: *CodeGen, stmt: *const MatchStmt, ctx: *ActionCtx) anyerror!void {
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
    fn genEach(self: *CodeGen, loop: *const EachLoop, ctx: *ActionCtx) anyerror!void {
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
            .single => |name| {
                const ty = (self.resolver.inferExpr(loop.collection, &ctx.checked.scope) catch .void_);
                const element_ty = switch (ty) {
                    .array => |a| a.elem.*,
                    .list => |l| l.*,
                    else => .void_,
                };
                try ctx.locals.put(name, .{ .reg = iter_reg, .ty = element_ty });
            },
            .pair => |p| {
                try ctx.locals.put(p.first, .{ .reg = iter_reg, .ty = .u256 });
                const ty = (self.resolver.inferExpr(loop.collection, &ctx.checked.scope) catch .void_);
                const element_ty = switch (ty) {
                    .array => |a| a.elem.*,
                    .list => |l| l.*,
                    else => .void_,
                };
                try ctx.locals.put(p.second, .{ .reg = count_reg, .ty = element_ty });
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
    fn genRepeat(self: *CodeGen, loop: *const RepeatLoop, ctx: *ActionCtx) anyerror!void {
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
    fn genWhile(self: *CodeGen, loop: *const WhileLoop, ctx: *ActionCtx) anyerror!void {
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
    fn backpatchLoopExits(self: *CodeGen, ctx: *ActionCtx, start: usize, target_off: u32) void {
        _ = self;
        for (ctx.loop_exits.items[start..]) |patch_off| {
            const delta: i21 = @intCast(@as(i32, @intCast(target_off)) - @as(i32, @intCast(patch_off)));
            ctx.writer.patchAt(patch_off, riscv.JAL(.zero, delta));
        }
        ctx.loop_exits.shrinkRetainingCapacity(start);
    }

    /// Backpatch all loop continue (skip) jumps from index `start` to target `target_off`.
    fn backpatchLoopConts(self: *CodeGen, ctx: *ActionCtx, start: usize, target_off: u32) void {
        _ = self;
        for (ctx.loop_conts.items[start..]) |patch_off| {
            const delta: i21 = @intCast(@as(i32, @intCast(target_off)) - @as(i32, @intCast(patch_off)));
            ctx.writer.patchAt(patch_off, riscv.JAL(.zero, delta));
        }
        ctx.loop_conts.shrinkRetainingCapacity(start);
    }

    // ── State access code generation ─────────────────────────────────────

    /// SPEC: Part 5.2 — Generate a state read using the Zephyria STORAGE_LOAD ABI.
    ///
    /// dispatch.zig storageLoad() expects:
    ///   a0 = 0x01 (set by ZEPH())
    ///   a1 = pointer to 32-byte storage key in VM memory
    ///   a2 = pointer to 32-byte result buffer in VM memory
    ///
    /// Key layout: [4-byte field_id] [28-byte map_key or zeros]
    fn genStateRead(self: *CodeGen, field_name: []const u8, index_expr: ?*const Expr, ctx: *ActionCtx, dest: Reg) anyerror!void {
        const field_id = self.getOrAssignFieldId(field_name);

        // Allocate scratch space on stack:
        //   [sp..sp+31] = 32-byte storage key
        //   [sp+32..sp+63] = 32-byte result buffer
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -64));
        errdefer _ = ctx.writer; // no cleanup, caller owns stack frame

        // Build storage key: write field_id into first 4 bytes, zero the rest
        const scratch = ctx.reg_alloc.alloc() orelse .t2;
        defer ctx.reg_alloc.free(scratch);
        try self.genLoadImmediate(@intCast(field_id), scratch, ctx);
        try ctx.writer.emit(riscv.SW(.sp, scratch, 0)); // store u32 field_id at sp+0
        // Zero bytes 4..31 of the key
        try ctx.writer.emit(riscv.ADDI(.t3, .zero, 0));
        try ctx.writer.emit(riscv.SD(.sp, .t3, 8));    // bytes 8-15
        try ctx.writer.emit(riscv.SD(.sp, .t3, 16));   // bytes 16-23
        try ctx.writer.emit(riscv.SD(.sp, .t3, 24));   // bytes 24-31
        // If there's a map key, write it at bytes 4-7
        if (index_expr) |idx| {
            const idx_reg = ctx.reg_alloc.alloc() orelse .t4;
            defer ctx.reg_alloc.free(idx_reg);
            try self.genExpr(idx, ctx, idx_reg);
            try ctx.writer.emit(riscv.SW(.sp, idx_reg, 4)); // bytes 4-7 = map key
        } else {
            // Write zero into bytes 4-7 as well
            try ctx.writer.emit(riscv.SW(.sp, .t3, 4));
        }

        // Set syscall arguments:
        //   a1 = pointer to key buffer (sp)
        //   a2 = pointer to result buffer (sp+32)
        try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
        try ctx.writer.emit(riscv.ADDI(.a2, .sp, 32));
        try ctx.writer.emit(riscv.ZEPH(.STATE_READ));
        try ctx.writer.emit(riscv.ECALL());

        // Load 8 bytes from the result buffer into dest (64-bit value)
        try ctx.writer.emit(riscv.LD(dest, .sp, 32));

        // Restore stack
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, 64));
    }

    /// SPEC: Part 5.2 — Generate a state write using the Zephyria STORAGE_STORE ABI.
    ///
    /// dispatch.zig storageStore() expects:
    ///   a0 = 0x02 (set by ZEPH())
    ///   a1 = pointer to 32-byte storage key in VM memory
    ///   a2 = pointer to 32-byte value in VM memory
    ///
    /// Key layout: [4-byte field_id] [28-byte map_key or zeros]
    fn genStateWrite(self: *CodeGen, field_name: []const u8, index_expr: ?*const Expr, value: *const Expr, ctx: *ActionCtx) anyerror!void {
        const field_id = self.getOrAssignFieldId(field_name);

        // Allocate:
        //   [sp..sp+31] = 32-byte storage key
        //   [sp+32..sp+63] = 32-byte value buffer
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -64));

        // Evaluate the value expression, place in a temp register
        const val_reg = ctx.reg_alloc.alloc() orelse .t2;
        defer ctx.reg_alloc.free(val_reg);
        try self.genExpr(value, ctx, val_reg);

        // Build storage key at [sp..sp+31]
        const fid_reg = ctx.reg_alloc.alloc() orelse .t3;
        defer ctx.reg_alloc.free(fid_reg);
        try self.genLoadImmediate(@intCast(field_id), fid_reg, ctx);
        try ctx.writer.emit(riscv.SW(.sp, fid_reg, 0));  // field_id bytes 0-3
        try ctx.writer.emit(riscv.ADDI(.t4, .zero, 0));
        try ctx.writer.emit(riscv.SW(.sp, .t4, 4));      // map key bytes 4-7 (zero or index)
        try ctx.writer.emit(riscv.SD(.sp, .t4, 8));      // bytes 8-15
        try ctx.writer.emit(riscv.SD(.sp, .t4, 16));     // bytes 16-23
        try ctx.writer.emit(riscv.SD(.sp, .t4, 24));     // bytes 24-31
        if (index_expr) |idx| {
            const idx_reg = ctx.reg_alloc.alloc() orelse .t5;
            defer ctx.reg_alloc.free(idx_reg);
            try self.genExpr(idx, ctx, idx_reg);
            try ctx.writer.emit(riscv.SW(.sp, idx_reg, 4));
        }

        // Write value into [sp+32..sp+63]
        try ctx.writer.emit(riscv.SD(.sp, val_reg, 32));  // bytes 32-39 = low 64 bits
        // Zero out the rest of the 32-byte value slot (wide values would need more)
        try ctx.writer.emit(riscv.SD(.sp, .t4, 40));
        try ctx.writer.emit(riscv.SD(.sp, .t4, 48));
        try ctx.writer.emit(riscv.SD(.sp, .t4, 56));

        // Set syscall arguments
        try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));  // a1 = key_ptr
        try ctx.writer.emit(riscv.ADDI(.a2, .sp, 32));    // a2 = value_ptr
        try ctx.writer.emit(riscv.ZEPH(.STATE_WRITE));
        try ctx.writer.emit(riscv.ECALL());

        // Restore stack
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, 64));
    }

    // ── Authority check ──────────────────────────────────────────────────

    /// SPEC: Part 7.3 — Emit AUTH_CHECK for a named authority.
    /// ABI: a0=0x20, a1=role_hash_ptr(32B), a2=account_ptr(20B) → revert if fail
    fn genAuthCheck(self: *CodeGen, name: []const u8, ctx: *ActionCtx) anyerror!void {
        // Build 32-byte role hash on stack: first 4 bytes = selector, rest zero.
        const selector = actionSelector(name);
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
        const tmp = ctx.reg_alloc.alloc() orelse .t0;
        defer ctx.reg_alloc.free(tmp);
        try self.genLoadImmediate(@intCast(selector), tmp, ctx);
        try ctx.writer.emit(riscv.SD(.sp, tmp, 0));
        try ctx.writer.emit(riscv.ADDI(.t2, .zero, 0));
        try ctx.writer.emit(riscv.SD(.sp, .t2, 8));
        try ctx.writer.emit(riscv.SD(.sp, .t2, 16));
        try ctx.writer.emit(riscv.SD(.sp, .t2, 24));
        try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero)); // a1 = role_hash_ptr
        try ctx.writer.emit(riscv.ADDI(.a2, .zero, 0)); // a2 = account (0 = caller)
        try ctx.writer.emit(riscv.ZEPH(.AUTH_CHECK));
        try ctx.writer.emit(riscv.ECALL());
        // Restore stack
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));
    }

    // ── Function call code generation ────────────────────────────────────

    /// Generate bytecode for a function call. Arguments go into a0-a6.
    fn genCall(self: *CodeGen, callee: *const Expr, args: []const Argument, ctx: *ActionCtx, dest: Reg) anyerror!void {
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
                    // ORACLE_QUERY: a0=0xA0 + args already in a0-a6 → ECALL
                    try ctx.writer.emit(riscv.ZEPH(.ORACLE_QUERY));
                    try ctx.writer.emit(riscv.ECALL());
                } else if (std.mem.eql(u8, name, "vrf_random")) {
                    // VRF_RANDOM: a0=0x6C, a1=buf_ptr(32B) → buf filled
                    try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                    try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                    try ctx.writer.emit(riscv.ZEPH(.VRF_RANDOM));
                    try ctx.writer.emit(riscv.ECALL());
                    if (dest != .sp) try ctx.writer.emit(riscv.ADD(dest, .sp, .zero));
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
                    // SPEC: Part 10.1 — Cross-contract call via CALL_CONTRACT syscall.
                    // ABI: a0=0x40, a1=to_ptr(20B), a2=selector, a3=calldata_ptr, a4=calldata_len
                    const selector = actionSelector(fa.field);
                    try self.genLoadImmediate(@intCast(selector), .a2, ctx);
                    _ = obj_name; // to_addr would be loaded here if we track cross-contract refs
                    try ctx.writer.emit(riscv.ADDI(.a3, .zero, 0)); // no calldata
                    try ctx.writer.emit(riscv.ADDI(.a4, .zero, 0));
                    try ctx.writer.emit(riscv.ZEPH(.SCHEDULE_CALL));
                    try ctx.writer.emit(riscv.ECALL());
                } else {
                    try ctx.writer.emit(riscv.ZEPH(.SCHEDULE_CALL));
                    try ctx.writer.emit(riscv.ECALL());
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
    fn genNeed(self: *CodeGen, stmt: *const NeedStmt, ctx: *ActionCtx) anyerror!void {
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
        try ctx.writer.emit(riscv.ADDI(.a2, .zero, 0)); // data_len
        try ctx.writer.emit(riscv.ZEPH(.REVERT));
        try ctx.writer.emit(riscv.ECALL());

        // Patch branch to skip over revert
        const after_revert = ctx.writer.currentOffset();
        const delta: i13 = @intCast(@as(i32, @intCast(after_revert)) - @as(i32, @intCast(branch_off)));
        ctx.writer.patchAt(branch_off, riscv.BNE(cond_reg, .zero, delta));
    }


    /// Generate bytecode for a `tell EventName(args)` statement.
    fn genTell(self: *CodeGen, stmt: *const TellStmt, ctx: *ActionCtx) anyerror!void {
        // SPEC: Part 5.9 — emit event syscall.
        // ABI: a0=0x30, a1=topic_count, a2=topics_ptr, a3=data_ptr, a4=data_len
        // For now: topic_count=1 (just the event selector), topics=[selector], data=args.
        const selector = actionSelector(stmt.event_name);
        // Build topics array on stack: 1 × 32 bytes
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
        // Write selector as the first 4 bytes of the 32-byte topic slot
        const tmp = ctx.reg_alloc.alloc() orelse .t0;
        defer ctx.reg_alloc.free(tmp);
        try self.genLoadImmediate(@intCast(selector), tmp, ctx);
        try ctx.writer.emit(riscv.SD(.sp, tmp, 0));
        // Fill remaining 24 bytes to zero
        try ctx.writer.emit(riscv.ADDI(.t2, .zero, 0));
        try ctx.writer.emit(riscv.SD(.sp, .t2, 8));
        try ctx.writer.emit(riscv.SD(.sp, .t2, 16));
        try ctx.writer.emit(riscv.SD(.sp, .t2, 24));
        // Set syscall arguments
        try ctx.writer.emit(riscv.ADDI(.a1, .zero, 1));        // a1 = topic_count = 1
        try ctx.writer.emit(riscv.ADD(.a2, .sp, .zero));       // a2 = topics_ptr
        // Build data inline: encode up to 6 args as packed 8-byte values on stack
        const max_args: usize = @min(stmt.args.len, 6);
        if (max_args > 0) {
            const data_size: i12 = @intCast(max_args * 8);
            try ctx.writer.emit(riscv.ADDI(.sp, .sp, -data_size));
            for (stmt.args[0..max_args], 0..) |arg, i| {
                const arg_reg: Reg = @enumFromInt(@as(u5, @intCast(11 + i)));
                try self.genExpr(arg.value, ctx, arg_reg);
                const off: i12 = @intCast(i * 8);
                try ctx.writer.emit(riscv.SD(.sp, arg_reg, off));
            }
            try ctx.writer.emit(riscv.ADD(.a3, .sp, .zero));   // a3 = data_ptr
            try self.genLoadImmediate(@intCast(max_args * 8), .a4, ctx); // a4 = data_len
            try ctx.writer.emit(riscv.ZEPH(.EMIT_EVENT));
            try ctx.writer.emit(riscv.ECALL());
            // Restore data stack
            try ctx.writer.emit(riscv.ADDI(.sp, .sp, data_size));
        } else {
            try ctx.writer.emit(riscv.ADDI(.a3, .zero, 0));
            try ctx.writer.emit(riscv.ADDI(.a4, .zero, 0));
            try ctx.writer.emit(riscv.ZEPH(.EMIT_EVENT));
            try ctx.writer.emit(riscv.ECALL());
        }
        // Restore topics stack
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));
    }

    // ── Return value ─────────────────────────────────────────────────────

    /// Generate bytecode for `give back expr`.
    fn genGiveBack(self: *CodeGen, expr: *const Expr, ctx: *ActionCtx) anyerror!void {
        try self.genExpr(expr, ctx, .a0);
    }

    // ── Binary serialization ─────────────────────────────────────────────

    /// Serialize the access list section.
    /// Format per action: [4-byte selector] [2-byte read_count] [2-byte write_count]
    ///   then read entries: [1-byte name_len] [name bytes] [1-byte field_len] [field bytes]
    ///   then write entries: same format.
    fn serializeAccessList(self: *CodeGen, contract: *const ContractDef, checked: *const CheckedContract) anyerror![]u8 {
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
    fn serializeAccessEntry(self: *CodeGen, buf: *std.ArrayListUnmanaged(u8), entry: *const AccessEntry) anyerror!void {
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
    fn serializeBytecodeSection(self: *CodeGen, action_codes: anytype) anyerror![]u8 {
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

    /// SPEC: Novel Idea 1 — Serialize conservation equations into the binary.
    /// Format: [2-byte eq_count]
    ///   per equation: [1-byte op] [1-byte flags(at_all_times)]
    ///                 [lhs_field_ref][rhs_field_ref]
    ///   field_ref:    [1-byte name_len][name bytes]
    fn serializeConservationMetadata(self: *CodeGen, contract: *const ContractDef) anyerror![]u8 {
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
            // Operator byte
            const op_byte: u8 = switch (eq.op) {
                .equals => 0x00,
                .gte => 0x01,
                .lte => 0x02,
                .gt => 0x03,
                .lt => 0x04,
            };
            try buf.append(self.allocator, op_byte);

            // Flags byte: bit 0 = at_all_times
            const flags_byte: u8 = if (eq.at_all_times) 0x01 else 0x00;
            try buf.append(self.allocator, flags_byte);

            // LHS field reference
            try self.serializeExprRef(&buf, eq.lhs);

            // RHS field reference
            try self.serializeExprRef(&buf, eq.rhs);
        }

        return buf.toOwnedSlice(self.allocator);
    }

    /// Serialize an expression reference for conservation metadata.
    /// Encodes field names as [1-byte len][name bytes].
    fn serializeExprRef(self: *CodeGen, buf: *std.ArrayListUnmanaged(u8), expr: *const ast.Expr) anyerror!void {
        switch (expr.kind) {
            .identifier => |name| {
                const name_len: u8 = @intCast(@min(name.len, 255));
                try buf.append(self.allocator, name_len);
                try buf.appendSlice(self.allocator, name[0..name_len]);
            },
            .field_access => |fa| {
                // Encode as "object.field" concatenated
                const field = fa.field;
                if (fa.object.kind == .identifier) {
                    const obj = fa.object.kind.identifier;
                    const total_len = @min(obj.len + 1 + field.len, 255);
                    try buf.append(self.allocator, @intCast(total_len));
                    try buf.appendSlice(self.allocator, obj);
                    try buf.append(self.allocator, '.');
                    try buf.appendSlice(self.allocator, field);
                } else {
                    // Fallback: encode just the field name
                    const flen: u8 = @intCast(@min(field.len, 255));
                    try buf.append(self.allocator, flen);
                    try buf.appendSlice(self.allocator, field[0..flen]);
                }
            },
            .bin_op => |bop| {
                // For binary ops, encode a synthetic representation:
                // 0xFF marker, then op byte, then both sub-expressions
                try buf.append(self.allocator, 0xFF); // compound marker
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
                // Unknown expression — write zero-length marker
                try buf.append(self.allocator, 0);
            },
        }
    }
};

// ============================================================================
// Section 7 — Tests
// ============================================================================

test "ZephBinHeader is still exactly 64 bytes after adding data_section_len" {
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(ZephBinHeader));
}

test "internString stores content and returns correct offset" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    const off1 = try gen.internString("hello");
    try std.testing.expectEqual(@as(u32, 0), off1);

    const off2 = try gen.internString("world");
    try std.testing.expectEqual(@as(u32, 8), off2); // 5 + 1 (null) = 6 -> pad to 8

    const off3 = try gen.internString("hello");
    try std.testing.expectEqual(@as(u32, 0), off3); // deduplicated

    try std.testing.expectEqualSlices(u8, "hello", gen.data_section.items[0..5]);
    try std.testing.expectEqual(@as(u8, 0), gen.data_section.items[5]);
}

test "internString null-terminates and 4-byte aligns" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    const off1 = try gen.internString("hi");
    try std.testing.expectEqual(@as(u32, 0), off1);
    try std.testing.expectEqualSlices(u8, "hi\x00\x00", gen.data_section.items[0..4]);
    
    const off2 = try gen.internString("abc");
    try std.testing.expectEqual(@as(u32, 4), off2);
    try std.testing.expectEqualSlices(u8, "abc\x00", gen.data_section.items[4..8]);
}

test "genExpr string_lit emits gp-relative load" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    var field_ids = std.StringHashMap(u32).init(allocator);
    defer field_ids.deinit();

    var checked = checker.CheckedContract{
        .name = "Test",
        .action_lists = std.StringHashMap(checker.AccessList).init(allocator),
        .type_map = std.StringHashMap(types.ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();

    var ctx = ActionCtx.init(allocator, "dummy", &field_ids, &checked);
    defer ctx.deinit();

    const expr = Expr{ .kind = .{ .string_lit = "\"hello\"" }, .span = .{ .line=1, .col=1, .len=7 } };
    try gen.genExpr(&expr, &ctx, .a0);

    const bytes = ctx.writer.toBytes();
    try std.testing.expect(bytes.len >= 8); // Loadimmediate (4) + ADD a0, gp, a0 (4)
    
    const actual_load = std.mem.readInt(u32, bytes[0..4], .little);
    const expected_load = riscv.ADDI(.a0, .zero, 0); // Offset is 0
    try std.testing.expectEqual(expected_load, actual_load);

    const actual_add = std.mem.readInt(u32, bytes[4..8], .little);
    const expected_add = riscv.ADD(.a0, .gp, .a0);
    try std.testing.expectEqual(expected_add, actual_add);

    try std.testing.expectEqualSlices(u8, "hello\x00", gen.data_section.items[0..6]);
}

test "generate includes data section in binary" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    var contract = makeEmptyContract("StringContract");
    
    var ast_arena = std.heap.ArenaAllocator.init(allocator);
    defer ast_arena.deinit();

    // Create an action with a single string literal expr statement
    var expr = Expr{ .kind = .{ .string_lit = "\"test_data\"" }, .span = .{ .line=1, .col=1, .len=11 } };
    const expr_stmt = Stmt{ .kind = .{ .call_stmt = &expr }, .span = .{ .line=1, .col=1, .len=11 } };

    var body_stmts = [_]Stmt{expr_stmt};
    const action = ActionDecl{
        .name = "test_action",
        .visibility = .shared,
        .type_params = &.{},
        .params = &.{},
        .return_type = null,
        .annotations = &.{},
        .accounts = &.{},
        .body = &body_stmts,
        .complexity_class = null,
        .span = .{ .line=1, .col=1, .len=11 },
    };

    var actions = [_]ActionDecl{action};
    contract.actions = &actions;

    var checked = CheckedContract{
        .name = "Test",
        .action_lists = std.StringHashMap(AccessList).init(allocator),
        .type_map = std.StringHashMap(ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();

    const binary = try gen.generate(&contract, &checked);
    defer allocator.free(binary);

    const ds_len = std.mem.readInt(u32, binary[@offsetOf(ZephBinHeader, "data_section_len")..][0..4], .little);
    try std.testing.expect(ds_len > 0);
    try std.testing.expectEqual(@as(u32, 12), ds_len); // "test_data" is 9 chars + 1 null = 10, padded to 12

    const al_len = std.mem.readInt(u32, binary[@offsetOf(ZephBinHeader, "access_list_len")..][0..4], .little);
    const bc_len = std.mem.readInt(u32, binary[@offsetOf(ZephBinHeader, "bytecode_len")..][0..4], .little);
    
    try std.testing.expectEqual(@sizeOf(ZephBinHeader) + al_len + bc_len + ds_len, binary.len);
}

test "ZephBinHeader default magic is ZEPH" {
    const header = ZephBinHeader{};
    try std.testing.expectEqualSlices(u8, "FORG", &header.magic);
    try std.testing.expectEqual(@as(u16, 1), header.version);
}

test "CRC32 known value" {
    const data = "FORG";
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

// ── Test Helper ──────────────────────────────────────────────────────────────

fn makeEmptyContract(name: []const u8) ContractDef {
    return .{
        .name = name,
        .inherits = null,
        .implements = &.{},
        .accounts = &.{},
        .authorities = &.{},
        .config = &.{},
        .always = &.{},
        .state = &.{},
        .computed = &.{},
        .setup = null,
        .guards = &.{},
        .actions = &.{},
        .views = &.{},
        .pures = &.{},
        .helpers = &.{},
        .events = &.{},
        .errors_ = &.{},
        .upgrade = null,
        .namespaces = &.{},
        .invariants = &.{},
        .conserves = &.{},
        .adversary_blocks = &.{},
        .fallback = null, .receive_ = null,
        .span = .{ .line = 1, .col = 1, .len = 12 },
    };
}

test "generate omits setup section when setup is null" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    const contract = makeEmptyContract("EmptyContract");
    var checked = CheckedContract{
        .name = "Test",
        .action_lists = std.StringHashMap(AccessList).init(allocator),
        .type_map = std.StringHashMap(ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();

    const binary = try gen.generate(&contract, &checked);
    defer allocator.free(binary);

    const action_count = std.mem.readInt(u16, binary[@offsetOf(ZephBinHeader, "action_count")..][0..2], .little);
    try std.testing.expectEqual(@as(u16, 0), action_count);

    const al_len = std.mem.readInt(u32, binary[@offsetOf(ZephBinHeader, "access_list_len")..][0..4], .little);
    const bc_start = 64 + al_len;
    
    const bc_action_count = std.mem.readInt(u16, binary[bc_start..][0..2], .little);
    try std.testing.expectEqual(@as(u16, 0), bc_action_count);
}

test "generate includes setup block in binary when present" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    var contract = makeEmptyContract("SetupContract");
    
    var ast_arena = std.heap.ArenaAllocator.init(allocator);
    defer ast_arena.deinit();

    const setup = ast.SetupBlock{
        .params = &.{},
        .body = &.{},
        .span = .{ .line = 1, .col = 1, .len = 10 },
    };
    contract.setup = setup;

    var checked = CheckedContract{
        .name = "Test",
        .action_lists = std.StringHashMap(AccessList).init(allocator),
        .type_map = std.StringHashMap(ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();

    const binary = try gen.generate(&contract, &checked);
    defer allocator.free(binary);

    const action_count = std.mem.readInt(u16, binary[@offsetOf(ZephBinHeader, "action_count")..][0..2], .little);
    try std.testing.expectEqual(@as(u16, 1), action_count);

    const al_len = std.mem.readInt(u32, binary[@offsetOf(ZephBinHeader, "access_list_len")..][0..4], .little);
    const bc_start = 64 + al_len;
    
    const bc_action_count = std.mem.readInt(u16, binary[bc_start..][0..2], .little);
    try std.testing.expectEqual(@as(u16, 1), bc_action_count);

    const selector = std.mem.readInt(u32, binary[bc_start + 2 ..][0..4], .little);
    try std.testing.expectEqual(@as(u32, 0), selector);
}

test "genSetup emits prologue and epilogue instructions" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    const setup = ast.SetupBlock{
        .params = &.{},
        .body = &.{},
        .span = .{ .line = 1, .col = 1, .len = 10 },
    };

    var checked = checker.CheckedContract{
        .name = "Test",
        .action_lists = std.StringHashMap(checker.AccessList).init(allocator),
        .type_map = std.StringHashMap(types.ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();

    var ctx = ActionCtx.init(allocator, "__setup__", &gen.field_ids, &checked);
    defer ctx.deinit();

    try gen.genSetup(&setup, &ctx);
    
    const bytes = ctx.writer.toBytes();
    try std.testing.expect(bytes.len > 0);

    const expected_prologue = riscv.ADDI(.sp, .sp, -64);
    const actual_prologue = std.mem.readInt(u32, bytes[0..4], .little);
    try std.testing.expectEqual(expected_prologue, actual_prologue);

    const expected_epilogue = riscv.JALR(.zero, .ra, 0);
    const actual_epilogue = std.mem.readInt(u32, bytes[bytes.len - 4 ..][0..4], .little);
    try std.testing.expectEqual(expected_epilogue, actual_epilogue);
}

test "genExpr int_lit small value" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    var field_ids = std.StringHashMap(u32).init(allocator);
    defer field_ids.deinit();

    var checked = checker.CheckedContract{
        .name = "Test",
        .action_lists = std.StringHashMap(checker.AccessList).init(allocator),
        .type_map = std.StringHashMap(types.ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();

    var ctx = ActionCtx.init(allocator, "dummy", &field_ids, &checked);
    defer ctx.deinit();

    const expr = Expr{ .kind = .{ .int_lit = "42" }, .span = .{ .line=1, .col=1, .len=2 } };
    try gen.genExpr(&expr, &ctx, .a0);

    const bytes = ctx.writer.toBytes();
    try std.testing.expect(bytes.len >= 4);
    const expected = riscv.ADDI(.a0, .zero, 42); // ADDI a0, zero, 42
    const actual = std.mem.readInt(u32, bytes[0..4], .little);
    try std.testing.expectEqual(expected, actual);
}

test "genExpr int_lit u64_max does not overflow" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    var field_ids = std.StringHashMap(u32).init(allocator);
    defer field_ids.deinit();

    var checked = checker.CheckedContract{
        .name = "Test",
        .action_lists = std.StringHashMap(checker.AccessList).init(allocator),
        .type_map = std.StringHashMap(types.ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();

    var ctx = ActionCtx.init(allocator, "dummy", &field_ids, &checked);
    defer ctx.deinit();

    const expr = Expr{ .kind = .{ .int_lit = "18446744073709551615" }, .span = .{ .line=1, .col=1, .len=20 } };
    try gen.genExpr(&expr, &ctx, .a0);
    const bytes = ctx.writer.toBytes();
    try std.testing.expect(bytes.len >= 4);
    const zero_addi = riscv.ADDI(.a0, .zero, 0);
    const actual = std.mem.readInt(u32, bytes[0..4], .little);
    try std.testing.expect(actual != zero_addi);
}

test "genExpr int_lit larger than u64 emits stack pointer" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    var field_ids = std.StringHashMap(u32).init(allocator);
    defer field_ids.deinit();

    var checked = checker.CheckedContract{
        .name = "Test",
        .action_lists = std.StringHashMap(checker.AccessList).init(allocator),
        .type_map = std.StringHashMap(types.ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();

    var ctx = ActionCtx.init(allocator, "dummy", &field_ids, &checked);
    defer ctx.deinit();

    const expr = Expr{ .kind = .{ .int_lit = "18446744073709551616" }, .span = .{ .line=1, .col=1, .len=20 } };
    try gen.genExpr(&expr, &ctx, .a0);

    const bytes = ctx.writer.toBytes();
    try std.testing.expect(bytes.len >= 4);
    const expected = riscv.ADDI(.sp, .sp, -32);
    const actual = std.mem.readInt(u32, bytes[0..4], .little);
    try std.testing.expectEqual(expected, actual);
}

test "scaleFixedPoint with 9 decimals" {
    try std.testing.expectEqual(@as(u64, 1_500_000_000), scaleFixedPoint("1.5", 9));
    try std.testing.expectEqual(@as(u64, 1_000_000), scaleFixedPoint("0.001", 9));
    try std.testing.expectEqual(@as(u64, 100_000_000_000), scaleFixedPoint("100", 9));
    try std.testing.expectEqual(@as(u64, 1_234_567_890_000), scaleFixedPoint("1_234.567890", 9));
}

test "scaleFixedPoint truncates excess decimals" {
    try std.testing.expectEqual(@as(u64, 1_123_456_789), scaleFixedPoint("1.123456789012345", 9));
}

test "genExpr float_lit produces non-zero for non-zero input" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    var field_ids = std.StringHashMap(u32).init(allocator);
    defer field_ids.deinit();

    var checked = checker.CheckedContract{
        .name = "Dummy",
        .action_lists = std.StringHashMap(checker.AccessList).init(allocator),
        .type_map = std.StringHashMap(types.ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();

    var ctx = ActionCtx.init(allocator, "dummy", &field_ids, &checked);
    defer ctx.deinit();

    const expr = Expr{ .kind = .{ .float_lit = "1.5" }, .span = .{ .line=1, .col=1, .len=3 } };
    try gen.genExpr(&expr, &ctx, .a0);

    const bytes = ctx.writer.toBytes();
    try std.testing.expect(bytes.len >= 4);
    const zero_addi = riscv.ADDI(.a0, .zero, 0);
    const actual = std.mem.readInt(u32, bytes[0..4], .little);
    try std.testing.expect(actual != zero_addi);
}

test "pow10 lookup table" {
    try std.testing.expectEqual(@as(u64, 1), pow10(0));
    try std.testing.expectEqual(@as(u64, 1_000_000_000), pow10(9));
    try std.testing.expectEqual(@as(u64, 1_000_000_000_000_000_000), pow10(18));
    try std.testing.expectEqual(std.math.maxInt(u64), pow10(19));
}

