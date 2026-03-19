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
    /// Reserved padding to reach exactly 64 bytes.
    _reserved: [8]u8 = [_]u8{0} ** 8,
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
// Section 6 — Code Generator
// ============================================================================

/// Main code generator. Walks the checked AST and emits a .fozbin binary.
pub const CodeGenPolkaVM = struct {
    allocator: std.mem.Allocator,
    diagnostics: *DiagnosticList,
    resolver: *TypeResolver,
    field_ids: std.StringHashMap(u32),
    next_field_id: u32,

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
        };
    }

    /// Release all internal resources.
    pub fn deinit(self: *CodeGenPolkaVM) void {
        self.field_ids.deinit();
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

        // action_count includes both actions and views (both are externally callable)
        const action_count: u16 = @intCast(contract.actions.len + contract.views.len);

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

        // ── Serialize access list section ────────────────────────────────
        const access_list_bytes = try self.serializeAccessList(contract, checked);
        defer self.allocator.free(access_list_bytes);

        // ── Serialize bytecode section ───────────────────────────────────
        const bytecode_bytes = try self.serializeBytecodeSection(action_codes.items);
        defer self.allocator.free(bytecode_bytes);

        // ── Assemble final binary ────────────────────────────────────────
        var header = PolkaVmHeader{};
        header.contract_name = writeContractName(contract.name);
        header.action_count = action_count;
        header.flags = flags;
        header.access_list_len = @intCast(access_list_bytes.len);
        header.bytecode_len = @intCast(bytecode_bytes.len);

        const total_size = @sizeOf(PolkaVmHeader) + access_list_bytes.len + bytecode_bytes.len;
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
                const val = std.fmt.parseInt(u64, lit, 10) catch 0;
                try self.genLoadImmediate(val, dest, ctx);
            },
            .bool_lit => |b| {
                try ctx.writer.emit(riscv.ADDI(dest, .zero, if (b) 1 else 0));
            },
            .string_lit => |s| {
                try self.genLoadImmediate(@intCast(s.len), dest, ctx);
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
            .float_lit => |_| {
                try ctx.writer.emit(riscv.ADDI(dest, .zero, 0));
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
        // pallet-revive: get_storage(flags: u32, key_ptr: *const u8, key_len: u32, out_ptr: *mut u8, out_len_ptr: *mut u32)
        const field_id = self.getOrAssignFieldId(field_name);
        
        // 1. write field_id to stack so we have a key_ptr
        try self.genLoadImmediate(@intCast(field_id), .t0, ctx);
        try ctx.writer.emit(riscv.SD(.sp, .t0, -8));
        
        // a0 = flags (0)
        try ctx.writer.emit(riscv.ADDI(.a0, .zero, 0));
        // a1 = key_ptr (sp - 8)
        try ctx.writer.emit(riscv.ADDI(.a1, .sp, -8));
        // a2 = key_len (8 bytes for u64 field_id)
        try ctx.writer.emit(riscv.ADDI(.a2, .zero, 8));
        // a3 = out_ptr (sp - 16)
        try ctx.writer.emit(riscv.ADDI(.a3, .sp, -16));
        // a4 = out_len_ptr (sp - 24, where we store 8 for expected length)
        try self.genLoadImmediate(8, .t1, ctx);
        try ctx.writer.emit(riscv.SD(.sp, .t1, -24));
        try ctx.writer.emit(riscv.ADDI(.a4, .sp, -24));

        _ = index_expr; // dynamic keys not fully implemented in stub
        
        try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.STATE_READ)));
        
        // load result from out_ptr to dest
        try ctx.writer.emit(riscv.LD(dest, .sp, -16));
    }

    /// Generate a state write: value → SSTORE(field_id).
    fn genStateWrite(self: *CodeGenPolkaVM, field_name: []const u8, index_expr: ?*const Expr, value: *const Expr, ctx: *ActionCtx) anyerror!void {
        // pallet-revive: set_storage(flags: u32, key_ptr: *const u8, key_len: u32, value_ptr: *const u8, value_len: u32)
        const field_id = self.getOrAssignFieldId(field_name);
        const val_reg = ctx.reg_alloc.alloc() orelse .t0;
        defer ctx.reg_alloc.free(val_reg);
        try self.genExpr(value, ctx, val_reg);
        
        // 1. Write field_id to stack
        try self.genLoadImmediate(@intCast(field_id), .t1, ctx);
        try ctx.writer.emit(riscv.SD(.sp, .t1, -8));
        // 2. Write value to stack
        try ctx.writer.emit(riscv.SD(.sp, val_reg, -16));

        // a0 = flags (0)
        try ctx.writer.emit(riscv.ADDI(.a0, .zero, 0));
        // a1 = key_ptr (sp - 8)
        try ctx.writer.emit(riscv.ADDI(.a1, .sp, -8));
        // a2 = key_len (8)
        try ctx.writer.emit(riscv.ADDI(.a2, .zero, 8));
        // a3 = value_ptr (sp - 16)
        try ctx.writer.emit(riscv.ADDI(.a3, .sp, -16));
        // a4 = value_len (8)
        try ctx.writer.emit(riscv.ADDI(.a4, .zero, 8));

        _ = index_expr;
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
                // Internal call via selector
                const selector = actionSelector(name);
                try self.genLoadImmediate(@intCast(selector), .t0, ctx);
                try ctx.writer.emit(riscv.JALR(.ra, .t0, 0));
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
        // pallet-revive deposit_event(topics_ptr: *const [u8; 32], num_topic: u32, data_ptr: *const u8, data_len: u32)
        const selector = actionSelector(stmt.event_name);
        
        // Store selector (topic hash substitute) on stack
        try self.genLoadImmediate(@intCast(selector), .t0, ctx);
        try ctx.writer.emit(riscv.SD(.sp, .t0, -32)); // 32 byte topic array fake

        // Serialize args to stack (simple flat buffer for data_ptr)
        // This is a stub for the ABI register mapping
        var offset: i12 = -40;
        for (stmt.args) |arg| {
            const arg_reg = ctx.reg_alloc.alloc() orelse .t1;
            try self.genExpr(arg.value, ctx, arg_reg);
            try ctx.writer.emit(riscv.SD(.sp, arg_reg, offset));
            ctx.reg_alloc.free(arg_reg);
            offset -= 8;
        }

        // a0 = topics_ptr
        try ctx.writer.emit(riscv.ADDI(.a0, .sp, -32));
        // a1 = num_topic (1 topic: the selector)
        try ctx.writer.emit(riscv.ADDI(.a1, .zero, 1));
        // a2 = data_ptr (starts at -40)
        try ctx.writer.emit(riscv.ADDI(.a2, .sp, offset));
        // a3 = data_len
        const total_len = -40 - offset;
        try self.genLoadImmediate(@intCast(total_len), .a3, ctx);

        try ctx.writer.emit(riscv.ECALLI(@intFromEnum(PolkaHostCalls.EMIT_EVENT)));
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
