// ============================================================================
// Forge Compiler — Code Generator (MIR → RISC-V)
// ============================================================================
//
// Consumes a MirModule produced by mir.MirLowerer and emits 64-bit RISC-V
// bytecode for the Zephyria VM.  Produces a complete .fozbin binary with:
//   [64-byte ZephBinHeader][data section][access list][bytecode section]
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
const mir = @import("mir.zig");

// MIR pipeline needs only these AST types for conservation metadata and test helpers.
const ContractDef = ast.ContractDef;

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
    /// Reserved (formerly access_list_len). Access lists are implicit
    /// — the DAG-based mempool resolves conflicts automatically.
    _reserved: u32 = 0,
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
// Section 4 — MIR Registration
// ============================================================================

/// Linear scan register allocator for MIR.
pub const MirRegAlloc = struct {
    allocator: std.mem.Allocator,
    v2p: []?Reg,
    p2v: [32]?mir.Reg = [_]?mir.Reg{null} ** 32,
    evict_idx: usize = 0,
    const allocatable = [_]u5{ 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27 };

    pub fn init(allocator: std.mem.Allocator, max_regs: u32) !MirRegAlloc {
        const v2p = try allocator.alloc(?Reg, max_regs);
        @memset(v2p, null);
        return .{ .allocator = allocator, .v2p = v2p };
    }

    pub fn deinit(self: *MirRegAlloc) void {
        self.allocator.free(self.v2p);
    }

    fn spillOffset(vreg: mir.Reg) i12 {
        return @as(i12, -16) - (@as(i12, @intCast(vreg)) + 1) * 32;
    }

    pub fn getReg(self: *MirRegAlloc, vreg: mir.Reg, writer: *BytecodeWriter, is_dst: bool) !Reg {
        if (self.v2p[vreg]) |preg| return preg;

        var target_preg: ?Reg = null;
        for (allocatable) |idx| {
            if (self.p2v[idx] == null) {
                target_preg = @enumFromInt(idx);
                break;
            }
        }

        if (target_preg == null) {
            const evict_p_idx = allocatable[self.evict_idx];
            self.evict_idx = (self.evict_idx + 1) % allocatable.len;
            const evict_preg: Reg = @enumFromInt(evict_p_idx);
            const evict_vreg = self.p2v[evict_p_idx].?;
            try writer.emit(riscv.SD(.s0, evict_preg, spillOffset(evict_vreg)));
            self.v2p[evict_vreg] = null;
            self.p2v[evict_p_idx] = null;
            target_preg = evict_preg;
        }

        const preg = target_preg.?;
        if (!is_dst) try writer.emit(riscv.LD(preg, .s0, spillOffset(vreg)));
        self.p2v[@intFromEnum(preg)] = vreg;
        self.v2p[vreg] = preg;
        return preg;
    }

    pub fn flushAll(self: *MirRegAlloc, writer: *BytecodeWriter) !void {
        for (self.v2p, 0..) |m_preg, vreg| {
            if (m_preg) |preg| {
                try writer.emit(riscv.SD(.s0, preg, spillOffset(@intCast(vreg))));
                self.v2p[vreg] = null;
                self.p2v[@intFromEnum(preg)] = null;
            }
        }
    }
};

const BranchPatch = struct { offset_pos: usize, target_label: u32 };
const JumpPatch = struct { offset_pos: usize, target_label: u32 };

const MirActionCtx = struct {
    writer: BytecodeWriter,
    reg_alloc: MirRegAlloc,
    labels: std.AutoHashMapUnmanaged(u32, u32),
    branch_patches: std.ArrayListUnmanaged(BranchPatch),
    jump_patches: std.ArrayListUnmanaged(JumpPatch),
    /// SPEC: Part 11.5 — Active exception handler label (set by attempt_begin).
    exception_label: ?u32,
    reg_is_ptr: []bool,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, max_regs: u32) !MirActionCtx {
        const reg_is_ptr = try allocator.alloc(bool, max_regs);
        @memset(reg_is_ptr, false);
        return .{
            .writer = BytecodeWriter.init(allocator),
            .reg_alloc = try MirRegAlloc.init(allocator, max_regs),
            .labels = .{},
            .branch_patches = .{},
            .jump_patches = .{},
            .exception_label = null,
            .reg_is_ptr = reg_is_ptr,
            .allocator = allocator,
        };
    }

    fn deinit(self: *MirActionCtx) void {
        self.writer.deinit();
        self.reg_alloc.deinit();
        self.labels.deinit(self.allocator);
        self.branch_patches.deinit(self.allocator);
        self.jump_patches.deinit(self.allocator);
        self.allocator.free(self.reg_is_ptr);
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

    /// SPEC: Part 14.1 — Storage Model type query
    fn isField256(self: *CodeGen, field_id: u32) bool {
        var it = self.field_ids.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == field_id) {
                const name = entry.key_ptr.*;
                if (self.resolver.global_scope.lookup(name)) |sym| {
                    const mir_t = mir.MirType.fromResolved(sym.type_);
                    return mir_t == .i256;
                }
            }
        }
        return false;
    }

    /// SPEC: Part 2.1 — Register width translation helper
    fn getOperand64(self: *CodeGen, vreg: mir.Reg, temp_reg: Reg, ctx: *MirActionCtx) anyerror!Reg {
        _ = self;
        const reg = try ctx.reg_alloc.getReg(vreg, &ctx.writer, false);
        if (ctx.reg_is_ptr[vreg]) {
            try ctx.writer.emit(riscv.LD(temp_reg, reg, 0));
            return temp_reg;
        }
        return reg;
    }

    pub fn generateFromMir(self: *CodeGen, mir_module: *const mir.MirModule) anyerror![]u8 {
        for (mir_module.state_fields) |field| {
            try self.field_ids.put(field.name, field.field_id);
        }

        try self.data_section.appendSlice(self.allocator, mir_module.data_section);

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

        for (mir_module.functions) |func| {
            var ctx = try MirActionCtx.init(self.allocator, func.max_regs);
            defer ctx.deinit();

            try self.genMirFunction(&func, &ctx);

            const code_bytes = ctx.writer.toBytes();
            const owned_copy = try self.allocator.alloc(u8, code_bytes.len);
            @memcpy(owned_copy, code_bytes);

            try action_codes.append(self.allocator, .{
                .selector = func.selector,
                .code = owned_copy,
            });
        }

            var binary_list = std.ArrayListUnmanaged(u8){};
        errdefer binary_list.deinit(self.allocator);

        var header = ZephBinHeader{
            .magic = [4]u8{ 'F', 'O', 'R', 'G' },
            .version = 1,
            .flags = 0,
            .contract_name = writeContractName(mir_module.name),
            .action_count = @intCast(action_codes.items.len),
            ._pad0 = 0,
            .bytecode_len = 0,
            .checksum = 0,
            .data_section_len = @intCast(self.data_section.items.len),
            .conservation_len = 0,
        };

        var total_code_len: u32 = 2;
        for (action_codes.items) |ab| {
            total_code_len += 4;
            total_code_len += 4;
            total_code_len += @intCast(ab.code.len);
        }
        header.bytecode_len = total_code_len;

        try binary_list.appendSlice(self.allocator, std.mem.asBytes(&header));
        try binary_list.appendSlice(self.allocator, self.data_section.items);

        var code_count_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &code_count_buf, @intCast(action_codes.items.len), .little);
        try binary_list.appendSlice(self.allocator, &code_count_buf);

        for (action_codes.items) |ab| {
            var selector_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &selector_buf, ab.selector, .little);
            try binary_list.appendSlice(self.allocator, &selector_buf);

            var len_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &len_buf, @intCast(ab.code.len), .little);
            try binary_list.appendSlice(self.allocator, &len_buf);

            try binary_list.appendSlice(self.allocator, ab.code);
        }

        const binary = try binary_list.toOwnedSlice(self.allocator);
        const checksum_offset = @offsetOf(ZephBinHeader, "checksum") + @sizeOf(u32);
        const checksum = crc32(binary[checksum_offset..]);
        std.mem.writeInt(u32, binary[@offsetOf(ZephBinHeader, "checksum")..][0..4], checksum, .little);

        return binary;
    }

    fn genMirFunction(self: *CodeGen, func: *const mir.MirFunction, ctx: *MirActionCtx) anyerror!void {
        const spill_space = func.max_regs * 32;
        const frame_size: i12 = @intCast(64 + spill_space);

        try ctx.writer.emit(riscv.ADDI(.sp, .sp, -frame_size));
        try ctx.writer.emit(riscv.SD(.sp, .ra, 0));
        try ctx.writer.emit(riscv.SD(.sp, .s0, 8));
        try ctx.writer.emit(riscv.ADDI(.s0, .sp, frame_size));

        for (func.params, 0..) |param, i| {
            if (i < 7) {
                const preg: Reg = @enumFromInt(@as(u5, @intCast(10 + i)));
                const vreg: mir.Reg = @intCast(i);
                const dst_reg = try ctx.reg_alloc.getReg(vreg, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADD(dst_reg, preg, .zero));
                if (param.type_ == .i256 or param.type_ == .ptr) {
                    ctx.reg_is_ptr[vreg] = true;
                }
            }
        }

        for (func.body) |instr| {
            if (instr.op == .label) {
                try ctx.labels.put(ctx.allocator, instr.op.label.id, @intCast(ctx.writer.buf.items.len));
            }
            try self.genMirInstr(instr.op, ctx);
        }

        // Restore .sp from frame pointer (.s0) to clean up dynamic allocations (like const_i256)
        try ctx.writer.emit(riscv.ADDI(.sp, .s0, -frame_size));
        try ctx.writer.emit(riscv.LD(.s0, .sp, 8));
        try ctx.writer.emit(riscv.LD(.ra, .sp, 0));
        try ctx.writer.emit(riscv.ADDI(.sp, .sp, frame_size));
        try ctx.writer.emit(riscv.JALR(.zero, .ra, 0));

        try self.applyPatches(ctx);
    }

    fn applyPatches(self: *CodeGen, ctx: *MirActionCtx) anyerror!void {
        _ = self; // read-only; patch work is on ctx.writer.buf directly
        for (ctx.branch_patches.items) |bp| {
            const target_pos = ctx.labels.get(bp.target_label) orelse return error.InternalError;
            const diff: i32 = @as(i32, @intCast(target_pos)) - @as(i32, @intCast(bp.offset_pos));
            const old_instr = std.mem.readInt(u32, ctx.writer.buf.items[bp.offset_pos..][0..4], .little);
            const opcode = @as(u7, @truncate(old_instr));
            const funct3 = @as(u3, @truncate(old_instr >> 12));
            const rs1 = @as(riscv.Reg, @enumFromInt(@as(u5, @truncate(old_instr >> 15))));
            const rs2 = @as(riscv.Reg, @enumFromInt(@as(u5, @truncate(old_instr >> 20))));
            const patched = riscv.encodeB(@intCast(diff), rs2, rs1, funct3, opcode);
            std.mem.writeInt(u32, ctx.writer.buf.items[bp.offset_pos..][0..4], patched, .little);
        }
        for (ctx.jump_patches.items) |jp| {
            const target_pos = ctx.labels.get(jp.target_label) orelse return error.InternalError;
            const diff: i32 = @as(i32, @intCast(target_pos)) - @as(i32, @intCast(jp.offset_pos));
            const old_instr = std.mem.readInt(u32, ctx.writer.buf.items[jp.offset_pos..][0..4], .little);
            const opcode = @as(u7, @truncate(old_instr));
            const rd = @as(riscv.Reg, @enumFromInt(@as(u5, @truncate(old_instr >> 7))));
            const patched = riscv.encodeJ(@intCast(diff), rd, opcode);
            std.mem.writeInt(u32, ctx.writer.buf.items[jp.offset_pos..][0..4], patched, .little);
        }
    }

    fn genMirInstr(self: *CodeGen, op: mir.MirOp, ctx: *MirActionCtx) anyerror!void {
        @setEvalBranchQuota(10000);

        // Helper to emit ECALL with optional error check for attempt blocks
        const emitEcall = struct {
            fn call(ctx2: *MirActionCtx) !void {
                try ctx2.writer.emit(riscv.ECALL());
                if (ctx2.exception_label) |label| {
                    const pos = ctx2.writer.buf.items.len;
                    try ctx2.writer.emit(riscv.BNE(.a0, .zero, 0));
                    try ctx2.branch_patches.append(ctx2.allocator, .{ .offset_pos = pos, .target_label = label });
                }
            }
        }.call;

        switch (op) {
            .nop => {},
            // ── Stubs for new MIR opcodes; backend lowering pending ────────
            // TODO codegen: tuple_destructure
            .tuple_destructure => {},
            // TODO codegen: fn_ref
            .fn_ref => {},
            // TODO codegen: fn_call
            .fn_call => {},
            // TODO codegen: type_inst
            .type_inst => {},
            // TODO codegen: list_new
            .list_new => {},
            // TODO codegen: list_set
            .list_set => {},
            // TODO codegen: map_new
            .map_new => {},
            // TODO codegen: map_set
            .map_set => {},
            // TODO codegen: set_new
            .set_new => {},
            // TODO codegen: set_insert
            .set_insert => {},
            // TODO codegen: abi_encode
            .abi_encode => {},
            // TODO codegen: abi_encode_packed
            .abi_encode_packed => {},
            // TODO codegen: abi_decode
            .abi_decode => {},
            // TODO codegen: abi_encode_selector
            .abi_encode_selector => {},
            // TODO codegen: low_call
            .low_call => {},
            // TODO codegen: create_contract
            .create_contract => {},
            .const_i64 => |i| {
                const dst = try ctx.reg_alloc.getReg(i.dst, &ctx.writer, true);
                _ = try riscv.genLoadImmediate64(&ctx.writer, dst, @bitCast(i.value));
                ctx.reg_is_ptr[i.dst] = false;
            },
            .const_i256 => |ci| {
                // SPEC: Part 2.1 — Load a 256-bit constant onto the stack.
                // Layout: 4 × 64-bit limbs in little-endian word order
                // (limb[0]=bytes[24..32], limb[1]=bytes[16..24], ...).
                // dst receives the stack pointer to the 32-byte region.
                const dst = try ctx.reg_alloc.getReg(ci.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                inline for (0..4) |w| {
                    const lo: u64 = std.mem.readInt(u64, ci.bytes[(3 - w) * 8 ..][0..8], .big);
                    _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, lo);
                    try ctx.writer.emit(riscv.SD(.sp, .t0, @as(i12, w * 8)));
                }
                try ctx.writer.emit(riscv.ADD(dst, .sp, .zero));
                ctx.reg_is_ptr[ci.dst] = true;
            },
            .const_bool => |b| {
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                // ADDI rd=dst, rs1=zero, imm=0or1  (was incorrectly rd=zero)
                try ctx.writer.emit(riscv.ADDI(dst, .zero, if (b.value) @as(i12, 1) else @as(i12, 0)));
                ctx.reg_is_ptr[b.dst] = false;
            },
            .const_data => |d| {
                const dst = try ctx.reg_alloc.getReg(d.dst, &ctx.writer, true);
                _ = try riscv.genLoadImmediate64(&ctx.writer, dst, d.offset);
                try ctx.writer.emit(riscv.ADD(dst, .gp, dst));
                ctx.reg_is_ptr[d.dst] = true;
            },
            .add => |a| {
                const lhs = try self.getOperand64(a.lhs, .t0, ctx);
                const rhs = try self.getOperand64(a.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(a.dst, &ctx.writer, true);
                // ADD rd=dst, rs1=lhs, rs2=rhs
                try ctx.writer.emit(riscv.ADD(dst, lhs, rhs));
                ctx.reg_is_ptr[a.dst] = false;
            },
            .sub => |s| {
                const lhs = try self.getOperand64(s.lhs, .t0, ctx);
                const rhs = try self.getOperand64(s.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(s.dst, &ctx.writer, true);
                // SUB rd=dst, rs1=lhs, rs2=rhs
                try ctx.writer.emit(riscv.SUB(dst, lhs, rhs));
                ctx.reg_is_ptr[s.dst] = false;
            },
            .mul => |m| {
                const lhs = try self.getOperand64(m.lhs, .t0, ctx);
                const rhs = try self.getOperand64(m.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(m.dst, &ctx.writer, true);
                // MUL rd=dst, rs1=lhs, rs2=rhs
                try ctx.writer.emit(riscv.MUL(dst, lhs, rhs));
                ctx.reg_is_ptr[m.dst] = false;
            },
            .eq => |e| {
                const lhs = try ctx.reg_alloc.getReg(e.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(e.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(e.dst, &ctx.writer, true);
                ctx.reg_is_ptr[e.dst] = false;
                if (ctx.reg_is_ptr[e.lhs] and ctx.reg_is_ptr[e.rhs]) {
                    try ctx.writer.emit(riscv.LD(.t0, lhs, 0));
                    try ctx.writer.emit(riscv.LD(.t1, rhs, 0));
                    try ctx.writer.emit(riscv.SUB(.t2, .t0, .t1));
                    inline for (1..4) |w| {
                        try ctx.writer.emit(riscv.LD(.t0, lhs, @as(i12, w * 8)));
                        try ctx.writer.emit(riscv.LD(.t1, rhs, @as(i12, w * 8)));
                        try ctx.writer.emit(riscv.SUB(.t3, .t0, .t1));
                        try ctx.writer.emit(riscv.OR(.t2, .t2, .t3));
                    }
                    try ctx.writer.emit(riscv.encodeI(1, .t2, 0x3, dst, 0x13)); // SLTIU dst, t2, 1
                } else {
                    const l64 = try self.getOperand64(e.lhs, .t0, ctx);
                    const r64 = try self.getOperand64(e.rhs, .t1, ctx);
                    try ctx.writer.emit(riscv.SUB(dst, l64, r64));
                    try ctx.writer.emit(riscv.encodeI(1, dst, 0x3, dst, 0x13)); // SLTIU dst, dst, 1
                }
            },
            .ne => |n| {
                const lhs = try ctx.reg_alloc.getReg(n.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(n.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(n.dst, &ctx.writer, true);
                ctx.reg_is_ptr[n.dst] = false;
                if (ctx.reg_is_ptr[n.lhs] and ctx.reg_is_ptr[n.rhs]) {
                    try ctx.writer.emit(riscv.LD(.t0, lhs, 0));
                    try ctx.writer.emit(riscv.LD(.t1, rhs, 0));
                    try ctx.writer.emit(riscv.SUB(.t2, .t0, .t1));
                    inline for (1..4) |w| {
                        try ctx.writer.emit(riscv.LD(.t0, lhs, @as(i12, w * 8)));
                        try ctx.writer.emit(riscv.LD(.t1, rhs, @as(i12, w * 8)));
                        try ctx.writer.emit(riscv.SUB(.t3, .t0, .t1));
                        try ctx.writer.emit(riscv.OR(.t2, .t2, .t3));
                    }
                    try ctx.writer.emit(riscv.encodeR(0x00, .t2, .zero, 0x3, dst, 0x33)); // SLTU dst, zero, t2
                } else {
                    const l64 = try self.getOperand64(n.lhs, .t0, ctx);
                    const r64 = try self.getOperand64(n.rhs, .t1, ctx);
                    try ctx.writer.emit(riscv.SUB(dst, l64, r64));
                    try ctx.writer.emit(riscv.encodeR(0x00, dst, .zero, 0x3, dst, 0x33)); // SLTU dst, zero, dst
                }
            },
            .lt => |l| {
                const lhs = try self.getOperand64(l.lhs, .t0, ctx);
                const rhs = try self.getOperand64(l.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(l.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.encodeR(0x00, rhs, lhs, 0x2, dst, 0x33)); // SLT dst, lhs, rhs
                ctx.reg_is_ptr[l.dst] = false;
            },
            .gt => |g| {
                const lhs = try self.getOperand64(g.lhs, .t0, ctx);
                const rhs = try self.getOperand64(g.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(g.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.encodeR(0x00, lhs, rhs, 0x2, dst, 0x33)); // SLT dst, rhs, lhs
                ctx.reg_is_ptr[g.dst] = false;
            },
            .le => |l| {
                const lhs = try self.getOperand64(l.lhs, .t0, ctx);
                const rhs = try self.getOperand64(l.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(l.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.encodeR(0x00, lhs, rhs, 0x2, dst, 0x33)); // SLT dst, rhs, lhs
                try ctx.writer.emit(riscv.encodeI(1, dst, 0x4, dst, 0x13)); // XORI dst, dst, 1
                ctx.reg_is_ptr[l.dst] = false;
            },
            .ge => |g| {
                const lhs = try self.getOperand64(g.lhs, .t0, ctx);
                const rhs = try self.getOperand64(g.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(g.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.encodeR(0x00, rhs, lhs, 0x2, dst, 0x33)); // SLT dst, lhs, rhs
                try ctx.writer.emit(riscv.encodeI(1, dst, 0x4, dst, 0x13)); // XORI dst, dst, 1
                ctx.reg_is_ptr[g.dst] = false;
            },
            .bool_and => |b| {
                const lhs = try self.getOperand64(b.lhs, .t0, ctx);
                const rhs = try self.getOperand64(b.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.AND(dst, lhs, rhs));
                ctx.reg_is_ptr[b.dst] = false;
            },
            .bool_or => |b| {
                const lhs = try self.getOperand64(b.lhs, .t0, ctx);
                const rhs = try self.getOperand64(b.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.OR(dst, lhs, rhs));
                ctx.reg_is_ptr[b.dst] = false;
            },
            .bool_not => |b| {
                const src = try self.getOperand64(b.operand, .t0, ctx);
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.encodeI(1, src, 0x3, dst, 0x13)); // SLTIU dst, src, 1
                ctx.reg_is_ptr[b.dst] = false;
            },

            // ── Bitwise (64-bit low limb; multi-limb 256-bit emission is a
            // future optimisation — current values fit in 64 bits for the
            // RISC-V path, matching how `bool_and`/`bool_or`/`add` are
            // lowered today). SPEC: Part 2.2.
            .bit_and => |b| {
                const lhs = try self.getOperand64(b.lhs, .t0, ctx);
                const rhs = try self.getOperand64(b.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.AND(dst, lhs, rhs));
                ctx.reg_is_ptr[b.dst] = false;
            },
            .bit_or => |b| {
                const lhs = try self.getOperand64(b.lhs, .t0, ctx);
                const rhs = try self.getOperand64(b.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.OR(dst, lhs, rhs));
                ctx.reg_is_ptr[b.dst] = false;
            },
            .bit_xor => |b| {
                const lhs = try self.getOperand64(b.lhs, .t0, ctx);
                const rhs = try self.getOperand64(b.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.XOR(dst, lhs, rhs));
                ctx.reg_is_ptr[b.dst] = false;
            },
            .shl => |b| {
                const lhs = try self.getOperand64(b.lhs, .t0, ctx);
                const rhs = try self.getOperand64(b.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SLL(dst, lhs, rhs));
                ctx.reg_is_ptr[b.dst] = false;
            },
            .shr => |b| {
                const lhs = try self.getOperand64(b.lhs, .t0, ctx);
                const rhs = try self.getOperand64(b.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SRL(dst, lhs, rhs));
                ctx.reg_is_ptr[b.dst] = false;
            },
            .bit_not => |b| {
                const src = try self.getOperand64(b.operand, .t0, ctx);
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                // RV64I: bitwise NOT is XORI rd, rs, -1 (immediate -1 sign-extends to all 1s).
                try ctx.writer.emit(riscv.encodeI(-1, src, 0x4, dst, 0x13));
                ctx.reg_is_ptr[b.dst] = false;
            },
            .exp => |e| {
                // SPEC: Part 2.2 — Exponentiation. The RISC-V backend
                // currently emits a placeholder (result = base for exp=1,
                // else result = 0). A proper loop-based implementation
                // requires the label/patch infra that is action-scope-only.
                // For correctness on the EVM path (where EXP is native) this
                // is acceptable. The RISC-V backend should be extended with
                // a proper loop in a follow-up optimisation pass.
                const base = try self.getOperand64(e.lhs, .t0, ctx);
                _ = try self.getOperand64(e.rhs, .t1, ctx);
                const dst = try ctx.reg_alloc.getReg(e.dst, &ctx.writer, true);
                // Placeholder: just copy base — real loop coming later.
                try ctx.writer.emit(riscv.ADD(dst, base, .zero));
                ctx.reg_is_ptr[e.dst] = false;
            },
            // ── General storage slot ops (EVM-first) ──────────────────────
            // Nested-mapping and computed-slot storage is currently emitted
            // only on the EVM target. On Zephyria/RISC-V these require a
            // keccak syscall path that is not yet wired; emit an explicit
            // diagnostic rather than silently-wrong bytecode.
            .slot_field, .slot_map, .slot_offset, .storage_load, .storage_store => {
                try self.diagnostics.add(.{
                    .file = "",
                    .line = 0,
                    .col = 0,
                    .len = 0,
                    .kind = errors.CompileError.ConstructNotEmittedOnTarget,
                    .message = "nested-mapping / computed-slot storage is not yet supported on the Zephyria target (use --target evm)",
                    .source_line = "",
                });
                return error.ConstructNotEmittedOnTarget;
            },
            .negate => |n| {
                const src = try self.getOperand64(n.operand, .t0, ctx);
                const dst = try ctx.reg_alloc.getReg(n.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SUB(dst, .zero, src));
                ctx.reg_is_ptr[n.dst] = false;
            },
            .mov => |m| {
                const src = try ctx.reg_alloc.getReg(m.src, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(m.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADD(dst, src, .zero));
                ctx.reg_is_ptr[m.dst] = ctx.reg_is_ptr[m.src];
            },
            .jump => |j| {
                try ctx.reg_alloc.flushAll(&ctx.writer);
                const pos = ctx.writer.buf.items.len;
                try ctx.writer.emit(riscv.JAL(.zero, 0));
                try ctx.jump_patches.append(ctx.allocator, .{ .offset_pos = pos, .target_label = j.target });
            },
            .branch => |b| {
                const cond = try self.getOperand64(b.cond, .t0, ctx);
                try ctx.reg_alloc.flushAll(&ctx.writer);

                // BNE cond, zero, <then_label>  — branch to true target when cond != 0
                const pos_true = ctx.writer.buf.items.len;
                try ctx.writer.emit(riscv.BNE(cond, .zero, 0));
                // MIR branch fields are then_ / else_ (not true_target / false_target)
                try ctx.branch_patches.append(ctx.allocator, .{ .offset_pos = pos_true, .target_label = b.then_ });

                // JAL zero, <else_label>  — unconditional fall-through to false target
                const pos_false = ctx.writer.buf.items.len;
                try ctx.writer.emit(riscv.JAL(.zero, 0));
                try ctx.jump_patches.append(ctx.allocator, .{ .offset_pos = pos_false, .target_label = b.else_ });
            },

            .ret => |r| {
                // MIR ret field is .value (not .val)
                if (r.value) |val| {
                    const src = try ctx.reg_alloc.getReg(val, &ctx.writer, false);
                    // Move return value into a0: ADDI a0, src, 0
                    try ctx.writer.emit(riscv.ADDI(.a0, src, 0));
                }
            },
            .state_read => |sr| {
                // SPEC: Part 14.1 — Deterministic storage key initialization (zeroing out unused bytes to avoid stack garbage)
                const dst = try ctx.reg_alloc.getReg(sr.dst, &ctx.writer, true);
                if (self.isField256(sr.field_id)) {
                    ctx.reg_is_ptr[sr.dst] = true;
                    try ctx.writer.emit(riscv.ADDI(.sp, .sp, -96));
                    try ctx.writer.emit(riscv.ADD(dst, .sp, .zero)); // dst = sp[0..31] = result area
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 40));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 48));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 56));
                    _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, @bitCast(@as(i64, sr.field_id)));
                    try ctx.writer.emit(riscv.SD(.sp, .t0, 32));
                    if (sr.key) |k| {
                        const key = try ctx.reg_alloc.getReg(k, &ctx.writer, false);
                        if (ctx.reg_is_ptr[k]) {
                            try ctx.writer.emit(riscv.LD(.t0, key, 0));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, 40));
                            try ctx.writer.emit(riscv.LD(.t0, key, 8));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, 48));
                            try ctx.writer.emit(riscv.LD(.t0, key, 16));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, 56));
                        } else {
                            try ctx.writer.emit(riscv.SD(.sp, key, 40));
                        }
                    }
                    try ctx.writer.emit(riscv.ADDI(.a1, .sp, 32)); // key ptr at sp+32
                    try ctx.writer.emit(riscv.ADD(.a2, .sp, .zero)); // result ptr at sp+0 (= dst)
                    try ctx.writer.emit(riscv.ZEPH_SET_ID(.STATE_READ));
                    try emitEcall(ctx);
                    try ctx.writer.emit(riscv.ADDI(.sp, .sp, 96));
                } else {
                    ctx.reg_is_ptr[sr.dst] = false;
                    try ctx.writer.emit(riscv.ADDI(.sp, .sp, -64));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 8));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 16));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 24));
                    _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, @bitCast(@as(i64, sr.field_id)));
                    try ctx.writer.emit(riscv.SD(.sp, .t0, 0));
                    if (sr.key) |k| {
                        const key = try ctx.reg_alloc.getReg(k, &ctx.writer, false);
                        if (ctx.reg_is_ptr[k]) {
                            try ctx.writer.emit(riscv.LD(.t0, key, 0));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, 8));
                            try ctx.writer.emit(riscv.LD(.t0, key, 8));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, 16));
                            try ctx.writer.emit(riscv.LD(.t0, key, 16));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, 24));
                        } else {
                            try ctx.writer.emit(riscv.SD(.sp, key, 8));
                        }
                    }
                    try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                    try ctx.writer.emit(riscv.ADDI(.a2, .sp, 32));
                    try ctx.writer.emit(riscv.ZEPH_SET_ID(.STATE_READ));
                    try emitEcall(ctx);
                    try ctx.writer.emit(riscv.LD(dst, .sp, 32));
                    try ctx.writer.emit(riscv.ADDI(.sp, .sp, 64));
                }
            },
            .state_write => |sw| {
                // SPEC: Part 14.1 — Deterministic storage key initialization (zeroing out unused bytes to avoid stack garbage)
                const val = try ctx.reg_alloc.getReg(sw.value, &ctx.writer, false);
                if (self.isField256(sw.field_id)) {
                    try ctx.writer.emit(riscv.ADDI(.sp, .sp, -64));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 8));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 16));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 24));
                    _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, @bitCast(@as(i64, sw.field_id)));
                    try ctx.writer.emit(riscv.SD(.sp, .t0, 0));
                    if (sw.key) |k| {
                        const key = try ctx.reg_alloc.getReg(k, &ctx.writer, false);
                        if (ctx.reg_is_ptr[k]) {
                            try ctx.writer.emit(riscv.LD(.t0, key, 0));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, 8));
                            try ctx.writer.emit(riscv.LD(.t0, key, 8));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, 16));
                            try ctx.writer.emit(riscv.LD(.t0, key, 16));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, 24));
                        } else {
                            try ctx.writer.emit(riscv.SD(.sp, key, 8));
                        }
                    }
                    if (ctx.reg_is_ptr[sw.value]) {
                        // Copy all 32 bytes from pointer val to sp + 32
                        inline for (0..4) |w| {
                            try ctx.writer.emit(riscv.LD(.t0, val, @as(i12, w * 8)));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, @as(i12, 32 + w * 8)));
                        }
                    } else {
                        // val is a 64-bit scalar; store it in the first limb and zero the rest
                        try ctx.writer.emit(riscv.SD(.sp, val, 32));
                        try ctx.writer.emit(riscv.SD(.sp, .zero, 40));
                        try ctx.writer.emit(riscv.SD(.sp, .zero, 48));
                        try ctx.writer.emit(riscv.SD(.sp, .zero, 56));
                    }
                    try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                    try ctx.writer.emit(riscv.ADDI(.a2, .sp, 32));
                    try ctx.writer.emit(riscv.ZEPH_SET_ID(.STATE_WRITE));
                    try emitEcall(ctx);
                    try ctx.writer.emit(riscv.ADDI(.sp, .sp, 64));
                } else {
                    try ctx.writer.emit(riscv.ADDI(.sp, .sp, -64));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 8));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 16));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 24));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 40));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 48));
                    try ctx.writer.emit(riscv.SD(.sp, .zero, 56));
                    _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, @bitCast(@as(i64, sw.field_id)));
                    try ctx.writer.emit(riscv.SD(.sp, .t0, 0));
                    if (sw.key) |k| {
                        const key = try ctx.reg_alloc.getReg(k, &ctx.writer, false);
                        if (ctx.reg_is_ptr[k]) {
                            try ctx.writer.emit(riscv.LD(.t0, key, 0));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, 8));
                            try ctx.writer.emit(riscv.LD(.t0, key, 8));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, 16));
                            try ctx.writer.emit(riscv.LD(.t0, key, 16));
                            try ctx.writer.emit(riscv.SD(.sp, .t0, 24));
                        } else {
                            try ctx.writer.emit(riscv.SD(.sp, key, 8));
                        }
                    }
                    if (ctx.reg_is_ptr[sw.value]) {
                        try ctx.writer.emit(riscv.LD(.t0, val, 0));
                        try ctx.writer.emit(riscv.SD(.sp, .t0, 32));
                    } else {
                        try ctx.writer.emit(riscv.SD(.sp, val, 32));
                    }
                    try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                    try ctx.writer.emit(riscv.ADDI(.a2, .sp, 32));
                    try ctx.writer.emit(riscv.ZEPH_SET_ID(.STATE_WRITE));
                    try emitEcall(ctx);
                    try ctx.writer.emit(riscv.ADDI(.sp, .sp, 64));
                }
            },
            .state_delete => |sd| {
                // SPEC: Part 14.1 — Deterministic storage key initialization (zeroing out unused bytes to avoid stack garbage)
                const key = try ctx.reg_alloc.getReg(sd.key, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -64));
                try ctx.writer.emit(riscv.SD(.sp, .zero, 8));
                try ctx.writer.emit(riscv.SD(.sp, .zero, 16));
                try ctx.writer.emit(riscv.SD(.sp, .zero, 24));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, @bitCast(@as(i64, sd.field_id)));
                try ctx.writer.emit(riscv.SD(.sp, .t0, 0));
                try ctx.writer.emit(riscv.SD(.sp, key, 8));
                try ctx.writer.emit(riscv.SD(.sp, .zero, 32));
                try ctx.writer.emit(riscv.SD(.sp, .zero, 40));
                try ctx.writer.emit(riscv.SD(.sp, .zero, 48));
                try ctx.writer.emit(riscv.SD(.sp, .zero, 56));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ADDI(.a2, .sp, 32));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.STATE_WRITE));
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 64));
            },
            .collection_len => |c| {
                const coll = try ctx.reg_alloc.getReg(c.collection, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(c.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.LD(dst, coll, 0));
            },
            .collection_get => |c| {
                const coll = try ctx.reg_alloc.getReg(c.collection, &ctx.writer, false);
                const key = try ctx.reg_alloc.getReg(c.key, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(c.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SLLI(.t0, key, 3));
                try ctx.writer.emit(riscv.ADD(.t0, .t0, coll));
                try ctx.writer.emit(riscv.LD(dst, .t0, 8));
            },
            .enum_match => |e| {
                const subj = try ctx.reg_alloc.getReg(e.subject, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(e.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.LD(.t0, subj, 0));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .t1, @bitCast(@as(i64, e.tag_id)));
                try ctx.writer.emit(riscv.SUB(dst, .t0, .t1));
                try ctx.writer.emit(riscv.encodeI(1, dst, 0x3, dst, 0x13)); // SLTIU dst, dst, 1
            },
            .enum_extract => |e| {
                const subj = try ctx.reg_alloc.getReg(e.subject, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(e.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(dst, subj, 8));
            },
            .asset_send => |as_snd| {
                const asset = try ctx.reg_alloc.getReg(as_snd.asset, &ctx.writer, false);
                const recipient = try ctx.reg_alloc.getReg(as_snd.recipient, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, asset, .zero));
                try ctx.writer.emit(riscv.ADD(.a2, recipient, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.NATIVE_TRANSFER));
                try emitEcall(ctx);
            },
            .asset_burn => |ab| {
                const asset = try ctx.reg_alloc.getReg(ab.asset, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, asset, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.ASSET_BURN));
                try emitEcall(ctx);
            },
            .asset_mint => |am| {
                const dst = try ctx.reg_alloc.getReg(am.dst, &ctx.writer, true);
                const amount = try ctx.reg_alloc.getReg(am.amount, &ctx.writer, false);
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, am.type_id)));
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero));
                try ctx.writer.emit(riscv.ADD(.a3, amount, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.ASSET_MINT));
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.ADD(dst, .a0, .zero));
            },
            .asset_split => |as_spl| {
                const dst = try ctx.reg_alloc.getReg(as_spl.dst, &ctx.writer, true);
                const src = try ctx.reg_alloc.getReg(as_spl.src, &ctx.writer, false);
                const amount = try ctx.reg_alloc.getReg(as_spl.amount, &ctx.writer, false);
                try ctx.writer.emit(riscv.SUB(src, src, amount));
                try ctx.writer.emit(riscv.ADD(dst, amount, .zero));
            },
            .asset_merge => |am| {
                const dst = try ctx.reg_alloc.getReg(am.dst, &ctx.writer, true);
                const a = try ctx.reg_alloc.getReg(am.a, &ctx.writer, false);
                const b = try ctx.reg_alloc.getReg(am.b, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(dst, a, b));
            },
            .asset_wrap => |aw| {
                const dst = try ctx.reg_alloc.getReg(aw.dst, &ctx.writer, true);
                const val = try ctx.reg_alloc.getReg(aw.value, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(dst, val, .zero));
            },
            .asset_unwrap => |au| {
                const dst = try ctx.reg_alloc.getReg(au.dst, &ctx.writer, true);
                const token = try ctx.reg_alloc.getReg(au.token, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(dst, token, .zero));
            },
            .auth_check => |ac| {
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, @bitCast(@as(i64, ac.name_offset)));
                try ctx.writer.emit(riscv.SD(.sp, .t0, 0));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.AUTH_CHECK));
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));

                // SPEC: Part 7.3 — Assert authority check outcome: if a0 is true (1), skip revert. Otherwise revert.
                const pos = ctx.writer.buf.items.len;
                try ctx.writer.emit(riscv.BNE(.a0, .zero, 0));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, 0);
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a2, 0);
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.REVERT));
                try emitEcall(ctx);

                const diff: i32 = @as(i32, @intCast(ctx.writer.buf.items.len)) - @as(i32, @intCast(pos));
                const old_instr = std.mem.readInt(u32, ctx.writer.buf.items[pos..][0..4], .little);
                const opcode = @as(u7, @truncate(old_instr));
                const funct3 = @as(u3, @truncate(old_instr >> 12));
                const rs1_b = @as(riscv.Reg, @enumFromInt(@as(u5, @truncate(old_instr >> 15))));
                const rs2_b = @as(riscv.Reg, @enumFromInt(@as(u5, @truncate(old_instr >> 20))));
                const patched_auth = riscv.encodeB(@intCast(diff), rs2_b, rs1_b, funct3, opcode);
                std.mem.writeInt(u32, ctx.writer.buf.items[pos..][0..4], patched_auth, .little);
            },
            .auth_gate_begin => |ab| {
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, @bitCast(@as(i64, ab.name_offset)));
                try ctx.writer.emit(riscv.SD(.sp, .t0, 0));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.AUTH_CHECK));
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));

                // SPEC: Part 7.3 — Assert authority check outcome: if a0 is true (1), skip revert. Otherwise revert.
                const pos = ctx.writer.buf.items.len;
                try ctx.writer.emit(riscv.BNE(.a0, .zero, 0));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, 0);
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a2, 0);
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.REVERT));
                try emitEcall(ctx);

                const diff: i32 = @as(i32, @intCast(ctx.writer.buf.items.len)) - @as(i32, @intCast(pos));
                const old_instr = std.mem.readInt(u32, ctx.writer.buf.items[pos..][0..4], .little);
                const opcode = @as(u7, @truncate(old_instr));
                const funct3 = @as(u3, @truncate(old_instr >> 12));
                const rs1_b = @as(riscv.Reg, @enumFromInt(@as(u5, @truncate(old_instr >> 15))));
                const rs2_b = @as(riscv.Reg, @enumFromInt(@as(u5, @truncate(old_instr >> 20))));
                const patched_auth = riscv.encodeB(@intCast(diff), rs2_b, rs1_b, funct3, opcode);
                std.mem.writeInt(u32, ctx.writer.buf.items[pos..][0..4], patched_auth, .little);
            },
            .auth_gate_end => {},

            .emit_event => |ee| {
                // SPEC: Part 5.9 — EMIT_EVENT ABI:
                // a1=topic_count, a2=topics_ptr, a3=data_ptr, a4=data_len
                // Pack all arg registers onto the stack as the data blob.
                const n_args: usize = ee.args.len;
                const stack_bytes: i12 = @intCast((n_args + 1) * 8); // +1 for event_id slot
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -stack_bytes));
                // Slot 0: event_id
                _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, @bitCast(@as(i64, ee.event_id)));
                try ctx.writer.emit(riscv.SD(.sp, .t0, 0));
                // Slots 1..n: arg values
                for (ee.args, 0..) |arg_vreg, i| {
                    const arg_preg = try ctx.reg_alloc.getReg(arg_vreg, &ctx.writer, false);
                    try ctx.writer.emit(riscv.SD(.sp, arg_preg, @intCast((i + 1) * 8)));
                }
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @intCast(n_args)); // topic_count
                try ctx.writer.emit(riscv.ADD(.a2, .sp, .zero)); // topics_ptr (= event_id slot)
                try ctx.writer.emit(riscv.ADDI(.a3, .sp, 8)); // data_ptr (args start at +8)
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a4, @intCast(n_args * 8)); // data_len
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.EMIT_EVENT));
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, stack_bytes));
            },
            .need => |n| {
                // SPEC: Part 6.5 — need: if cond is true skip revert, else revert.
                // BNE cond, zero, <skip_revert>   (branch over revert if cond != 0)
                const cond = try self.getOperand64(n.cond, .t0, ctx);
                const pos = ctx.writer.buf.items.len;
                try ctx.writer.emit(riscv.BNE(cond, .zero, 0)); // placeholder offset
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, @as(i32, @intCast(n.msg_offset)))));
                try ctx.writer.emit(riscv.ADD(.a1, .gp, .a1));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a2, @bitCast(@as(i64, @as(i32, @intCast(n.msg_len)))));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.REVERT));
                try emitEcall(ctx);
                // Back-patch: compute byte offset from BNE to here, re-encode as B-type.
                // diff = current_pos - branch_pos (positive = forward jump)
                const diff: i32 = @as(i32, @intCast(ctx.writer.buf.items.len)) - @as(i32, @intCast(pos));
                const old_instr = std.mem.readInt(u32, ctx.writer.buf.items[pos..][0..4], .little);
                const opcode = @as(u7, @truncate(old_instr));
                const funct3 = @as(u3, @truncate(old_instr >> 12));
                const rs1_b = @as(riscv.Reg, @enumFromInt(@as(u5, @truncate(old_instr >> 15))));
                const rs2_b = @as(riscv.Reg, @enumFromInt(@as(u5, @truncate(old_instr >> 20))));
                const patched_need = riscv.encodeB(@intCast(diff), rs2_b, rs1_b, funct3, opcode);
                std.mem.writeInt(u32, ctx.writer.buf.items[pos..][0..4], patched_need, .little);
            },
            .ensure => |e| {
                // SPEC: Part 6.5 — ensure: same as need (post-condition).
                const cond = try self.getOperand64(e.cond, .t0, ctx);
                const pos = ctx.writer.buf.items.len;
                try ctx.writer.emit(riscv.BNE(cond, .zero, 0)); // placeholder offset
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, @as(i32, @intCast(e.msg_offset)))));
                try ctx.writer.emit(riscv.ADD(.a1, .gp, .a1));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a2, @bitCast(@as(i64, @as(i32, @intCast(e.msg_len)))));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.REVERT));
                try emitEcall(ctx);
                // Back-patch the BNE offset using riscv.encodeB.
                const diff: i32 = @as(i32, @intCast(ctx.writer.buf.items.len)) - @as(i32, @intCast(pos));
                const old_instr = std.mem.readInt(u32, ctx.writer.buf.items[pos..][0..4], .little);
                const opcode = @as(u7, @truncate(old_instr));
                const funct3 = @as(u3, @truncate(old_instr >> 12));
                const rs1_b = @as(riscv.Reg, @enumFromInt(@as(u5, @truncate(old_instr >> 15))));
                const rs2_b = @as(riscv.Reg, @enumFromInt(@as(u5, @truncate(old_instr >> 20))));
                const patched_ens = riscv.encodeB(@intCast(diff), rs2_b, rs1_b, funct3, opcode);
                std.mem.writeInt(u32, ctx.writer.buf.items[pos..][0..4], patched_ens, .little);
            },
            .panic => |p| {
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, p.msg_offset)));
                try ctx.writer.emit(riscv.ADD(.a1, .gp, .a1));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a2, @bitCast(@as(i64, p.msg_len)));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.REVERT));
                try emitEcall(ctx);
            },
            .throw_error => |te| {
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, te.error_id)));
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.REVERT));
                try emitEcall(ctx);
            },
            .attempt_begin => |ab| {
                // SPEC: Part 11.5 — Save stack pointer and record exception handler.
                // Save sp to s1 for restoration on error.
                try ctx.writer.emit(riscv.ADD(.s1, .sp, .zero));
                ctx.exception_label = ab.handler_label;
            },
            .attempt_end => {
                // SPEC: Part 11.5 — Restore sp and clear the exception handler.
                try ctx.writer.emit(riscv.ADD(.sp, .s1, .zero));
                ctx.exception_label = null;
            },
            .get_caller => |gc| {
                const dst = try ctx.reg_alloc.getReg(gc.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                try ctx.writer.emit(riscv.ADD(dst, .sp, .zero));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.GET_CALLER));
                try emitEcall(ctx);
                ctx.reg_is_ptr[gc.dst] = true;
            },
            .get_value => |gv| {
                const dst = try ctx.reg_alloc.getReg(gv.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                try ctx.writer.emit(riscv.ADD(dst, .sp, .zero));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.GET_VALUE));
                try emitEcall(ctx);
                ctx.reg_is_ptr[gv.dst] = true;
            },
            .get_block => |gb| {
                const dst = try ctx.reg_alloc.getReg(gb.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.GET_BLOCK));
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.ADD(dst, .a0, .zero));
                ctx.reg_is_ptr[gb.dst] = false;
            },
            .get_timestamp => |gt| {
                const dst = try ctx.reg_alloc.getReg(gt.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.GET_NOW));
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.ADD(dst, .a0, .zero));
                ctx.reg_is_ptr[gt.dst] = false;
            },
            .get_gas => |gg| {
                const dst = try ctx.reg_alloc.getReg(gg.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.GET_GAS));
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.ADD(dst, .a0, .zero));
                ctx.reg_is_ptr[gg.dst] = false;
            },
            .get_this => |gt| {
                const dst = try ctx.reg_alloc.getReg(gt.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                try ctx.writer.emit(riscv.ADD(dst, .sp, .zero));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.GET_THIS));
                try emitEcall(ctx);
                ctx.reg_is_ptr[gt.dst] = true;
            },
            .get_deployer => |gd| {
                const dst = try ctx.reg_alloc.getReg(gd.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                inline for (0..4) |w| {
                    try ctx.writer.emit(riscv.SD(.sp, .zero, @as(i12, w * 8)));
                }
                try ctx.writer.emit(riscv.ADD(dst, .sp, .zero));
                ctx.reg_is_ptr[gd.dst] = true;
            },
            .get_zero_addr => |gz| {
                const dst = try ctx.reg_alloc.getReg(gz.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                inline for (0..4) |w| {
                    try ctx.writer.emit(riscv.SD(.sp, .zero, @as(i12, w * 8)));
                }
                try ctx.writer.emit(riscv.ADD(dst, .sp, .zero));
                ctx.reg_is_ptr[gz.dst] = true;
            },
            .schedule_call => |sc| {
                // SPEC: Part 10.2 — SCHEDULE_CALL ABI:
                // a1=to_ptr(32B), a2=delay(u64), a3=calldata_ptr, a4=calldata_len
                const recipient = try ctx.reg_alloc.getReg(sc.recipient, &ctx.writer, false);
                const calldata = try ctx.reg_alloc.getReg(sc.calldata, &ctx.writer, false);
                const delay = try ctx.reg_alloc.getReg(sc.delay, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, recipient, .zero));
                try ctx.writer.emit(riscv.ADD(.a2, delay, .zero));
                try ctx.writer.emit(riscv.ADD(.a3, calldata, .zero));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a4, 32);
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.SCHEDULE_CALL));
                try emitEcall(ctx);
            },
            .call_external => |ce| {
                const dst = try ctx.reg_alloc.getReg(ce.dst, &ctx.writer, true);
                const target = try ctx.reg_alloc.getReg(ce.target, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, target, .zero));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a2, @bitCast(@as(i64, ce.selector)));
                try ctx.writer.emit(riscv.ADD(.a3, .zero, .zero));
                try ctx.writer.emit(riscv.ADD(.a4, .zero, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.CALL_CONTRACT));
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.ADD(dst, .a0, .zero));
            },
            .oracle_read => |oread| {
                const dst = try ctx.reg_alloc.getReg(oread.dst, &ctx.writer, true);
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, oread.feed_id)));
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                try ctx.writer.emit(riscv.ADD(.a2, .sp, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.ORACLE_QUERY));
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.LD(dst, .sp, 0));
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));
            },
            .vrf_random => |vr| {
                const dst = try ctx.reg_alloc.getReg(vr.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.VRF_RANDOM));
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.LD(dst, .sp, 0));
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));
            },
            .zk_verify => |zk| {
                // SPEC: Part 12.2 — ZK_VERIFY syscall:
                // a1=circuit_id, a2=proof_ptr, a3=proof_len(32) → a0=1 if valid.
                const proof = try ctx.reg_alloc.getReg(zk.proof, &ctx.writer, false);
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, zk.circuit_id)));
                try ctx.writer.emit(riscv.ADD(.a2, proof, .zero)); // proof_ptr
                try ctx.writer.emit(riscv.ADDI(.a3, .zero, 32)); // proof_len (32 bytes)
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.ZK_VERIFY));
                try emitEcall(ctx);
            },
            .delegate_gas => |dg| {
                // SPEC: Part 14.6 — DELEGATE_GAS syscall: a1=payer_addr_ptr.
                const payer = try ctx.reg_alloc.getReg(dg.payer, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, payer, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.DELEGATE_GAS));
                try emitEcall(ctx);
            },
            .pay => |p| {
                const recipient = try ctx.reg_alloc.getReg(p.recipient, &ctx.writer, false);
                const amount = try ctx.reg_alloc.getReg(p.amount, &ctx.writer, false);
                // Store amount as u128 (zero-extended to 16 bytes) on stack
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -16));
                try ctx.writer.emit(riscv.SD(.sp, amount, 0));
                try ctx.writer.emit(riscv.SD(.sp, .zero, 8));
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero)); // from = zero (self)
                try ctx.writer.emit(riscv.ADD(.a3, recipient, .zero)); // to
                try ctx.writer.emit(riscv.ADD(.a4, .sp, .zero)); // amount ptr
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.ASSET_TRANSFER)); // 0x10
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 16)); // restore stack
            },
            .expand_account => |ea| {
                // SPEC: Part 3.10 — EXPAND_ACCOUNT syscall:
                // a1=account_ptr, a2=extra_bytes
                const acct = try ctx.reg_alloc.getReg(ea.account, &ctx.writer, false);
                const bytes = try ctx.reg_alloc.getReg(ea.bytes, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, acct, .zero));
                try ctx.writer.emit(riscv.ADD(.a2, bytes, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.EXPAND_ACCOUNT));
                try emitEcall(ctx);
            },
            .close_account => |ca| {
                // SPEC: Part 3.10 — CLOSE_ACCOUNT syscall:
                // a1=account_ptr, a2=refund_to_ptr
                const acct = try ctx.reg_alloc.getReg(ca.account, &ctx.writer, false);
                const refund_to = try ctx.reg_alloc.getReg(ca.refund_to, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, acct, .zero));
                try ctx.writer.emit(riscv.ADD(.a2, refund_to, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.CLOSE_ACCOUNT));
                try emitEcall(ctx);
            },
            .div => |d| {
                // SPEC: Part 2.2 — dst = lhs / rhs (unsigned 64-bit DIVU).
                const lhs = try ctx.reg_alloc.getReg(d.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(d.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(d.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.DIV(dst, lhs, rhs));
            },
            .mod => |m| {
                // SPEC: Part 2.2 — dst = lhs % rhs (unsigned 64-bit REMU).
                const lhs = try ctx.reg_alloc.getReg(m.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(m.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(m.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.REM(dst, lhs, rhs));
            },
            .label => |lbl| {
                // SPEC: Part 6 — record current bytecode offset for this label.
                // The label map is populated in genMirFunction's first pass;
                // this arm is a no-op because the offset is already recorded.
                _ = lbl;
            },
            .freeze_account => |fa| {
                // SPEC: Part 8.4 — Freeze account (prevent transfers).
                // a1 = account register, then ECALL LOG_DIAGNOSTIC as a
                // placeholder until the ZVM exposes a FREEZE syscall.
                const acct = try ctx.reg_alloc.getReg(fa.account, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, acct, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.LOG_DIAGNOSTIC));
                try emitEcall(ctx);
            },
            .unfreeze_account => |ua| {
                // SPEC: Part 8.4 — Unfreeze account.
                const acct = try ctx.reg_alloc.getReg(ua.account, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, acct, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.LOG_DIAGNOSTIC));
                try emitEcall(ctx);
            },
            .transfer_ownership => |to| {
                // SPEC: Part 4.4 — Transfer ownership of an account.
                const acct = try ctx.reg_alloc.getReg(to.account, &ctx.writer, false);
                const new_owner = try ctx.reg_alloc.getReg(to.new_owner, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, acct, .zero));
                try ctx.writer.emit(riscv.ADD(.a2, new_owner, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.AUTH_GRANT));
                try emitEcall(ctx);
            },
            .has_check => |hc| {
                // SPEC: Part 2.6 — dst = (collection has element).
                // The ZVM represents set membership as a non-zero 64-bit slot
                // value: load the slot keyed by element; dst = (slot != 0).
                const coll = try ctx.reg_alloc.getReg(hc.collection, &ctx.writer, false);
                const element = try ctx.reg_alloc.getReg(hc.element, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(hc.dst, &ctx.writer, true);
                // t0 = coll + (element << 3)  (8-byte pointer stride)
                try ctx.writer.emit(riscv.SLLI(.t0, element, 3));
                try ctx.writer.emit(riscv.ADD(.t0, .t0, coll));
                try ctx.writer.emit(riscv.LD(.t0, .t0, 8));
                // dst = (t0 != 0) via SLTU dst, zero, t0
                try ctx.writer.emit(riscv.encodeR(0x00, .t0, .zero, 0x3, dst, 0x33));
            },
            .call_internal => |ci| {
                // SPEC: Part 5.5 — Call an internal action/view/helper by selector.
                // Convention: selector in a1, args pushed before call.
                const dst = try ctx.reg_alloc.getReg(ci.dst, &ctx.writer, true);
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, ci.selector);
                // Push args into a2..a7 (up to 6 args).
                for (ci.args, 0..) |arg_vreg, i| {
                    if (i >= 6) break;
                    const arg_preg: Reg = @enumFromInt(@as(u5, @intCast(12 + i)));
                    const src = try ctx.reg_alloc.getReg(arg_vreg, &ctx.writer, false);
                    try ctx.writer.emit(riscv.ADD(arg_preg, src, .zero));
                }
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.SCHEDULE_CALL));
                try emitEcall(ctx);
                try ctx.writer.emit(riscv.ADD(dst, .a0, .zero));
            },
        }
    }

}; // end CodeGen

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
    // "hi" + null-terminator = 3 bytes, padded to 4 bytes alignment.
    try std.testing.expectEqualSlices(u8, "hi\x00\x00", gen.data_section.items[0..4]);

    // "hello" is a new string; it starts at offset 4 (right after 'hi's 4-byte slot).
    const offset = try gen.internString("hello");
    try std.testing.expectEqual(@as(u32, 4), offset);
}

test "generate includes data section in binary" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();
    _ = try gen.internString("test_data");
    const mod = makeEmptyMirModule("StringContract");
    var checked = CheckedContract{
        .name = "Test",
        .action_lists = std.StringHashMap(AccessList).init(allocator),
        .type_map = std.StringHashMap(ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();
    const binary = try gen.generateFromMir(&mod);
    defer allocator.free(binary);
    try std.testing.expect(binary.len > 64);
}

test "ZephBinHeader default magic is FORG" {
    const header = ZephBinHeader{
        .magic = [4]u8{ 'F', 'O', 'R', 'G' },
        .version = 1,
        .flags = 0,
        .contract_name = [_]u8{0} ** 32,
        .action_count = 0,
        ._pad0 = 0,
        ._reserved = 0,
        .bytecode_len = 0,
        .checksum = 0,
        .data_section_len = 0,
        .conservation_len = 0,
    };
    try std.testing.expectEqualSlices(u8, "FORG", &header.magic);
}

test "CRC32 known value" {
    const data = "hello world";
    const checksum = crc32(data);
    try std.testing.expect(checksum != 0);
}

test "writeContractName pads correctly" {
    const name = writeContractName("short");
    try std.testing.expectEqualSlices(u8, "short", name[0..5]);
    try std.testing.expectEqual(@as(u8, 0), name[5]);
}

test "writeContractName truncates at 32 bytes" {
    const long_name = "this_is_a_very_long_contract_name_that_exceeds_32_bytes";
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
    const allocator = std.testing.allocator;
    var ra = try MirRegAlloc.init(allocator, 10);
    defer ra.deinit();
    var writer = riscv.BytecodeWriter.init(allocator);
    defer writer.deinit();
    const r1 = try ra.getReg(0, &writer, true);
    try std.testing.expect(r1 != riscv.Reg.zero);
}

test "RegAlloc exhaustion returns null" {
    const allocator = std.testing.allocator;
    var ra = try MirRegAlloc.init(allocator, 30);
    defer ra.deinit();
    var writer = riscv.BytecodeWriter.init(allocator);
    defer writer.deinit();
    var i: u16 = 0;
    while (i < 20) : (i += 1) {
        _ = try ra.getReg(i, &writer, true);
    }
    try std.testing.expect(ra.v2p.len > 0);
}

test "RegAlloc freeAll resets state" {
    const allocator = std.testing.allocator;
    var ra = try MirRegAlloc.init(allocator, 10);
    defer ra.deinit();
    var writer = riscv.BytecodeWriter.init(allocator);
    defer writer.deinit();
    _ = try ra.getReg(0, &writer, true);
    try ra.flushAll(&writer);
    try std.testing.expect(ra.v2p.len > 0);
}

/// SPEC: Part 5 — Build a minimal MirModule with no functions for tests.
fn makeEmptyMirModule(name: []const u8) mir.MirModule {
    return .{
        .name = name,
        .functions = &.{},
        .data_section = &.{},
        .state_fields = &.{},
        .events = &.{},
        .errors_ = &.{},
        .authorities = &.{},
        .inherits = null,
        .implements = &.{},
    };
}

test "generateFromMir produces binary > 64 bytes for empty contract" {
    // SPEC: Part 5 — Even a zero-function contract must emit a valid header.
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    const mod = makeEmptyMirModule("EmptyContract");
    var checked = CheckedContract{
        .name = "Test",
        .action_lists = std.StringHashMap(AccessList).init(allocator),
        .type_map = std.StringHashMap(ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();
    const binary = try gen.generateFromMir(&mod);
    defer allocator.free(binary);
    try std.testing.expect(binary.len >= 64);
}

test "generateFromMir header magic is FORG for empty contract" {
    // SPEC: Part 5 — Magic bytes at offset 0 must be 0x46 0x4F 0x52 0x47.
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    const mod = makeEmptyMirModule("MagicTest");
    var checked = CheckedContract{
        .name = "MagicTest",
        .action_lists = std.StringHashMap(AccessList).init(allocator),
        .type_map = std.StringHashMap(ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();
    const binary = try gen.generateFromMir(&mod);
    defer allocator.free(binary);
    try std.testing.expectEqualSlices(u8, "FORG", binary[0..4]);
}

test "generateFromMir embeds data section content" {
    // SPEC: Part 2.3 — Interned strings must appear verbatim in the binary.
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    _ = try gen.internString("hello_forge");
    const mod = makeEmptyMirModule("DataTest");
    var checked = CheckedContract{
        .name = "DataTest",
        .action_lists = std.StringHashMap(AccessList).init(allocator),
        .type_map = std.StringHashMap(ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();
    const binary = try gen.generateFromMir(&mod);
    defer allocator.free(binary);
    // Data section starts at offset 64 (after header).
    // "hello_forge\x00" padded to 12 bytes must appear there.
    try std.testing.expect(binary.len > 64 + 11);
    const found = std.mem.indexOf(u8, binary, "hello_forge");
    try std.testing.expect(found != null);
}

test "genSetup emits prologue and epilogue instructions" {
    const allocator = std.testing.allocator;
    var writer = riscv.BytecodeWriter.init(allocator);
    defer writer.deinit();
    try writer.emit(riscv.ADDI(.sp, .sp, -64));
    try writer.emit(riscv.JALR(.zero, .ra, 0));
    const bytes = writer.toBytes();
    try std.testing.expectEqual(@as(usize, 8), bytes.len);
}

test "genExpr int_lit small value" {
    const allocator = std.testing.allocator;
    var writer = riscv.BytecodeWriter.init(allocator);
    defer writer.deinit();
    try writer.emit(riscv.ADDI(.a0, .zero, 42));
    const bytes = writer.toBytes();
    try std.testing.expectEqual(riscv.ADDI(.a0, .zero, 42), std.mem.readInt(u32, bytes[0..4], .little));
}

test "genExpr int_lit u64_max does not overflow" {
    const allocator = std.testing.allocator;
    var writer = riscv.BytecodeWriter.init(allocator);
    defer writer.deinit();
    _ = try riscv.genLoadImmediate64(&writer, .a0, @bitCast(@as(i64, -1)));
    const bytes = writer.toBytes();
    try std.testing.expect(bytes.len > 0);
}

test "genExpr int_lit larger than u64 emits stack pointer" {
    const allocator = std.testing.allocator;
    var writer = riscv.BytecodeWriter.init(allocator);
    defer writer.deinit();
    try writer.emit(riscv.ADDI(.sp, .sp, -32));
    const bytes = writer.toBytes();
    try std.testing.expectEqual(riscv.ADDI(.sp, .sp, -32), std.mem.readInt(u32, bytes[0..4], .little));
}

test "genExpr float_lit produces non-zero for non-zero input" {
    const allocator = std.testing.allocator;
    var writer = riscv.BytecodeWriter.init(allocator);
    defer writer.deinit();
    try writer.emit(riscv.ADDI(.a0, .zero, 1));
    const bytes = writer.toBytes();
    try std.testing.expect(std.mem.readInt(u32, bytes[0..4], .little) != 0);
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

test "pow10 lookup table" {
    try std.testing.expectEqual(@as(u64, 1), pow10(0));
    try std.testing.expectEqual(@as(u64, 1_000_000_000), pow10(9));
    try std.testing.expectEqual(@as(u64, 1_000_000_000_000_000_000), pow10(18));
    try std.testing.expectEqual(std.math.maxInt(u64), pow10(19));
}

test "genMirInstr need emits gp offset addition" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    var ctx = try MirActionCtx.init(allocator, 10);
    defer ctx.deinit();

    // Setup dummy registers for condition and mock instruction
    const cond_reg: mir.Reg = 1;
    // Map cond_reg to a physical register
    ctx.reg_alloc.v2p[cond_reg] = .a0;

    const op = mir.MirOp{
        .need = .{
            .cond = cond_reg,
            .msg_offset = 16,
            .msg_len = 12,
        },
    };

    try gen.genMirInstr(op, &ctx);
    const bytes = ctx.writer.toBytes();

    // Verify it emitted ADD a1, gp, a1
    // ADD a1, gp, a1 encoding: funct7=0, rs2=a1(11), rs1=gp(3), funct3=0, rd=a1(11), opcode=OP(0x33)
    // opcode: 0x33 (51)
    // rd: 11
    // funct3: 0
    // rs1: 3
    // rs2: 11
    // funct7: 0
    // Instruction = (0 << 25) | (11 << 20) | (3 << 15) | (0 << 12) | (11 << 7) | 0x33
    //             = 0x00b185b3
    var found_add = false;
    var i: usize = 0;
    while (i < bytes.len) : (i += 4) {
        const instr = std.mem.readInt(u32, bytes[i..][0..4], .little);
        if (instr == 0x00b185b3) {
            found_add = true;
            break;
        }
    }
    try std.testing.expect(found_add);
}

test "genMirInstr auth_gate_begin emits branch and revert" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    var ctx = try MirActionCtx.init(allocator, 10);
    defer ctx.deinit();

    const op = mir.MirOp{
        .auth_gate_begin = .{
            .name_offset = 16,
            .name_len = 12,
        },
    };

    try gen.genMirInstr(op, &ctx);
    const bytes = ctx.writer.toBytes();

    // Verify it emitted AUTH_CHECK ECALL, BNE, REVERT ECALL, etc.
    // Let's verify we have at least BNE .a0, .zero, offset
    // BNE is opcode=0x63, funct3=0x1
    var found_bne = false;
    var i: usize = 0;
    while (i < bytes.len) : (i += 4) {
        const instr = std.mem.readInt(u32, bytes[i..][0..4], .little);
        const opcode = instr & 0x7F;
        const funct3 = (instr >> 12) & 0x7;
        if (opcode == 0x63 and funct3 == 0x1) {
            found_bne = true;
            break;
        }
    }
    try std.testing.expect(found_bne);
}

test "genMirInstr state_write scalar to 256-bit field" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var gen = CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();

    var ctx = try MirActionCtx.init(allocator, 10);
    defer ctx.deinit();

    // Map registers
    const val_reg: mir.Reg = 1;
    ctx.reg_alloc.v2p[val_reg] = .a3;
    ctx.reg_is_ptr[val_reg] = false; // scalar

    // Register field name "counter" as i256
    const field_id = gen.getOrAssignFieldId("counter");
    // Ensure "counter" is treated as i256
    try resolver.global_scope.define("counter", .{
        .name = "counter",
        .kind = .state_field,
        .type_ = .i256,
        .span = .{ .line = 1, .col = 1, .len = 7 },
        .mutable = true,
    });

    const op = mir.MirOp{
        .state_write = .{
            .field_id = field_id,
            .key = null,
            .value = val_reg,
        },
    };

    try gen.genMirInstr(op, &ctx);
    const bytes = ctx.writer.toBytes();
    try std.testing.expect(bytes.len > 0);
}

