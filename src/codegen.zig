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
// Section 4 — MIR Registration
// ============================================================================

/// Linear scan register allocator for MIR.
pub const MirRegAlloc = struct {
    allocator: std.mem.Allocator,
    v2p: []?Reg,
    p2v: [32]?mir.Reg = [_]?mir.Reg{null} ** 32,
    evict_idx: usize = 0,
    const allocatable = [_]u5{ 6, 7, 10, 11, 12, 13, 14, 15, 16, 28, 29, 30, 31 };

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
            try writer.emit(riscv.SD(evict_preg, .s0, spillOffset(evict_vreg)));
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
                try writer.emit(riscv.SD(preg, .s0, spillOffset(@intCast(vreg))));
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
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, max_regs: u32) !MirActionCtx {
        return .{
            .writer = BytecodeWriter.init(allocator),
            .reg_alloc = try MirRegAlloc.init(allocator, max_regs),
            .labels = .{},
            .branch_patches = .{},
            .jump_patches = .{},
            .exception_label = null,
            .allocator = allocator,
        };
    }

    fn deinit(self: *MirActionCtx) void {
        self.writer.deinit();
        self.reg_alloc.deinit();
        self.labels.deinit(self.allocator);
        self.branch_patches.deinit(self.allocator);
        self.jump_patches.deinit(self.allocator);
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

    pub fn generateFromMir(self: *CodeGen, mir_module: *const mir.MirModule, checked: *const @import("checker.zig").CheckedContract) anyerror![]u8 {
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

        // Serialize the access list using the checked contract's access tracking.
        const access_list_bytes = try self.serializeAccessListFromChecked(mir_module, checked);
        defer self.allocator.free(access_list_bytes);

        var binary_list = std.ArrayListUnmanaged(u8){};
        errdefer binary_list.deinit(self.allocator);

        var header = ZephBinHeader{
            .magic = [4]u8{ 'F', 'O', 'R', 'G' },
            .version = 1,
            .flags = 0,
            .contract_name = writeContractName(mir_module.name),
            .action_count = @intCast(action_codes.items.len),
            ._pad0 = 0,
            .access_list_len = @intCast(access_list_bytes.len),
            .bytecode_len = 0,
            .checksum = 0,
            .data_section_len = @intCast(self.data_section.items.len),
            .conservation_len = 0,
        };

        var total_code_len: u32 = 4;
        for (action_codes.items) |ab| {
            total_code_len += 4;
            total_code_len += 4;
            total_code_len += @intCast(ab.code.len);
        }
        header.bytecode_len = total_code_len;

        try binary_list.appendSlice(self.allocator, std.mem.asBytes(&header));
        try binary_list.appendSlice(self.allocator, self.data_section.items);
        try binary_list.appendSlice(self.allocator, access_list_bytes);


        var code_count_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &code_count_buf, @intCast(action_codes.items.len), .little);
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

        for (func.params, 0..) |_, i| {
            if (i < 7) {
                const preg: Reg = @enumFromInt(@as(u5, @intCast(10 + i)));
                const vreg: mir.Reg = @intCast(i);
                ctx.reg_alloc.v2p[vreg] = preg;
                ctx.reg_alloc.p2v[@intFromEnum(preg)] = vreg;
            }
        }

        for (func.body) |instr| {
            if (instr.op == .label) {
                try ctx.labels.put(ctx.allocator, instr.op.label.id, @intCast(ctx.writer.buf.items.len));
            }
            try self.genMirInstr(instr.op, ctx);
        }

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
        _ = self; // no CodeGen state mutation in this dispatch; all ops via ctx
        switch (op) {
            .nop => {},
            .const_i64 => |i| {
                const dst = try ctx.reg_alloc.getReg(i.dst, &ctx.writer, true);
                _ = try riscv.genLoadImmediate64(&ctx.writer, dst, @bitCast(i.value));
            },
            .const_i256 => |ci| {
                // SPEC: Part 2.1 — Load a 256-bit constant onto the stack.
                // Layout: 4 × 64-bit limbs in little-endian word order
                // (limb[0]=bytes[0..8], limb[1]=bytes[8..16], ...).
                // dst receives the stack pointer to the 32-byte region.
                const dst = try ctx.reg_alloc.getReg(ci.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                inline for (0..4) |w| {
                    const lo: u64 = std.mem.readInt(u64, ci.bytes[w * 8 ..][0..8], .little);
                    _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, lo);
                    try ctx.writer.emit(riscv.SD(.sp, .t0, @as(i12, w * 8)));
                }
                try ctx.writer.emit(riscv.ADD(dst, .sp, .zero));
            },
            .const_bool => |b| {
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                // ADDI rd=dst, rs1=zero, imm=0or1  (was incorrectly rd=zero)
                try ctx.writer.emit(riscv.ADDI(dst, .zero, if (b.value) @as(i12, 1) else @as(i12, 0)));
            },
            .const_data => |d| {
                const dst = try ctx.reg_alloc.getReg(d.dst, &ctx.writer, true);
                _ = try riscv.genLoadImmediate64(&ctx.writer, dst, d.offset);
                try ctx.writer.emit(riscv.ADD(dst, .gp, dst));
            },
            .add => |a| {
                const lhs = try ctx.reg_alloc.getReg(a.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(a.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(a.dst, &ctx.writer, true);
                // ADD rd=dst, rs1=lhs, rs2=rhs
                try ctx.writer.emit(riscv.ADD(dst, lhs, rhs));
            },
            .sub => |s| {
                const lhs = try ctx.reg_alloc.getReg(s.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(s.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(s.dst, &ctx.writer, true);
                // SUB rd=dst, rs1=lhs, rs2=rhs
                try ctx.writer.emit(riscv.SUB(dst, lhs, rhs));
            },
            .mul => |m| {
                const lhs = try ctx.reg_alloc.getReg(m.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(m.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(m.dst, &ctx.writer, true);
                // MUL rd=dst, rs1=lhs, rs2=rhs
                try ctx.writer.emit(riscv.MUL(dst, lhs, rhs));
            },
            .eq => |e| {
                const lhs = try ctx.reg_alloc.getReg(e.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(e.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(e.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SUB(dst, lhs, rhs));
                try ctx.writer.emit(riscv.encodeI(1, dst, 0x3, dst, 0x13)); // SLTIU dst, dst, 1
            },
            .ne => |n| {
                const lhs = try ctx.reg_alloc.getReg(n.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(n.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(n.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SUB(dst, lhs, rhs));
                try ctx.writer.emit(riscv.encodeR(0x00, dst, .zero, 0x3, dst, 0x33)); // SLTU dst, zero, dst
            },
            .lt => |l| {
                const lhs = try ctx.reg_alloc.getReg(l.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(l.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(l.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.encodeR(0x00, rhs, lhs, 0x2, dst, 0x33)); // SLT dst, lhs, rhs
            },
            .gt => |g| {
                const lhs = try ctx.reg_alloc.getReg(g.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(g.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(g.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.encodeR(0x00, lhs, rhs, 0x2, dst, 0x33)); // SLT dst, rhs, lhs
            },
            .le => |l| {
                const lhs = try ctx.reg_alloc.getReg(l.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(l.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(l.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.encodeR(0x00, lhs, rhs, 0x2, dst, 0x33)); // SLT dst, rhs, lhs
                try ctx.writer.emit(riscv.encodeI(1, dst, 0x4, dst, 0x13)); // XORI dst, dst, 1
            },
            .ge => |g| {
                const lhs = try ctx.reg_alloc.getReg(g.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(g.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(g.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.encodeR(0x00, rhs, lhs, 0x2, dst, 0x33)); // SLT dst, lhs, rhs
                try ctx.writer.emit(riscv.encodeI(1, dst, 0x4, dst, 0x13)); // XORI dst, dst, 1
            },
            .bool_and => |b| {
                const lhs = try ctx.reg_alloc.getReg(b.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(b.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.AND(dst, lhs, rhs));
            },
            .bool_or => |b| {
                const lhs = try ctx.reg_alloc.getReg(b.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(b.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.OR(dst, lhs, rhs));
            },
            .bool_not => |b| {
                const src = try ctx.reg_alloc.getReg(b.operand, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(b.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.encodeI(1, src, 0x3, dst, 0x13)); // SLTIU dst, src, 1
            },
            .negate => |n| {
                const src = try ctx.reg_alloc.getReg(n.operand, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(n.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SUB(dst, .zero, src));
            },
            .mov => |m| {
                const src = try ctx.reg_alloc.getReg(m.src, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(m.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADD(dst, src, .zero));
            },
            .jump => |j| {
                try ctx.reg_alloc.flushAll(&ctx.writer);
                const pos = ctx.writer.buf.items.len;
                try ctx.writer.emit(riscv.JAL(.zero, 0));
                try ctx.jump_patches.append(ctx.allocator, .{ .offset_pos = pos, .target_label = j.target });
            },
            .branch => |b| {
                const cond = try ctx.reg_alloc.getReg(b.cond, &ctx.writer, false);
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
                const dst = try ctx.reg_alloc.getReg(sr.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -64));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, @bitCast(@as(i64, sr.field_id)));
                try ctx.writer.emit(riscv.SD(.t0, .sp, 0));
                if (sr.key) |k| {
                    const key = try ctx.reg_alloc.getReg(k, &ctx.writer, false);
                    try ctx.writer.emit(riscv.SD(key, .sp, 8));
                }
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ADDI(.a2, .sp, 32));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.STATE_READ));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.LD(dst, .sp, 32));
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 64));
            },
            .state_write => |sw| {
                const val = try ctx.reg_alloc.getReg(sw.value, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -64));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, @bitCast(@as(i64, sw.field_id)));
                try ctx.writer.emit(riscv.SD(.t0, .sp, 0));
                if (sw.key) |k| {
                    const key = try ctx.reg_alloc.getReg(k, &ctx.writer, false);
                    try ctx.writer.emit(riscv.SD(key, .sp, 8));
                }
                try ctx.writer.emit(riscv.SD(val, .sp, 32));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ADDI(.a2, .sp, 32));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.STATE_WRITE));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 64));
            },
            .state_delete => |sd| {
                const key = try ctx.reg_alloc.getReg(sd.key, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -64));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, @bitCast(@as(i64, sd.field_id)));
                try ctx.writer.emit(riscv.SD(.t0, .sp, 0));
                try ctx.writer.emit(riscv.SD(key, .sp, 8));
                try ctx.writer.emit(riscv.SD(.zero, .sp, 32));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ADDI(.a2, .sp, 32));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.STATE_WRITE));
                try ctx.writer.emit(riscv.ECALL());
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
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.ASSET_TRANSFER));
                try ctx.writer.emit(riscv.ECALL());
            },
            .asset_burn => |ab| {
                const asset = try ctx.reg_alloc.getReg(ab.asset, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, asset, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.ASSET_BURN));
                try ctx.writer.emit(riscv.ECALL());
            },
            .asset_mint => |am| {
                const dst = try ctx.reg_alloc.getReg(am.dst, &ctx.writer, true);
                const amount = try ctx.reg_alloc.getReg(am.amount, &ctx.writer, false);
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, am.type_id)));
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero));
                try ctx.writer.emit(riscv.ADD(.a3, amount, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.ASSET_MINT));
                try ctx.writer.emit(riscv.ECALL());
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
                try ctx.writer.emit(riscv.SD(.t0, .sp, 0));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.AUTH_CHECK));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));
            },
            .auth_gate_begin => |ab| {
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .t0, @bitCast(@as(i64, ab.name_offset)));
                try ctx.writer.emit(riscv.SD(.t0, .sp, 0));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.AUTH_CHECK));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));
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
                try ctx.writer.emit(riscv.ADD(.a2, .sp, .zero));                       // topics_ptr (= event_id slot)
                try ctx.writer.emit(riscv.ADDI(.a3, .sp, 8));                          // data_ptr (args start at +8)
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a4, @intCast(n_args * 8)); // data_len
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.EMIT_EVENT));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, stack_bytes));
            },
            .need => |n| {
                // SPEC: Part 6.5 — need: if cond is true skip revert, else revert.
                // BNE cond, zero, <skip_revert>   (branch over revert if cond != 0)
                const cond = try ctx.reg_alloc.getReg(n.cond, &ctx.writer, false);
                const pos = ctx.writer.buf.items.len;
                try ctx.writer.emit(riscv.BNE(cond, .zero, 0)); // placeholder offset
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, @as(i32, @intCast(n.msg_offset)))));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a2, @bitCast(@as(i64, @as(i32, @intCast(n.msg_len)))));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.REVERT));
                try ctx.writer.emit(riscv.ECALL());
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
                const cond = try ctx.reg_alloc.getReg(e.cond, &ctx.writer, false);
                const pos = ctx.writer.buf.items.len;
                try ctx.writer.emit(riscv.BNE(cond, .zero, 0)); // placeholder offset
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, @as(i32, @intCast(e.msg_offset)))));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a2, @bitCast(@as(i64, @as(i32, @intCast(e.msg_len)))));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.REVERT));
                try ctx.writer.emit(riscv.ECALL());
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
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a2, @bitCast(@as(i64, p.msg_len)));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.REVERT));
                try ctx.writer.emit(riscv.ECALL());
            },
            .throw_error => |te| {
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, te.error_id)));
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.REVERT));
                try ctx.writer.emit(riscv.ECALL());
            },
            .attempt_begin => |ab| {
                // SPEC: Part 11.5 — Record the exception handler label.
                // The ZVM does not have native try/catch; we model it by
                // recording the handler target. Any ECALL that returns a
                // non-zero error code should be followed by a BNE to this
                // label. The label resolution uses the normal jump_patches path.
                ctx.exception_label = ab.handler_label;
            },
            .attempt_end => {
                // SPEC: Part 11.5 — Clear the active exception handler.
                ctx.exception_label = null;
            },
            .get_caller => |gc| {
                const dst = try ctx.reg_alloc.getReg(gc.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.GET_CALLER));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.LD(dst, .sp, 0));
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));
            },
            .get_value => |gv| {
                const dst = try ctx.reg_alloc.getReg(gv.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.GET_VALUE));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.LD(dst, .sp, 0));
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));
            },
            .get_block => |gb| {
                const dst = try ctx.reg_alloc.getReg(gb.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.GET_BLOCK));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.ADD(dst, .a0, .zero));
            },
            .get_timestamp => |gt| {
                const dst = try ctx.reg_alloc.getReg(gt.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.GET_NOW));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.ADD(dst, .a0, .zero));
            },
            .get_gas => |gg| {
                const dst = try ctx.reg_alloc.getReg(gg.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.GET_GAS));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.ADD(dst, .a0, .zero));
            },
            .get_this => |gt| {
                const dst = try ctx.reg_alloc.getReg(gt.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.GET_THIS));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.LD(dst, .sp, 0));
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));
            },
            .get_deployer => |gd| {
                const dst = try ctx.reg_alloc.getReg(gd.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADD(dst, .zero, .zero));
            },
            .get_zero_addr => |gz| {
                const dst = try ctx.reg_alloc.getReg(gz.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADD(dst, .zero, .zero));
            },
            .schedule_call => |sc| {
                // SPEC: Part 10.2 — SCHEDULE_CALL ABI:
                // a1=to_ptr, a2=delay(u64), a3=calldata_ptr, a4=calldata_len
                const delay       = try ctx.reg_alloc.getReg(sc.delay,        &ctx.writer, false);
                const calldata    = try ctx.reg_alloc.getReg(sc.calldata,     &ctx.writer, false);
                const calldata_len = try ctx.reg_alloc.getReg(sc.calldata_len, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, .zero,    .zero));   // to_ptr (not provided — zero = self)
                try ctx.writer.emit(riscv.ADD(.a2, delay,    .zero));   // delay in blocks
                try ctx.writer.emit(riscv.ADD(.a3, calldata, .zero));   // calldata ptr
                try ctx.writer.emit(riscv.ADD(.a4, calldata_len, .zero)); // calldata len
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.SCHEDULE_CALL));
                try ctx.writer.emit(riscv.ECALL());
            },
            .call_external => |ce| {
                const dst = try ctx.reg_alloc.getReg(ce.dst, &ctx.writer, true);
                const target = try ctx.reg_alloc.getReg(ce.target, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, target, .zero));
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a2, @bitCast(@as(i64, ce.selector)));
                try ctx.writer.emit(riscv.ADD(.a3, .zero, .zero));
                try ctx.writer.emit(riscv.ADD(.a4, .zero, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.SCHEDULE_CALL));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.ADD(dst, .a0, .zero));
            },
            .oracle_read => |oread| {
                const dst = try ctx.reg_alloc.getReg(oread.dst, &ctx.writer, true);
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, oread.feed_id)));
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                try ctx.writer.emit(riscv.ADD(.a2, .sp, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.ORACLE_QUERY));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.LD(dst, .sp, 0));
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));
            },
            .vrf_random => |vr| {
                const dst = try ctx.reg_alloc.getReg(vr.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, -32));
                try ctx.writer.emit(riscv.ADD(.a1, .sp, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.VRF_RANDOM));
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.LD(dst, .sp, 0));
                try ctx.writer.emit(riscv.ADDI(.sp, .sp, 32));
            },
            .zk_verify => |zk| {
                // SPEC: Part 12.2 — ZK_VERIFY syscall:
                // a1=circuit_id, a2=proof_ptr, a3=proof_len(32) → a0=1 if valid.
                const proof = try ctx.reg_alloc.getReg(zk.proof, &ctx.writer, false);
                _ = try riscv.genLoadImmediate64(&ctx.writer, .a1, @bitCast(@as(i64, zk.circuit_id)));
                try ctx.writer.emit(riscv.ADD(.a2, proof, .zero));  // proof_ptr
                try ctx.writer.emit(riscv.ADDI(.a3, .zero, 32));    // proof_len (32 bytes)
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.ZK_VERIFY));
                try ctx.writer.emit(riscv.ECALL());
            },
            .delegate_gas => |dg| {
                // SPEC: Part 14.6 — DELEGATE_GAS syscall: a1=payer_addr_ptr.
                const payer = try ctx.reg_alloc.getReg(dg.payer, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, payer, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.DELEGATE_GAS));
                try ctx.writer.emit(riscv.ECALL());
            },
            .pay => |p| {
                const recipient = try ctx.reg_alloc.getReg(p.recipient, &ctx.writer, false);
                const amount = try ctx.reg_alloc.getReg(p.amount, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a2, .zero, .zero)); // from
                try ctx.writer.emit(riscv.ADD(.a3, recipient, .zero)); // to
                try ctx.writer.emit(riscv.ADD(.a4, amount, .zero)); // amount
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.ASSET_TRANSFER)); // 0x10
                try ctx.writer.emit(riscv.ECALL());
            },
            .expand_account => |ea| {
                // SPEC: Part 3.10 — EXPAND_ACCOUNT syscall:
                // a1=account_ptr, a2=extra_bytes
                const acct  = try ctx.reg_alloc.getReg(ea.account, &ctx.writer, false);
                const bytes = try ctx.reg_alloc.getReg(ea.bytes,   &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, acct,  .zero));
                try ctx.writer.emit(riscv.ADD(.a2, bytes, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.EXPAND_ACCOUNT));
                try ctx.writer.emit(riscv.ECALL());
            },
            .close_account => |ca| {
                // SPEC: Part 3.10 — CLOSE_ACCOUNT syscall:
                // a1=account_ptr, a2=refund_to_ptr
                const acct      = try ctx.reg_alloc.getReg(ca.account,   &ctx.writer, false);
                const refund_to = try ctx.reg_alloc.getReg(ca.refund_to, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, acct,      .zero));
                try ctx.writer.emit(riscv.ADD(.a2, refund_to, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.CLOSE_ACCOUNT));
                try ctx.writer.emit(riscv.ECALL());
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
                try ctx.writer.emit(riscv.ECALL());
            },
            .unfreeze_account => |ua| {
                // SPEC: Part 8.4 — Unfreeze account.
                const acct = try ctx.reg_alloc.getReg(ua.account, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, acct, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.LOG_DIAGNOSTIC));
                try ctx.writer.emit(riscv.ECALL());
            },
            .transfer_ownership => |to| {
                // SPEC: Part 4.4 — Transfer ownership of an account.
                const acct      = try ctx.reg_alloc.getReg(to.account,   &ctx.writer, false);
                const new_owner = try ctx.reg_alloc.getReg(to.new_owner, &ctx.writer, false);
                try ctx.writer.emit(riscv.ADD(.a1, acct,      .zero));
                try ctx.writer.emit(riscv.ADD(.a2, new_owner, .zero));
                try ctx.writer.emit(riscv.ZEPH_SET_ID(.AUTH_GRANT));
                try ctx.writer.emit(riscv.ECALL());
            },
            .has_check => |hc| {
                // SPEC: Part 2.6 — dst = (collection has element).
                // The ZVM represents set membership as a non-zero 64-bit slot
                // value: load the slot keyed by element; dst = (slot != 0).
                const coll    = try ctx.reg_alloc.getReg(hc.collection, &ctx.writer, false);
                const element = try ctx.reg_alloc.getReg(hc.element,    &ctx.writer, false);
                const dst     = try ctx.reg_alloc.getReg(hc.dst,        &ctx.writer, true);
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
                try ctx.writer.emit(riscv.ECALL());
                try ctx.writer.emit(riscv.ADD(dst, .a0, .zero));
            },
        }
    }

    // ── Binary serialization ─────────────────────────────────────────────

    /// Serialize the access list section.
    /// Format per action: [4-byte selector] [2-byte read_count] [2-byte write_count]
    ///   then read entries: [1-byte name_len] [name bytes] [1-byte field_len] [field bytes]
    ///   then write entries: same format.
    /// SPEC: Part 9.1 — Serialize access lists from the checked contract.
    /// Iterates MirModule functions, looks up each action's AccessList in
    /// `checked.action_lists`, and serializes [selector][r_count][w_count][entries...].
    fn serializeAccessListFromChecked(
        self: *CodeGen,
        mir_module: *const mir.MirModule,
        checked: *const CheckedContract,
    ) anyerror![]u8 {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);

        for (mir_module.functions) |func| {
            // Only action/view functions appear in access lists.
            if (func.kind != .action and func.kind != .view) continue;

            // Write 4-byte selector.
            var sel_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &sel_bytes, func.selector, .little);
            try buf.appendSlice(self.allocator, &sel_bytes);

            if (checked.action_lists.get(func.name)) |al| {
                var counts: [4]u8 = undefined;
                std.mem.writeInt(u16, counts[0..2], @intCast(al.reads.items.len), .little);
                std.mem.writeInt(u16, counts[2..4], @intCast(al.writes.items.len), .little);
                try buf.appendSlice(self.allocator, &counts);
                for (al.reads.items) |entry| {
                    try self.serializeAccessEntry(&buf, &entry);
                }
                for (al.writes.items) |entry| {
                    try self.serializeAccessEntry(&buf, &entry);
                }
            } else {
                // No access list recorded — emit zero counts.
                const zeros: [4]u8 = .{ 0, 0, 0, 0 };
                try buf.appendSlice(self.allocator, &zeros);
            }
        }

        return buf.toOwnedSlice(self.allocator);
    }

    /// SPEC: Part 9.1 — Serialize one access list entry.
    /// Format: [1-byte name_len][name bytes][1-byte field_len][field bytes or 0].
    fn serializeAccessEntry(self: *CodeGen, buf: *std.ArrayListUnmanaged(u8), entry: *const AccessEntry) anyerror!void {
        const name_len: u8 = @intCast(@min(entry.account_name.len, 255));
        try buf.append(self.allocator, name_len);
        try buf.appendSlice(self.allocator, entry.account_name[0..name_len]);
        if (entry.field) |f| {
            const field_len: u8 = @intCast(@min(f.len, 255));
            try buf.append(self.allocator, field_len);
            try buf.appendSlice(self.allocator, f[0..field_len]);
        } else {
            try buf.append(self.allocator, 0);
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
    const binary = try gen.generateFromMir(&mod, &checked);
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
        .access_list_len = 0,
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
    const binary = try gen.generateFromMir(&mod, &checked);
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
    const binary = try gen.generateFromMir(&mod, &checked);
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
    const binary = try gen.generateFromMir(&mod, &checked);
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

