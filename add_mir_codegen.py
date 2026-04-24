import re

with open("src/codegen.zig", "r") as f:
    content = f.read()

# 1. Add import
if 'const mir = @import("mir.zig");' not in content:
    content = content.replace(
        'const riscv = @import("riscv.zig");\nconst u256_mod = @import("u256.zig");\n',
        'const riscv = @import("riscv.zig");\nconst u256_mod = @import("u256.zig");\nconst mir = @import("mir.zig");\n'
    )

# 2. Add MIR codegen functions before tests
test_marker = 'test "ZephBinHeader is still exactly 64 bytes after adding data_section_len" {'
test_idx = content.find(test_marker)
if test_idx == -1:
    print("Could not find test marker")
    exit(1)

mir_code = """
// ============================================================================
// Section 7 — MIR Code Generation (Phase 2)
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
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, max_regs: u32) !MirActionCtx {
        return .{
            .writer = BytecodeWriter.init(allocator),
            .reg_alloc = try MirRegAlloc.init(allocator, max_regs),
            .labels = .{},
            .branch_patches = .{},
            .jump_patches = .{},
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

impl CodeGen {
    pub fn generateFromMir(
        self: *CodeGen,
        mir_module: *const mir.MirModule,
        contract: *const ContractDef,
        checked: *const CheckedContract,
    ) anyerror![]u8 {
        for (contract.state) |sf| {
            _ = self.getOrAssignFieldId(sf.name);
        }

        var flags: u16 = 0;
        if (contract.upgrade != null) flags |= 0x01;
        for (contract.actions) |action| {
            for (action.annotations) |ann| {
                if (ann.kind == .parallel) {
                    flags |= 0x02;
                    break;
                }
            }
        }

        const ActionBytecode = struct { selector: u32, code: []const u8 };
        var action_codes = std.ArrayListUnmanaged(ActionBytecode){};
        defer {
            for (action_codes.items) |ab| self.allocator.free(ab.code);
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

        const access_list_bytes = try self.serializeAccessList(contract, checked);
        defer self.allocator.free(access_list_bytes);

        const bytecode_bytes = try self.serializeBytecodeSection(action_codes.items);
        defer self.allocator.free(bytecode_bytes);

        const data_bytes = mir_module.data_section;
        var header = ZephBinHeader{};
        header.contract_name = writeContractName(mir_module.name);
        header.action_count = @intCast(action_codes.items.len);
        header.flags = flags;
        header.access_list_len = @intCast(access_list_bytes.len);
        header.bytecode_len = @intCast(bytecode_bytes.len);
        header.data_section_len = @intCast(data_bytes.len);

        const conservation_bytes = try self.serializeConservationMetadata(contract);
        defer self.allocator.free(conservation_bytes);
        header.conservation_len = @intCast(conservation_bytes.len);

        const total_size = @sizeOf(ZephBinHeader) + access_list_bytes.len + bytecode_bytes.len + data_bytes.len + conservation_bytes.len;
        const binary = try self.allocator.alloc(u8, total_size);
        errdefer self.allocator.free(binary);

        const header_bytes: *const [@sizeOf(ZephBinHeader)]u8 = @ptrCast(&header);
        @memcpy(binary[0..@sizeOf(ZephBinHeader)], header_bytes);

        const al_start = @sizeOf(ZephBinHeader);
        @memcpy(binary[al_start..][0..access_list_bytes.len], access_list_bytes);

        const bc_start = al_start + access_list_bytes.len;
        @memcpy(binary[bc_start..][0..bytecode_bytes.len], bytecode_bytes);

        const ds_start = bc_start + bytecode_bytes.len;
        if (data_bytes.len > 0) @memcpy(binary[ds_start..][0..data_bytes.len], data_bytes);

        const cm_start = ds_start + data_bytes.len;
        if (conservation_bytes.len > 0) @memcpy(binary[cm_start..][0..conservation_bytes.len], conservation_bytes);

        const checksum_offset = @offsetOf(ZephBinHeader, "checksum") + @sizeOf(u32);
        const checksum = crc32(binary[checksum_offset..]);
        std.mem.writeInt(u32, binary[@offsetOf(ZephBinHeader, "checksum")..][0..4], checksum, .little);

        return binary;
    }

    fn genMirFunction(self: *CodeGen, func: *const mir.MirFunction, ctx: *MirActionCtx) anyerror!void {
        _ = self;
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
            if (instr.label) |lbl| {
                try ctx.labels.put(ctx.allocator, lbl, @intCast(ctx.writer.bytes.items.len));
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
        _ = self;
        for (ctx.branch_patches.items) |bp| {
            const target_pos = ctx.labels.get(bp.target_label) orelse return error.InternalError;
            const diff: i32 = @as(i32, @intCast(target_pos)) - @as(i32, @intCast(bp.offset_pos));
            const old_instr = std.mem.readInt(u32, ctx.writer.bytes.items[bp.offset_pos..][0..4], .little);
            const patched = riscv.encodeBranchOffset(old_instr, diff);
            std.mem.writeInt(u32, ctx.writer.bytes.items[bp.offset_pos..][0..4], patched, .little);
        }
        for (ctx.jump_patches.items) |jp| {
            const target_pos = ctx.labels.get(jp.target_label) orelse return error.InternalError;
            const diff: i32 = @as(i32, @intCast(target_pos)) - @as(i32, @intCast(jp.offset_pos));
            const old_instr = std.mem.readInt(u32, ctx.writer.bytes.items[jp.offset_pos..][0..4], .little);
            const patched = riscv.encodeJalOffset(old_instr, diff);
            std.mem.writeInt(u32, ctx.writer.bytes.items[jp.offset_pos..][0..4], patched, .little);
        }
    }

    fn genMirInstr(self: *CodeGen, op: mir.MirOp, ctx: *MirActionCtx) anyerror!void {
        _ = self;
        switch (op) {
            .nop => {},
            .imm => |i| {
                const dst = try ctx.reg_alloc.getReg(i.dst, &ctx.writer, true);
                if (i.val == 0) {
                    try ctx.writer.emit(riscv.ADDI(.zero, dst, 0));
                } else {
                    try ctx.writer.emit(riscv.ADDI(.zero, dst, @intCast(i.val & 0x7FF)));
                }
            },
            .add => |a| {
                const lhs = try ctx.reg_alloc.getReg(a.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(a.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(a.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADD(lhs, rhs, dst));
            },
            .sub => |s| {
                const lhs = try ctx.reg_alloc.getReg(s.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(s.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(s.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SUB(lhs, rhs, dst));
            },
            .mul => |m| {
                const lhs = try ctx.reg_alloc.getReg(m.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(m.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(m.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.MUL(lhs, rhs, dst));
            },
            .eq => |e| {
                const lhs = try ctx.reg_alloc.getReg(e.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(e.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(e.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SUB(lhs, rhs, dst));
                try ctx.writer.emit(riscv.SLTIU(dst, dst, 1));
            },
            .lt => |l| {
                const lhs = try ctx.reg_alloc.getReg(l.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(l.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(l.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SLT(lhs, rhs, dst));
            },
            .jump => |j| {
                try ctx.reg_alloc.flushAll(&ctx.writer);
                const pos = ctx.writer.bytes.items.len;
                try ctx.writer.emit(riscv.JAL(.zero, 0));
                try ctx.jump_patches.append(ctx.allocator, .{ .offset_pos = pos, .target_label = j.target });
            },
            .branch => |b| {
                const cond = try ctx.reg_alloc.getReg(b.cond, &ctx.writer, false);
                try ctx.reg_alloc.flushAll(&ctx.writer);
                
                const pos_true = ctx.writer.bytes.items.len;
                try ctx.writer.emit(riscv.BNE(cond, .zero, 0));
                try ctx.branch_patches.append(ctx.allocator, .{ .offset_pos = pos_true, .target_label = b.true_target });

                const pos_false = ctx.writer.bytes.items.len;
                try ctx.writer.emit(riscv.JAL(.zero, 0));
                try ctx.jump_patches.append(ctx.allocator, .{ .offset_pos = pos_false, .target_label = b.false_target });
            },
            .ret => |r| {
                if (r.val) |val| {
                    const src = try ctx.reg_alloc.getReg(val, &ctx.writer, false);
                    try ctx.writer.emit(riscv.ADDI(src, .a0, 0));
                }
            },
            .state_read => |sr| {
                const dst = try ctx.reg_alloc.getReg(sr.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.CUSTOM0(0, dst, 1));
            },
            .state_write => |sw| {
                const src = try ctx.reg_alloc.getReg(sw.val, &ctx.writer, false);
                try ctx.writer.emit(riscv.CUSTOM0(src, .zero, 2));
            },
            else => {}
        }
    }
}
"""

# There is no `impl CodeGen {` in zig, we should just insert these functions into `CodeGen` struct or standalone.
# But `generateFromMir` needs to be in `CodeGen`.
# Since `CodeGen` is a struct, we should insert it BEFORE `    // ── Binary serialization ─────────────────────────────────────────────`
# Let's find the struct end or insert before `// ── Binary serialization ─────────────────────────────────────────────`

# Wait, we need to declare `MirRegAlloc`, `BranchPatch`, `JumpPatch`, `MirActionCtx` outside `CodeGen`, 
# and `generateFromMir`, `genMirFunction`, `applyPatches`, `genMirInstr` INSIDE `CodeGen`.

struct_part = """
    pub fn generateFromMir(
        self: *CodeGen,
        mir_module: *const mir.MirModule,
        contract: *const ContractDef,
        checked: *const CheckedContract,
    ) anyerror![]u8 {
        for (contract.state) |sf| {
            _ = self.getOrAssignFieldId(sf.name);
        }

        var flags: u16 = 0;
        if (contract.upgrade != null) flags |= 0x01;
        for (contract.actions) |action| {
            for (action.annotations) |ann| {
                if (ann.kind == .parallel) {
                    flags |= 0x02;
                    break;
                }
            }
        }

        const ActionBytecode = struct { selector: u32, code: []const u8 };
        var action_codes = std.ArrayListUnmanaged(ActionBytecode){};
        defer {
            for (action_codes.items) |ab| self.allocator.free(ab.code);
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

        const access_list_bytes = try self.serializeAccessList(contract, checked);
        defer self.allocator.free(access_list_bytes);

        const bytecode_bytes = try self.serializeBytecodeSection(action_codes.items);
        defer self.allocator.free(bytecode_bytes);

        const data_bytes = mir_module.data_section;
        var header = ZephBinHeader{};
        header.contract_name = writeContractName(mir_module.name);
        header.action_count = @intCast(action_codes.items.len);
        header.flags = flags;
        header.access_list_len = @intCast(access_list_bytes.len);
        header.bytecode_len = @intCast(bytecode_bytes.len);
        header.data_section_len = @intCast(data_bytes.len);

        const conservation_bytes = try self.serializeConservationMetadata(contract);
        defer self.allocator.free(conservation_bytes);
        header.conservation_len = @intCast(conservation_bytes.len);

        const total_size = @sizeOf(ZephBinHeader) + access_list_bytes.len + bytecode_bytes.len + data_bytes.len + conservation_bytes.len;
        const binary = try self.allocator.alloc(u8, total_size);
        errdefer self.allocator.free(binary);

        const header_bytes: *const [@sizeOf(ZephBinHeader)]u8 = @ptrCast(&header);
        @memcpy(binary[0..@sizeOf(ZephBinHeader)], header_bytes);

        const al_start = @sizeOf(ZephBinHeader);
        @memcpy(binary[al_start..][0..access_list_bytes.len], access_list_bytes);

        const bc_start = al_start + access_list_bytes.len;
        @memcpy(binary[bc_start..][0..bytecode_bytes.len], bytecode_bytes);

        const ds_start = bc_start + bytecode_bytes.len;
        if (data_bytes.len > 0) @memcpy(binary[ds_start..][0..data_bytes.len], data_bytes);

        const cm_start = ds_start + data_bytes.len;
        if (conservation_bytes.len > 0) @memcpy(binary[cm_start..][0..conservation_bytes.len], conservation_bytes);

        const checksum_offset = @offsetOf(ZephBinHeader, "checksum") + @sizeOf(u32);
        const checksum = crc32(binary[checksum_offset..]);
        std.mem.writeInt(u32, binary[@offsetOf(ZephBinHeader, "checksum")..][0..4], checksum, .little);

        return binary;
    }

    fn genMirFunction(self: *CodeGen, func: *const mir.MirFunction, ctx: *MirActionCtx) anyerror!void {
        _ = self;
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
            if (instr.label) |lbl| {
                try ctx.labels.put(ctx.allocator, lbl, @intCast(ctx.writer.bytes.items.len));
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
        _ = self;
        for (ctx.branch_patches.items) |bp| {
            const target_pos = ctx.labels.get(bp.target_label) orelse return error.InternalError;
            const diff: i32 = @as(i32, @intCast(target_pos)) - @as(i32, @intCast(bp.offset_pos));
            const old_instr = std.mem.readInt(u32, ctx.writer.bytes.items[bp.offset_pos..][0..4], .little);
            const patched = riscv.encodeBranchOffset(old_instr, diff);
            std.mem.writeInt(u32, ctx.writer.bytes.items[bp.offset_pos..][0..4], patched, .little);
        }
        for (ctx.jump_patches.items) |jp| {
            const target_pos = ctx.labels.get(jp.target_label) orelse return error.InternalError;
            const diff: i32 = @as(i32, @intCast(target_pos)) - @as(i32, @intCast(jp.offset_pos));
            const old_instr = std.mem.readInt(u32, ctx.writer.bytes.items[jp.offset_pos..][0..4], .little);
            const patched = riscv.encodeJalOffset(old_instr, diff);
            std.mem.writeInt(u32, ctx.writer.bytes.items[jp.offset_pos..][0..4], patched, .little);
        }
    }

    fn genMirInstr(self: *CodeGen, op: mir.MirOp, ctx: *MirActionCtx) anyerror!void {
        _ = self;
        switch (op) {
            .nop => {},
            .imm => |i| {
                const dst = try ctx.reg_alloc.getReg(i.dst, &ctx.writer, true);
                if (i.val == 0) {
                    try ctx.writer.emit(riscv.ADDI(.zero, dst, 0));
                } else {
                    try ctx.writer.emit(riscv.ADDI(.zero, dst, @intCast(i.val & 0x7FF)));
                }
            },
            .add => |a| {
                const lhs = try ctx.reg_alloc.getReg(a.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(a.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(a.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.ADD(lhs, rhs, dst));
            },
            .sub => |s| {
                const lhs = try ctx.reg_alloc.getReg(s.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(s.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(s.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SUB(lhs, rhs, dst));
            },
            .mul => |m| {
                const lhs = try ctx.reg_alloc.getReg(m.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(m.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(m.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.MUL(lhs, rhs, dst));
            },
            .eq => |e| {
                const lhs = try ctx.reg_alloc.getReg(e.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(e.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(e.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SUB(lhs, rhs, dst));
                try ctx.writer.emit(riscv.SLTIU(dst, dst, 1));
            },
            .lt => |l| {
                const lhs = try ctx.reg_alloc.getReg(l.lhs, &ctx.writer, false);
                const rhs = try ctx.reg_alloc.getReg(l.rhs, &ctx.writer, false);
                const dst = try ctx.reg_alloc.getReg(l.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.SLT(lhs, rhs, dst));
            },
            .jump => |j| {
                try ctx.reg_alloc.flushAll(&ctx.writer);
                const pos = ctx.writer.bytes.items.len;
                try ctx.writer.emit(riscv.JAL(.zero, 0));
                try ctx.jump_patches.append(ctx.allocator, .{ .offset_pos = pos, .target_label = j.target });
            },
            .branch => |b| {
                const cond = try ctx.reg_alloc.getReg(b.cond, &ctx.writer, false);
                try ctx.reg_alloc.flushAll(&ctx.writer);
                
                const pos_true = ctx.writer.bytes.items.len;
                try ctx.writer.emit(riscv.BNE(cond, .zero, 0));
                try ctx.branch_patches.append(ctx.allocator, .{ .offset_pos = pos_true, .target_label = b.true_target });

                const pos_false = ctx.writer.bytes.items.len;
                try ctx.writer.emit(riscv.JAL(.zero, 0));
                try ctx.jump_patches.append(ctx.allocator, .{ .offset_pos = pos_false, .target_label = b.false_target });
            },
            .ret => |r| {
                if (r.val) |val| {
                    const src = try ctx.reg_alloc.getReg(val, &ctx.writer, false);
                    try ctx.writer.emit(riscv.ADDI(src, .a0, 0));
                }
            },
            .state_read => |sr| {
                const dst = try ctx.reg_alloc.getReg(sr.dst, &ctx.writer, true);
                try ctx.writer.emit(riscv.CUSTOM0(0, dst, 1));
            },
            .state_write => |sw| {
                const src = try ctx.reg_alloc.getReg(sw.val, &ctx.writer, false);
                try ctx.writer.emit(riscv.CUSTOM0(src, .zero, 2));
            },
            else => {}
        }
    }

"""

# Find end of CodeGen struct before tests
insert_idx = content.rfind("    // ── Binary serialization ─────────────────────────────────────────────")

struct_content = content[:insert_idx] + struct_part + content[insert_idx:]

new_content = struct_content[:test_idx] + mir_code[:mir_code.find("impl CodeGen {")] + struct_content[test_idx:]

with open("src/codegen.zig", "w") as f:
    f.write(new_content)

print("Successfully added MIR generators to codegen.zig")
