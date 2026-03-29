/// RISC-V 64-bit instruction encoder for the Zephyria VM.
/// Produces raw 4-byte (u32) encoded instructions and defines custom
/// Zephyria opcodes using RISC-V's reserved custom opcode space.
/// Pure encoding — no allocation, no IO (except BytecodeWriter).
const std = @import("std");

/// Zephyria ABI register mapping for RISC-V.
pub const Reg = enum(u5) {
    /// Hardwired zero register.
    zero = 0,
    /// Return address.
    ra = 1,
    /// Stack pointer.
    sp = 2,
    /// Global pointer — points to mine.* base.
    gp = 3,
    /// Thread pointer — points to params base.
    tp = 4,
    /// Temp: scratch register 0.
    t0 = 5,
    /// Temp: scratch register 1.
    t1 = 6,
    /// Temp: current caller address.
    t2 = 7,
    /// Saved: frame pointer.
    s0 = 8,
    /// Saved: contract state pointer.
    s1 = 9,
    /// Argument / return value 0.
    a0 = 10,
    /// Argument / return value 1.
    a1 = 11,
    /// Argument / return value 2.
    a2 = 12,
    /// Argument / return value 3.
    a3 = 13,
    /// Argument / return value 4.
    a4 = 14,
    /// Argument / return value 5.
    a5 = 15,
    /// Argument / return value 6.
    a6 = 16,
    /// Syscall / custom-op number.
    a7 = 17,
    /// Saved: access list pointer.
    s2 = 18,
    /// Saved: diagnostics.
    s3 = 19,
    /// Saved: event buffer.
    s4 = 20,
    /// Saved: authority store.
    s5 = 21,
    /// Saved: asset tracker.
    s6 = 22,
    /// Saved: linear tracker.
    s7 = 23,
    /// Saved register 8.
    s8 = 24,
    /// Saved register 9.
    s9 = 25,
    /// Saved register 10.
    s10 = 26,
    /// Saved register 11.
    s11 = 27,
    /// Temp register 3.
    t3 = 28,
    /// Temp register 4.
    t4 = 29,
    /// Temp register 5.
    t5 = 30,
    /// Temp register 6.
    t6 = 31,

    /// Return the raw 5-bit integer value of this register.
    pub inline fn int(self: Reg) u5 {
        return @intFromEnum(self);
    }
};

// ─── Standard RISC-V instruction format opcodes ───────────────────────
const OP_REG: u7 = 0x33; // R-type arithmetic
const OP_IMM: u7 = 0x13; // I-type arithmetic immediate
const OP_LOAD: u7 = 0x03; // I-type load
const OP_STORE: u7 = 0x23; // S-type store
const OP_BRANCH: u7 = 0x63; // B-type branch
const OP_LUI: u7 = 0x37; // U-type load upper immediate
const OP_AUIPC: u7 = 0x17; // U-type add upper imm to PC
const OP_JAL: u7 = 0x6F; // J-type jump and link
const OP_JALR: u7 = 0x67; // I-type jump and link register
const OP_SYSTEM: u7 = 0x73; // system instructions (ecall)

// ─── R-type funct7 values ─────────────────────────────────────────────
const F7_ADD: u7 = 0x00;
const F7_SUB: u7 = 0x20;
const F7_MULDIV: u7 = 0x01;

// ─── R-type funct3 values ─────────────────────────────────────────────
const F3_ADD_SUB: u3 = 0x0;
const F3_SLL: u3 = 0x1;
const F3_XOR: u3 = 0x4;
const F3_SRL_SRA: u3 = 0x5;
const F3_OR: u3 = 0x6;
const F3_AND: u3 = 0x7;
const F3_MUL: u3 = 0x0;
const F3_DIV: u3 = 0x4;
const F3_REM: u3 = 0x6;

// ─── Load/Store funct3 widths ─────────────────────────────────────────
const F3_LB: u3 = 0x0;
const F3_LH: u3 = 0x1;
const F3_LW: u3 = 0x2;
const F3_LD: u3 = 0x3;
const F3_SB: u3 = 0x0;
const F3_SH: u3 = 0x1;
const F3_SW: u3 = 0x2;
const F3_SD: u3 = 0x3;

// ─── Branch funct3 values ─────────────────────────────────────────────
const F3_BEQ: u3 = 0x0;
const F3_BNE: u3 = 0x1;
const F3_BLT: u3 = 0x4;
const F3_BGE: u3 = 0x5;

// ─── I-type immediate funct3 ──────────────────────────────────────────
const F3_ADDI: u3 = 0x0;
const F3_ORI: u3 = 0x6;
const F3_ANDI: u3 = 0x7;
const F3_XORI: u3 = 0x4;
const F3_SLLI: u3 = 0x1;
const F3_SRLI_SRAI: u3 = 0x5;

// ─── Custom opcode space ──────────────────────────────────────────────
const CUSTOM_0: u7 = 0x0B;
const CUSTOM_1: u7 = 0x2B;
const CUSTOM_2: u7 = 0x5B;
const CUSTOM_3: u7 = 0x7B;

// ═══════════════════════════════════════════════════════════════════════
// Standard RISC-V instruction format encoders
// ═══════════════════════════════════════════════════════════════════════

/// Encode an R-type instruction.
/// Layout: [funct7 | rs2 | rs1 | funct3 | rd | opcode]
pub inline fn encodeR(funct7: u7, rs2: Reg, rs1: Reg, funct3: u3, rd: Reg, opcode: u7) u32 {
    return @as(u32, @intCast(funct7)) << 25 |
        @as(u32, rs2.int()) << 20 |
        @as(u32, rs1.int()) << 15 |
        @as(u32, @intCast(funct3)) << 12 |
        @as(u32, rd.int()) << 7 |
        @as(u32, @intCast(opcode));
}

/// Encode an I-type instruction.
/// Layout: [imm[11:0] | rs1 | funct3 | rd | opcode]
pub inline fn encodeI(imm12: i12, rs1: Reg, funct3: u3, rd: Reg, opcode: u7) u32 {
    const imm_bits: u32 = @as(u32, @bitCast(@as(i32, imm12))) & 0xFFF;
    return imm_bits << 20 |
        @as(u32, rs1.int()) << 15 |
        @as(u32, @intCast(funct3)) << 12 |
        @as(u32, rd.int()) << 7 |
        @as(u32, @intCast(opcode));
}

/// Encode an S-type instruction.
/// Layout: [imm[11:5] | rs2 | rs1 | funct3 | imm[4:0] | opcode]
pub inline fn encodeS(imm12: i12, rs2: Reg, rs1: Reg, funct3: u3, opcode: u7) u32 {
    const imm_bits: u32 = @as(u32, @bitCast(@as(i32, imm12))) & 0xFFF;
    const imm_hi: u32 = (imm_bits >> 5) & 0x7F;
    const imm_lo: u32 = imm_bits & 0x1F;
    return imm_hi << 25 |
        @as(u32, rs2.int()) << 20 |
        @as(u32, rs1.int()) << 15 |
        @as(u32, @intCast(funct3)) << 12 |
        imm_lo << 7 |
        @as(u32, @intCast(opcode));
}

/// Encode a B-type instruction.
/// Layout: [imm[12|10:5] | rs2 | rs1 | funct3 | imm[4:1|11] | opcode]
/// Note: imm13 is a 13-bit signed offset; bit 0 is always 0 (half-word aligned).
pub inline fn encodeB(imm13: i13, rs2: Reg, rs1: Reg, funct3: u3, opcode: u7) u32 {
    const imm_bits: u32 = @as(u32, @bitCast(@as(i32, imm13))) & 0x1FFF;
    const bit_12: u32 = (imm_bits >> 12) & 0x1;
    const bits_10_5: u32 = (imm_bits >> 5) & 0x3F;
    const bits_4_1: u32 = (imm_bits >> 1) & 0xF;
    const bit_11: u32 = (imm_bits >> 11) & 0x1;
    return bit_12 << 31 |
        bits_10_5 << 25 |
        @as(u32, rs2.int()) << 20 |
        @as(u32, rs1.int()) << 15 |
        @as(u32, @intCast(funct3)) << 12 |
        bits_4_1 << 8 |
        bit_11 << 7 |
        @as(u32, @intCast(opcode));
}

/// Encode a U-type instruction.
/// Layout: [imm[31:12] | rd | opcode]
pub inline fn encodeU(imm20: u20, rd: Reg, opcode: u7) u32 {
    return @as(u32, @intCast(imm20)) << 12 |
        @as(u32, rd.int()) << 7 |
        @as(u32, @intCast(opcode));
}

/// Encode a J-type instruction.
/// Layout: [imm[20|10:1|11|19:12] | rd | opcode]
/// Note: imm21 is a 21-bit signed offset; bit 0 is always 0.
pub inline fn encodeJ(imm21: i21, rd: Reg, opcode: u7) u32 {
    const imm_bits: u32 = @as(u32, @bitCast(@as(i32, imm21))) & 0x1FFFFF;
    const bit_20: u32 = (imm_bits >> 20) & 0x1;
    const bits_10_1: u32 = (imm_bits >> 1) & 0x3FF;
    const bit_11: u32 = (imm_bits >> 11) & 0x1;
    const bits_19_12: u32 = (imm_bits >> 12) & 0xFF;
    return bit_20 << 31 |
        bits_10_1 << 21 |
        bit_11 << 20 |
        bits_19_12 << 12 |
        @as(u32, rd.int()) << 7 |
        @as(u32, @intCast(opcode));
}

// ═══════════════════════════════════════════════════════════════════════
// Named instruction constructors
// ═══════════════════════════════════════════════════════════════════════

/// ADD rd, rs1, rs2
pub inline fn ADD(rd: Reg, rs1: Reg, rs2: Reg) u32 {
    return encodeR(F7_ADD, rs2, rs1, F3_ADD_SUB, rd, OP_REG);
}

/// ADDI rd, rs1, imm
pub inline fn ADDI(rd: Reg, rs1: Reg, imm: i12) u32 {
    return encodeI(imm, rs1, F3_ADDI, rd, OP_IMM);
}

/// SUB rd, rs1, rs2
pub inline fn SUB(rd: Reg, rs1: Reg, rs2: Reg) u32 {
    return encodeR(F7_SUB, rs2, rs1, F3_ADD_SUB, rd, OP_REG);
}

/// MUL rd, rs1, rs2 (RV64M extension)
pub inline fn MUL(rd: Reg, rs1: Reg, rs2: Reg) u32 {
    return encodeR(F7_MULDIV, rs2, rs1, F3_MUL, rd, OP_REG);
}

/// DIV rd, rs1, rs2 (RV64M extension)
pub inline fn DIV(rd: Reg, rs1: Reg, rs2: Reg) u32 {
    return encodeR(F7_MULDIV, rs2, rs1, F3_DIV, rd, OP_REG);
}

/// REM rd, rs1, rs2 (RV64M extension)
pub inline fn REM(rd: Reg, rs1: Reg, rs2: Reg) u32 {
    return encodeR(F7_MULDIV, rs2, rs1, F3_REM, rd, OP_REG);
}

/// AND rd, rs1, rs2
pub inline fn AND(rd: Reg, rs1: Reg, rs2: Reg) u32 {
    return encodeR(F7_ADD, rs2, rs1, F3_AND, rd, OP_REG);
}

/// OR rd, rs1, rs2
pub inline fn OR(rd: Reg, rs1: Reg, rs2: Reg) u32 {
    return encodeR(F7_ADD, rs2, rs1, F3_OR, rd, OP_REG);
}

/// XOR rd, rs1, rs2
pub inline fn XOR(rd: Reg, rs1: Reg, rs2: Reg) u32 {
    return encodeR(F7_ADD, rs2, rs1, F3_XOR, rd, OP_REG);
}

/// SLL rd, rs1, rs2 (shift left logical)
pub inline fn SLL(rd: Reg, rs1: Reg, rs2: Reg) u32 {
    return encodeR(F7_ADD, rs2, rs1, F3_SLL, rd, OP_REG);
}

/// SRL rd, rs1, rs2 (shift right logical)
pub inline fn SRL(rd: Reg, rs1: Reg, rs2: Reg) u32 {
    return encodeR(F7_ADD, rs2, rs1, F3_SRL_SRA, rd, OP_REG);
}

/// SRA rd, rs1, rs2 (shift right arithmetic)
pub inline fn SRA(rd: Reg, rs1: Reg, rs2: Reg) u32 {
    return encodeR(F7_SUB, rs2, rs1, F3_SRL_SRA, rd, OP_REG);
}

/// LUI rd, imm20 (load upper immediate)
pub inline fn LUI(rd: Reg, imm: u20) u32 {
    return encodeU(imm, rd, OP_LUI);
}

/// AUIPC rd, imm20 (add upper immediate to PC)
pub inline fn AUIPC(rd: Reg, imm: u20) u32 {
    return encodeU(imm, rd, OP_AUIPC);
}

/// JAL rd, offset (jump and link)
pub inline fn JAL(rd: Reg, offset: i21) u32 {
    return encodeJ(offset, rd, OP_JAL);
}

/// JALR rd, rs1, offset (jump and link register)
pub inline fn JALR(rd: Reg, rs1: Reg, offset: i12) u32 {
    return encodeI(offset, rs1, 0x0, rd, OP_JALR);
}

/// BEQ rs1, rs2, offset (branch if equal)
pub inline fn BEQ(rs1: Reg, rs2: Reg, offset: i13) u32 {
    return encodeB(offset, rs2, rs1, F3_BEQ, OP_BRANCH);
}

/// BNE rs1, rs2, offset (branch if not equal)
pub inline fn BNE(rs1: Reg, rs2: Reg, offset: i13) u32 {
    return encodeB(offset, rs2, rs1, F3_BNE, OP_BRANCH);
}

/// BLT rs1, rs2, offset (branch if less than)
pub inline fn BLT(rs1: Reg, rs2: Reg, offset: i13) u32 {
    return encodeB(offset, rs2, rs1, F3_BLT, OP_BRANCH);
}

/// BGE rs1, rs2, offset (branch if greater or equal)
pub inline fn BGE(rs1: Reg, rs2: Reg, offset: i13) u32 {
    return encodeB(offset, rs2, rs1, F3_BGE, OP_BRANCH);
}

/// LD rd, offset(rs1) (load doubleword)
pub inline fn LD(rd: Reg, rs1: Reg, offset: i12) u32 {
    return encodeI(offset, rs1, F3_LD, rd, OP_LOAD);
}

/// SD rs2, offset(rs1) (store doubleword)
pub inline fn SD(rs1: Reg, rs2: Reg, offset: i12) u32 {
    return encodeS(offset, rs2, rs1, F3_SD, OP_STORE);
}

/// LW rd, offset(rs1) (load word)
pub inline fn LW(rd: Reg, rs1: Reg, offset: i12) u32 {
    return encodeI(offset, rs1, F3_LW, rd, OP_LOAD);
}

/// SW rs2, offset(rs1) (store word)
pub inline fn SW(rs1: Reg, rs2: Reg, offset: i12) u32 {
    return encodeS(offset, rs2, rs1, F3_SW, OP_STORE);
}

/// ECALL — environment call (triggers syscall).
pub inline fn ECALL() u32 {
    return 0x00000073;
}

/// ECALLI — environment call with immediate (for PolkaVM).
/// Encodes the hostcall number into the upper 12 bits (imm12) of the SYSTEM instruction.
pub inline fn ECALLI(hostcall: u12) u32 {
    const imm12_signed: i12 = @bitCast(hostcall);
    return encodeI(imm12_signed, .zero, 0, .zero, 0x73);
}

// ═══════════════════════════════════════════════════════════════════════
// Zephyria custom opcodes
// ═══════════════════════════════════════════════════════════════════════

/// Custom opcodes for Zephyria VM operations, encoded in the
/// RISC-V custom opcode space (custom-0 through custom-3).
pub const ZephCustomOp = enum(u8) {
    // ── custom-0 (opcode 0x0B): State operations ──
    /// Read a state field. a7=op, a0=field_id, a1=key_ptr → a0=value_ptr
    STATE_READ = 0x00,
    /// Write a state field. a7=op, a0=field_id, a1=key_ptr, a2=val_ptr
    STATE_WRITE = 0x01,
    /// Check existence. a7=op, a0=field_id, a1=key_ptr → a0=bool
    STATE_EXISTS = 0x02,
    /// Delete from map. a7=op, a0=field_id, a1=key_ptr
    STATE_DELETE = 0x03,

    // ── custom-1 (opcode 0x2B): Authority & Access operations ──
    /// Check authority. a7=op, a0=auth_id → a0=bool, panics if false
    AUTH_CHECK = 0x10,
    /// Assert access list entry is valid. a7=op, a0=entry_ptr
    ACCESS_ASSERT = 0x11,
    /// Delegate gas payment to another account. a7=op, a0=payer_addr
    DELEGATE_GAS = 0x12,

    // ── custom-2 (opcode 0x5B): Asset & Payment operations ──
    /// Transfer asset. a7=op, a0=asset_id, a1=from, a2=to, a3=amount
    ASSET_TRANSFER = 0x20,
    /// Mint asset. a7=op, a0=asset_id, a1=to, a2=amount
    ASSET_MINT = 0x21,
    /// Burn asset. a7=op, a0=asset_id, a1=from, a2=amount
    ASSET_BURN = 0x22,
    /// Pay native ZPH. a7=op, a0=to, a1=amount
    NATIVE_PAY = 0x23,

    // ── custom-3 (opcode 0x7B): VM-level operations ──
    /// Emit event. a7=op, a0=event_id, a1=data_ptr, a2=data_len
    EMIT_EVENT = 0x30,
    /// Schedule deferred call. a7=op, a0=program, a1=selector, a2=delay
    SCHEDULE_CALL = 0x31,
    /// Revert transaction. a7=op, a0=error_ptr, a1=error_len
    REVERT = 0x32,
    /// Debug log. a7=op, a0=msg_ptr, a1=msg_len
    LOG_DIAGNOSTIC = 0x33,
    /// Get caller address. a7=op → a0=address_ptr
    GET_CALLER = 0x34,
    /// Get current timestamp. a7=op → a0=u64
    GET_NOW = 0x35,
    /// Get current block number. a7=op → a0=u64
    GET_BLOCK = 0x36,
    /// Get sent native value. a7=op → a0=u64
    GET_VALUE = 0x37,
    /// Query Oracle value. a7=op, a0=query_string_ptr → a0=u256_ptr
    ORACLE_QUERY = 0x38,
    /// Get VRF randomness. a7=op → a0=u256_ptr
    VRF_RANDOM = 0x39,

    /// Return the custom-N base opcode for this operation.
    pub fn baseOpcode(self: ZephCustomOp) u7 {
        const val = @intFromEnum(self);
        if (val < 0x10) return CUSTOM_0;
        if (val < 0x20) return CUSTOM_1;
        if (val < 0x30) return CUSTOM_2;
        return CUSTOM_3;
    }
};

/// Encode a Zephyria custom instruction.
/// Uses I-type format with the custom-N opcode. funct3 encodes
/// the top 3 bits of the op value, immediate holds remaining bits.
pub inline fn ZEPH(op: ZephCustomOp) u32 {
    const val: u8 = @intFromEnum(op);
    const funct3: u3 = @truncate(val >> 4);
    const imm_lo: i12 = @intCast(val & 0x0F);
    return encodeI(imm_lo, .a7, funct3, .zero, op.baseOpcode());
}

// ═══════════════════════════════════════════════════════════════════════
// Bytecode writer
// ═══════════════════════════════════════════════════════════════════════

/// A buffer-backed writer that emits u32 RISC-V instructions as
/// little-endian byte sequences and supports backpatching.
pub const BytecodeWriter = struct {
    buf: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    /// Initialise with a general-purpose allocator.
    pub fn init(allocator: std.mem.Allocator) BytecodeWriter {
        return .{
            .buf = .{},
            .allocator = allocator,
        };
    }

    /// Release underlying memory.
    pub fn deinit(self: *BytecodeWriter) void {
        self.buf.deinit(self.allocator);
    }

    /// Emit a single 4-byte instruction in little-endian order.
    pub fn emit(self: *BytecodeWriter, instr: u32) anyerror!void {
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, instr));
        try self.buf.appendSlice(self.allocator, &bytes);
    }

    /// Emit a slice of instructions sequentially.
    pub fn emitAll(self: *BytecodeWriter, instrs: []const u32) anyerror!void {
        for (instrs) |instr| {
            try self.emit(instr);
        }
    }

    /// Return the current byte offset (i.e. number of bytes emitted so far).
    pub fn currentOffset(self: *const BytecodeWriter) u32 {
        return @intCast(self.buf.items.len);
    }

    /// Overwrite the instruction at the given byte offset.
    /// Used for backpatching branch / jump targets.
    pub fn patchAt(self: *BytecodeWriter, offset: u32, instr: u32) void {
        const off: usize = @intCast(offset);
        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, instr));
        @memcpy(self.buf.items[off..][0..4], &bytes);
    }

    /// Return the raw bytes emitted so far as a read-only slice.
    pub fn toBytes(self: *const BytecodeWriter) []const u8 {
        return self.buf.items;
    }
};

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

test "encode ADD instruction" {
    // ADD a0, a1, a2 → R-type: funct7=0, rs2=a2(12), rs1=a1(11), funct3=0, rd=a0(10), op=0x33
    const instr = ADD(.a0, .a1, .a2);
    // Verify opcode field
    try std.testing.expectEqual(@as(u7, 0x33), @as(u7, @truncate(instr)));
    // Verify rd field
    try std.testing.expectEqual(@as(u5, 10), @as(u5, @truncate(instr >> 7)));
    // Verify funct3
    try std.testing.expectEqual(@as(u3, 0), @as(u3, @truncate(instr >> 12)));
    // Verify rs1
    try std.testing.expectEqual(@as(u5, 11), @as(u5, @truncate(instr >> 15)));
    // Verify rs2
    try std.testing.expectEqual(@as(u5, 12), @as(u5, @truncate(instr >> 20)));
    // Verify funct7
    try std.testing.expectEqual(@as(u7, 0), @as(u7, @truncate(instr >> 25)));
}

test "encode ADDI immediate" {
    // ADDI a0, zero, 42 → I-type
    const instr = ADDI(.a0, .zero, 42);
    // Opcode
    try std.testing.expectEqual(@as(u7, 0x13), @as(u7, @truncate(instr)));
    // rd = a0(10)
    try std.testing.expectEqual(@as(u5, 10), @as(u5, @truncate(instr >> 7)));
    // funct3 = 0 (ADDI)
    try std.testing.expectEqual(@as(u3, 0), @as(u3, @truncate(instr >> 12)));
    // rs1 = zero(0)
    try std.testing.expectEqual(@as(u5, 0), @as(u5, @truncate(instr >> 15)));
    // imm[11:0] = 42
    try std.testing.expectEqual(@as(u12, 42), @as(u12, @truncate(instr >> 20)));
}

test "encode BEQ branch" {
    // BEQ a0, a1, 8 — offset 8 encoded in B-type fields
    const instr = BEQ(.a0, .a1, 8);
    // Opcode
    try std.testing.expectEqual(@as(u7, 0x63), @as(u7, @truncate(instr)));
    // funct3 = 0 (BEQ)
    try std.testing.expectEqual(@as(u3, 0), @as(u3, @truncate(instr >> 12)));
    // rs1 = a0(10)
    try std.testing.expectEqual(@as(u5, 10), @as(u5, @truncate(instr >> 15)));
    // rs2 = a1(11)
    try std.testing.expectEqual(@as(u5, 11), @as(u5, @truncate(instr >> 20)));
    // Reconstruct the immediate from the B-type fields and verify = 8
    const bit_11: u13 = @intCast((instr >> 7) & 0x1);
    const bits_4_1: u13 = @intCast((instr >> 8) & 0xF);
    const bits_10_5: u13 = @intCast((instr >> 25) & 0x3F);
    const bit_12: u13 = @intCast((instr >> 31) & 0x1);
    const reconstructed: u13 = (bit_12 << 12) | (bit_11 << 11) | (bits_10_5 << 5) | (bits_4_1 << 1);
    try std.testing.expectEqual(@as(u13, 8), reconstructed);
}

test "bytecode writer emit and patch" {
    var writer = BytecodeWriter.init(std.testing.allocator);
    defer writer.deinit();
    // Emit a placeholder NOP (ADDI zero, zero, 0)
    const nop = ADDI(.zero, .zero, 0);
    try writer.emit(nop);
    try std.testing.expectEqual(@as(u32, 4), writer.currentOffset());
    // Emit a second instruction
    const add_instr = ADD(.a0, .a1, .a2);
    try writer.emit(add_instr);
    try std.testing.expectEqual(@as(u32, 8), writer.currentOffset());
    // Patch the first instruction with a JAL
    const jal_instr = JAL(.ra, 100);
    writer.patchAt(0, jal_instr);
    // Read back patched bytes and verify
    const patched = std.mem.readInt(u32, writer.toBytes()[0..4], .little);
    try std.testing.expectEqual(jal_instr, patched);
    // Second instruction should be unchanged
    const second = std.mem.readInt(u32, writer.toBytes()[4..8], .little);
    try std.testing.expectEqual(add_instr, second);
}

test "all encodings are 4 bytes" {
    // Every instruction is exactly a u32 — verify a representative set
    const instrs = [_]u32{
        ADD(.a0, .a1, .a2),
        ADDI(.t0, .zero, -1),
        SUB(.s0, .s1, .s2),
        MUL(.a3, .a4, .a5),
        DIV(.a0, .a1, .a2),
        REM(.a0, .a1, .a2),
        AND(.t1, .t2, .t3),
        OR(.t4, .t5, .t6),
        XOR(.a0, .a0, .a1),
        SLL(.a0, .a1, .a2),
        SRL(.a0, .a1, .a2),
        SRA(.a0, .a1, .a2),
        LUI(.a0, 0xFFFFF),
        AUIPC(.a0, 0x12345),
        JAL(.ra, 0),
        JALR(.ra, .a0, 0),
        BEQ(.a0, .a1, 0),
        BNE(.a0, .a1, 4),
        BLT(.a0, .a1, -4),
        BGE(.a0, .a1, 8),
        LD(.a0, .sp, 0),
        SD(.sp, .a0, 8),
        LW(.a0, .sp, 4),
        SW(.sp, .a1, 16),
        ECALL(),
        ZEPH(.STATE_READ),
        ZEPH(.AUTH_CHECK),
        ZEPH(.ASSET_TRANSFER),
        ZEPH(.EMIT_EVENT),
        ZEPH(.REVERT),
        ZEPH(.GET_CALLER),
    };
    // u32 is always 4 bytes; this is a compile-time guarantee, but
    // we verify the BytecodeWriter emits 4 bytes per instruction.
    var writer = BytecodeWriter.init(std.testing.allocator);
    defer writer.deinit();
    for (instrs) |instr| {
        _ = instr; // value is u32 by type
        try std.testing.expectEqual(@as(usize, 4), @sizeOf(u32));
    }
    try writer.emitAll(&instrs);
    try std.testing.expectEqual(@as(u32, @intCast(instrs.len * 4)), writer.currentOffset());
}
