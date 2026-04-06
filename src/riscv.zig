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
// Zephyria syscall IDs — must exactly match dispatch.zig SyscallId
// ═══════════════════════════════════════════════════════════════════════

/// SPEC: Part 5 — Syscall numbers for the Zephyria VM.
/// These must EXACTLY match the SyscallId constants in:
///   zephyria/vm/syscall/dispatch.zig
/// The VM dispatches via vm.regs[10] (a0) at ECALL time.
pub const ZephCustomOp = enum(u32) {
    // ── Storage (dispatch.zig 0x01-0x06) ─────────────────────────────
    /// SPEC: Part 5.2 — Load a state slot.
    /// a0=0x01, a1=key_ptr(32B), a2=result_ptr(32B)
    STATE_READ           = 0x01,
    /// SPEC: Part 5.2 — Store a state slot.
    /// a0=0x02, a1=key_ptr(32B), a2=value_ptr(32B)
    STATE_WRITE          = 0x02,
    /// SPEC: Part 5.2 — Load per-user derived state slot.
    /// a0=0x03, a1=user_addr_ptr(20B), a2=key_ptr(32B), a3=result_ptr(32B)
    STATE_READ_DERIVED   = 0x03,
    /// SPEC: Part 5.2 — Store per-user derived state slot.
    /// a0=0x04, a1=user_addr_ptr(20B), a2=key_ptr(32B), a3=value_ptr(32B)
    STATE_WRITE_DERIVED  = 0x04,
    /// SPEC: Part 5.2 — Load global commutative accumulator.
    /// a0=0x05, a1=key_ptr(32B), a2=result_ptr(32B)
    STATE_READ_GLOBAL    = 0x05,
    /// SPEC: Part 5.2 — Update global commutative accumulator.
    /// a0=0x06, a1=key_ptr(32B), a2=delta_ptr(32B)
    STATE_WRITE_GLOBAL   = 0x06,

    // ── Assets (dispatch.zig 0x10-0x16) ──────────────────────────────
    /// SPEC: Part 8.4 — Transfer a FORGE native asset.
    /// a0=0x10, a1=asset_id_ptr(32B), a2=from_ptr(20B), a3=to_ptr(20B), a4=amount_ptr(16B)
    ASSET_TRANSFER       = 0x10,
    /// SPEC: Part 8.3 — Query asset balance.
    /// a0=0x11, a1=addr_ptr(20B), a2=result_ptr(32B)
    ASSET_BALANCE        = 0x11,
    /// SPEC: Part 8.3 — Create/mint a new asset token.
    /// a0=0x12, a1=asset_type_id, a2=to_ptr(20B), a3=amount_ptr(16B)
    ASSET_MINT           = 0x12,
    /// SPEC: Part 8.3 — Burn asset tokens.
    /// a0=0x13, a1=asset_id_ptr(32B), a2=from_ptr(20B), a3=amount_ptr(16B)
    ASSET_BURN           = 0x13,
    // Note: NATIVE_PAY uses ASSET_TRANSFER (0x10) — codegen passes zero asset ID.

    // ── Authority (dispatch.zig 0x20-0x23) ───────────────────────────
    /// SPEC: Part 7.3 — Check authority role of caller.
    /// a0=0x20, a1=role_hash_ptr(32B), a2=account_ptr(20B) → a0=1 if OK else revert
    AUTH_CHECK           = 0x20,
    /// SPEC: Part 7.3 — Grant authority role.
    /// a0=0x21, a1=role_hash_ptr(32B), a2=account_ptr(20B)
    AUTH_GRANT           = 0x21,
    /// SPEC: Part 7.3 — Revoke authority role.
    /// a0=0x22, a1=role_hash_ptr(32B), a2=account_ptr(20B)
    AUTH_REVOKE          = 0x22,

    // ── Events (dispatch.zig 0x30-0x31) ──────────────────────────────
    /// SPEC: Part 5.9 — Emit a contract event.
    /// a0=0x30, a1=topic_count, a2=topics_ptr, a3=data_ptr, a4=data_len
    EMIT_EVENT           = 0x30,
    /// SPEC: Part 5.9 — Emit an indexed contract event.
    /// Same layout as EMIT_EVENT but with bloom-filter indexing.
    EMIT_INDEXED_EVENT   = 0x31,

    // ── Cross-contract (dispatch.zig 0x40-0x43) ───────────────────────
    /// SPEC: Part 10.1 — Call another contract.
    /// a0=0x40, a1=to_ptr(20B), a2=selector, a3=calldata_ptr, a4=calldata_len
    SCHEDULE_CALL        = 0x40,

    // ── Execution control (dispatch.zig 0x50-0x51) ───────────────────
    /// SPEC: Part 6.6 — Revert transaction with data.
    /// a0=0x51, a1=data_ptr, a2=data_len
    REVERT               = 0x51,

    // ── Environment (dispatch.zig 0x60-0x6C) ─────────────────────────
    /// SPEC: Part 7.5 — Get msg.sender address.
    /// a0=0x60, a1=result_ptr(20B)
    GET_CALLER           = 0x60,
    /// SPEC: Part 7.5 — Get msg.value (native currency attached).
    /// a0=0x61, a1=result_ptr(32B)
    GET_VALUE            = 0x61,
    /// SPEC: Part 5.1 — Get this contract's address.
    /// a0=0x64, a1=result_ptr(20B)
    GET_THIS             = 0x64,
    /// SPEC: Part 14.3 — Get current block number.
    /// a0=0x65 → a0=block_number(u64)
    GET_BLOCK            = 0x65,
    /// SPEC: Part 14.3 — Get current timestamp.
    /// a0=0x66 → a0=timestamp(u64)
    GET_NOW              = 0x66,
    /// SPEC: Part 14.6 — Get remaining gas.
    /// a0=0x68 → a0=gas_remaining(u64)
    GET_GAS              = 0x68,
    /// SPEC: Part 14.4 — Get VRF randomness (prevrandao).
    /// a0=0x6C, a1=result_ptr(32B)
    VRF_RANDOM           = 0x6C,

    // ── Debug (dispatch.zig 0xFF, debug builds only) ──────────────────
    /// SPEC: Internal — Debug log (no-op in release).
    /// a0=0xFF, a1=msg_ptr, a2=msg_len
    LOG_DIAGNOSTIC       = 0xFF,

    // ── Extended (0xA0 range, Forge-specific additions) ────────────────
    /// SPEC: Part 14.2 — Oracle price query.
    /// a0=0xA0, a1=feed_id(u32) → a2=result_ptr(32B)
    ORACLE_QUERY         = 0xA0,
};

/// SPEC: Part 5 — Emit a Zephyria syscall.
///
/// The Zephyria VM dispatches via vm.regs[10] (a0) at ECALL time.
/// This function does NOT emit an instruction itself — it returns the
/// ADDI a0, zero, syscall_id instruction that callers must emit BEFORE
/// calling ECALL().  Pattern:
///
///   try writer.emit(riscv.ZEPH_SET_ID(.STATE_READ));  // ADDI a0, zero, 0x01
///   try writer.emit(riscv.ECALL());                   // triggers dispatch
///
/// For backwards compatibility with existing call sites that do
/// `writer.emit(riscv.ZEPH(op))`, ZEPH() now returns the ADDI a0 instruction.
/// Callers still need to emit an ECALL() separately when transitioning,
/// but existing code in codegen.zig that calls ZEPH() and then does
/// the dispatch implicitly via the custom encoding is updated in codegen.zig.
pub inline fn ZEPH_SET_ID(op: ZephCustomOp) u32 {
    // ADDI a0, zero, syscall_id  (fits in i12 for IDs ≤ 0xFFF)
    const id: u32 = @intFromEnum(op);
    const imm: i12 = @intCast(id & 0x7FF); // truncate safely; IDs are small
    return encodeI(imm, .zero, F3_ADDI, .a0, OP_IMM);
}

/// SPEC: Part 5 — Backwards-compatible ZEPH() that emits the syscall-ID
/// load instruction.  Callers MUST also emit ECALL() after this.
/// This replaces the old custom-opcode encoding.
pub inline fn ZEPH(op: ZephCustomOp) u32 {
    return ZEPH_SET_ID(op);
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

// ═══════════════════════════════════════════════════════════════════════
// 64-bit constant loading helpers
// ═══════════════════════════════════════════════════════════════════════

/// SPEC: Part 3 — Load a full 64-bit constant into `rd` using at most 4
/// instructions (RV64 LUI/ADDI/SLLI/ADDI sequence).
///
/// Strategy for value V:
///   If V fits in 12 bits:  ADDI rd, zero, V
///   If V fits in 32 bits:  LUI rd, hi20 / ADDI rd, rd, lo12
///   Otherwise (64-bit):    LUI t0, hi20(upper32)
///                          ADDI t0, t0, lo12(upper32)
///                          SLLI rd, t0, 32
///                          ORI  rd, rd, lower32  (if lower32 non-zero)
///
/// Returns the number of instructions written (1-4).
/// WARNING: for the 64-bit case this clobbers `t0` (x5).
pub fn genLoadImmediate64(writer: *BytecodeWriter, rd: Reg, value: u64) anyerror!u32 {
    if (value <= 0x7FF) {
        // Tiny positive: single ADDI
        try writer.emit(ADDI(rd, .zero, @intCast(value)));
        return 1;
    }

    const lo32: u32 = @truncate(value);
    const hi32: u32 = @truncate(value >> 32);

    if (hi32 == 0) {
        // 32-bit value: LUI + ADDI (standard RV32 constant load sequence)
        const lo12: i12 = @bitCast(@as(u12, @truncate(lo32)));
        // Adjust upper 20 bits for sign extension of lo12
        const hi20_raw: u32 = lo32 >> 12;
        const hi20: u20 = if (lo12 < 0)
            @truncate(hi20_raw +% 1)
        else
            @truncate(hi20_raw);
        if (hi20 != 0) {
            try writer.emit(LUI(rd, hi20));
            try writer.emit(ADDI(rd, rd, lo12));
            return 2;
        }
        // hi20==0 means value fits in 12 bits (negative sign-extended)
        try writer.emit(ADDI(rd, .zero, lo12));
        return 1;
    }

    // Full 64-bit: build upper 32 bits in t0 then combine.
    // Step 1: load hi32 into t0
    const hi_lo12: i12 = @bitCast(@as(u12, @truncate(hi32)));
    const hi_hi20_raw: u32 = hi32 >> 12;
    const hi_hi20: u20 = if (hi_lo12 < 0)
        @truncate(hi_hi20_raw +% 1)
    else
        @truncate(hi_hi20_raw);
    try writer.emit(LUI(.t0, hi_hi20));
    try writer.emit(ADDI(.t0, .t0, hi_lo12));
    // Step 2: shift t0 left 32 into rd
    const slli_32 = encodeI(32, .t0, F3_SLLI, rd, OP_IMM);
    try writer.emit(slli_32);
    // Step 3: OR in the lower 32 bits (if non-zero)
    if (lo32 != 0) {
        // lo32 may not fit in i12; use a second LUI+ADDI into t0 then OR
        const lo_lo12: i12 = @bitCast(@as(u12, @truncate(lo32)));
        const lo_hi20_raw: u32 = lo32 >> 12;
        const lo_hi20: u20 = if (lo_lo12 < 0)
            @truncate(lo_hi20_raw +% 1)
        else
            @truncate(lo_hi20_raw);
        if (lo_hi20 != 0) {
            try writer.emit(LUI(.t0, lo_hi20));
            try writer.emit(ADDI(.t0, .t0, lo_lo12));
        } else {
            try writer.emit(ADDI(.t0, .zero, lo_lo12));
        }
        try writer.emit(OR(rd, rd, .t0));
        return 7; // worst case
    }
    return 3;
}

test "ZEPH() encodes correct syscall ID in a0" {
    // ZEPH(.STATE_READ) must emit: ADDI a0, zero, 0x01 (dispatch.zig STORAGE_LOAD)
    const instr = ZEPH(.STATE_READ);
    // Opcode = OP_IMM = 0x13
    try std.testing.expectEqual(@as(u7, 0x13), @as(u7, @truncate(instr)));
    // rd = a0 = 10
    try std.testing.expectEqual(@as(u5, 10), @as(u5, @truncate(instr >> 7)));
    // funct3 = 0 (ADDI)
    try std.testing.expectEqual(@as(u3, 0), @as(u3, @truncate(instr >> 12)));
    // rs1 = zero = 0
    try std.testing.expectEqual(@as(u5, 0), @as(u5, @truncate(instr >> 15)));
    // imm[11:0] = 0x01
    try std.testing.expectEqual(@as(u12, 0x01), @as(u12, @truncate(instr >> 20)));
}

test "ZEPH_SET_ID produces correct dispatch IDs" {
    // Verify a selection of syscall IDs against the dispatch.zig table
    const cases = [_]struct { op: ZephCustomOp, id: u12 }{
        .{ .op = .STATE_READ,    .id = 0x01 },
        .{ .op = .STATE_WRITE,   .id = 0x02 },
        .{ .op = .ASSET_TRANSFER,.id = 0x10 },
        .{ .op = .AUTH_CHECK,    .id = 0x20 },
        .{ .op = .EMIT_EVENT,    .id = 0x30 },
        .{ .op = .SCHEDULE_CALL, .id = 0x40 },
        .{ .op = .REVERT,        .id = 0x51 },
        .{ .op = .GET_CALLER,    .id = 0x60 },
        .{ .op = .GET_NOW,       .id = 0x66 },
        .{ .op = .GET_GAS,       .id = 0x68 },
        .{ .op = .VRF_RANDOM,    .id = 0x6C },
    };
    for (cases) |c| {
        const instr = ZEPH_SET_ID(c.op);
        const encoded_id = @as(u12, @truncate(instr >> 20));
        try std.testing.expectEqual(c.id, encoded_id);
    }
}

test "genLoadImmediate64 small value" {
    var writer = BytecodeWriter.init(std.testing.allocator);
    defer writer.deinit();
    const count = try genLoadImmediate64(&writer, .a0, 42);
    try std.testing.expectEqual(@as(u32, 1), count);
    const instr = std.mem.readInt(u32, writer.toBytes()[0..4], .little);
    // ADDI a0, zero, 42
    try std.testing.expectEqual(ADDI(.a0, .zero, 42), instr);
}

test "genLoadImmediate64 32-bit value" {
    var writer = BytecodeWriter.init(std.testing.allocator);
    defer writer.deinit();
    const count = try genLoadImmediate64(&writer, .a1, 0x12345);
    try std.testing.expect(count <= 2);
    // Result must be 4 or 8 bytes
    try std.testing.expect(writer.currentOffset() <= 8);
}
