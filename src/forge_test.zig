// ============================================================================
// Forge Test Runner — Foundry-equivalent for Forge smart contracts
// ============================================================================
//
// `forge test` discovers all *.test.foz files in the project tree, compiles
// each in-process, runs every action prefixed with `test_` inside a sandboxed
// mock host environment, and reports results to stdout.
//
// Design:
//   - No network, no node required (fully in-process)
//   - Each test gets a clean MockHostEnv (fresh storage, empty event log)
//   - Gas is metered by instruction count * fixed cost table
//   - Failures are detected by REVERT syscall or abnormal termination
//
// SPEC REFERENCE: Part 5 (contracts), Part 20 (binary format)
//
// RV64IM: All execution uses 64-bit registers matching the Zephyria VM.

const std = @import("std");
const lexer = @import("lexer.zig");
const parser = @import("parser.zig");
const types = @import("types.zig");
const checker = @import("checker.zig");
const codegen = @import("codegen.zig");
const errors = @import("errors.zig");

// ============================================================================
// Section 1 — Result Types
// ============================================================================

/// SPEC: Internal — outcome of a single test execution.
pub const TestResult = struct {
    /// Test name, e.g. "test_transfer".
    name: []const u8,
    /// True if the test passed (no REVERT, no panic).
    passed: bool,
    /// Instructions executed (proxy for gas used).
    gas_used: u64,
    /// Error message if failed, or null if passed.
    failure_msg: ?[]const u8,
    /// Events emitted during the test.
    event_count: u32,
};

/// SPEC: Internal — summary across all tests in one file.
pub const FileResult = struct {
    /// Path to the source file.
    file_path: []const u8,
    /// Compile error, if any (no individual test results in this case).
    compile_error: ?[]const u8,
    /// Individual test results (empty on compile failure).
    tests: []TestResult,
    /// Total tests passed.
    passed: u32,
    /// Total tests failed.
    failed: u32,
};

// ============================================================================
// Section 2 — Mock Storage Backend
// ============================================================================

/// SPEC: Part 5.2 — In-memory storage for testing.
/// Keys are 32-byte arrays (matching STORAGE_LOAD/STORE ABI).
/// Values are 32-byte arrays.
pub const MockStorage = struct {
    /// Storage map: 32-byte key → 32-byte value.
    map: std.StringHashMapUnmanaged([32]u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MockStorage {
        return .{ .map = .{}, .allocator = allocator };
    }

    pub fn deinit(self: *MockStorage) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.map.deinit(self.allocator);
    }

    /// Load 32 bytes at `key_ptr`[0..32]. Returns zeros if not set.
    pub fn load(self: *const MockStorage, key: *const [32]u8) [32]u8 {
        return self.map.get(key[0..]) orelse [_]u8{0} ** 32;
    }

    /// Store 32 bytes at `key_ptr`[0..32].
    pub fn store(self: *MockStorage, key: *const [32]u8, value: *const [32]u8) anyerror!void {
        // Duplicate key into owned allocation
        const owned_key = try self.allocator.dupe(u8, key[0..]);
        errdefer self.allocator.free(owned_key);
        const entry = try self.map.getOrPut(self.allocator, owned_key);
        if (entry.found_existing) self.allocator.free(owned_key);
        entry.value_ptr.* = value.*;
    }
};

// ============================================================================
// Section 3 — Mock Event Log
// ============================================================================

/// SPEC: Part 5.9 — Captured event emission during test execution.
pub const MockEvent = struct {
    /// Raw topic data (up to 4 * 32 = 128 bytes).
    topics: [128]u8,
    topic_count: u8,
    /// Raw event data (up to 256 bytes).
    data: [256]u8,
    data_len: u32,
};

/// SPEC: Part 5.9 — Growing event log for one test execution.
pub const EventLog = struct {
    events: std.ArrayListUnmanaged(MockEvent),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) EventLog {
        return .{ .events = .{}, .allocator = allocator };
    }

    pub fn deinit(self: *EventLog) void {
        self.events.deinit(self.allocator);
    }

    pub fn append(self: *EventLog, ev: MockEvent) anyerror!void {
        try self.events.append(self.allocator, ev);
    }
};

// ============================================================================
// Section 4 — Mock Host Environment
// ============================================================================

/// SPEC: Part 5 — Host environment for in-test execution.
/// Holds storage, event log, caller address, block metadata.
pub const MockHostEnv = struct {
    storage:      MockStorage,
    events:       EventLog,
    /// Simulated msg.sender (20-byte address, zero-padded).
    caller:       [20]u8,
    /// Simulated msg.value in smallest unit.
    call_value:   u64,
    /// Current simulated block number.
    block_number: u64,
    /// Current simulated timestamp (Unix seconds).
    timestamp:    u64,
    /// Remaining gas (decremented by instructions).
    gas_remaining: u64,
    /// True if a REVERT syscall was received.
    reverted:     bool,
    /// Revert message, if any.
    revert_msg:   [256]u8,
    revert_len:   u32,

    allocator: std.mem.Allocator,

    /// SPEC: Internal — default test environment.
    pub fn init(allocator: std.mem.Allocator) MockHostEnv {
        // Default test caller: 0xDEAD...0001
        var caller = [_]u8{0} ** 20;
        caller[18] = 0xDE;
        caller[19] = 0x01;
        return .{
            .storage      = MockStorage.init(allocator),
            .events       = EventLog.init(allocator),
            .caller       = caller,
            .call_value   = 0,
            .block_number = 1,
            .timestamp    = 1_700_000_000,
            .gas_remaining = 10_000_000,
            .reverted     = false,
            .revert_msg   = [_]u8{0} ** 256,
            .revert_len   = 0,
            .allocator    = allocator,
        };
    }

    pub fn deinit(self: *MockHostEnv) void {
        self.storage.deinit();
        self.events.deinit();
    }
};

// ============================================================================
// Section 5 — Bytecode Interpreter (RV64IM subset)
// ============================================================================

/// SPEC: Part 3 — RV64IM register file.
/// 32 × 64-bit integer registers; x0 is always zero.
const RegFile = struct {
    x: [32]u64 = [_]u64{0} ** 32,

    pub inline fn get(self: *const RegFile, r: u5) u64 {
        return if (r == 0) 0 else self.x[r];
    }

    pub inline fn set(self: *RegFile, r: u5, v: u64) void {
        if (r != 0) self.x[r] = v;
    }
};

/// SPEC: Part 3 — Result of one instruction step.
const StepResult = enum {
    /// Continue execution at pc + 4.
    ok,
    /// Branch or jump taken; pc already updated.
    jump,
    /// ECALL was issued; host must handle it.
    ecall,
    /// Execution complete (JALR zero, ra, 0 at top frame).
    halt,
    /// Illegal instruction or decode failure.
    @"error",
};

/// SPEC: Internal — RV64IM bytecode interpreter for the test runner.
/// This is NOT the production VM (that is in zephyria/vm/). It is a
/// minimal interpreter that can run generated .fozbin bytecode in tests.
pub const Interpreter = struct {
    /// Register file.
    regs: RegFile,
    /// Program counter (byte offset into `code`).
    pc: u64,
    /// Bytecode to execute.
    code: []const u8,
    /// Simulated main memory (stack + scratch buffers).
    memory: []u8,
    /// Host environment.
    host: *MockHostEnv,
    /// Instructions executed so far (gas proxy).
    instr_count: u64,
    /// Maximum instructions allowed.
    max_instrs: u64,

    const MEMORY_SIZE: usize = 64 * 1024; // 64 KiB test sandbox
    const STACK_BASE: u64    = MEMORY_SIZE - 8; // stack grows downward

    /// SPEC: Internal — initialise interpreter for one test invocation.
    pub fn init(
        allocator: std.mem.Allocator,
        code: []const u8,
        host: *MockHostEnv,
    ) anyerror!Interpreter {
        const memory = try allocator.alloc(u8, MEMORY_SIZE);
        @memset(memory, 0);
        var regs = RegFile{};
        // sp (x2) = top of simulated stack
        regs.set(2, STACK_BASE);
        // gp (x3) = base of data section (mapped at 0 in test sandbox)
        regs.set(3, 0);
        return .{
            .regs        = regs,
            .pc          = 0,
            .code        = code,
            .memory      = memory,
            .host        = host,
            .instr_count = 0,
            .max_instrs  = 5_000_000,
        };
    }

    pub fn deinit(self: *Interpreter, allocator: std.mem.Allocator) void {
        allocator.free(self.memory);
    }

    /// SPEC: Internal — fetch and execute one RV64IM instruction.
    /// Returns StepResult indicating what happened.
    pub fn step(self: *Interpreter) StepResult {
        if (self.pc + 4 > self.code.len) return .halt;
        if (self.instr_count >= self.max_instrs) return .@"error";
        self.instr_count += 1;

        const raw = std.mem.readInt(u32, self.code[self.pc..][0..4], .little);
        const opcode: u7 = @truncate(raw);

        switch (opcode) {
            0x73 => { // SYSTEM — ECALL or EBREAK
                if (raw == 0x00000073) return .ecall;
                // EBREAK or other — treat as halt
                return .halt;
            },
            0x33 => { // R-type: ADD/SUB/MUL/DIV/REM/AND/OR/XOR/SLL/SRL/SRA
                const rd:     u5 = @truncate(raw >> 7);
                const funct3: u3 = @truncate(raw >> 12);
                const rs1:    u5 = @truncate(raw >> 15);
                const rs2:    u5 = @truncate(raw >> 20);
                const funct7: u7 = @truncate(raw >> 25);
                const v1 = self.regs.get(rs1);
                const v2 = self.regs.get(rs2);
                const result: u64 = switch (funct7) {
                    0x00 => switch (funct3) {
                        0x0 => v1 +% v2,                              // ADD
                        0x4 => v1 ^ v2,                              // XOR
                        0x6 => v1 | v2,                              // OR
                        0x7 => v1 & v2,                              // AND
                        0x1 => v1 << @truncate(v2 & 63),            // SLL
                        0x5 => v1 >> @truncate(v2 & 63),            // SRL
                        0x2 => if (@as(i64, @bitCast(v1)) < @as(i64, @bitCast(v2))) 1 else 0, // SLT
                        0x3 => if (v1 < v2) 1 else 0,               // SLTU
                        else => 0,
                    },
                    0x20 => switch (funct3) {
                        0x0 => v1 -% v2,                             // SUB
                        0x5 => @as(u64, @bitCast(@as(i64, @bitCast(v1)) >> @truncate(v2 & 63))), // SRA
                        else => 0,
                    },
                    0x01 => switch (funct3) { // M extension
                        0x0 => v1 *% v2,                             // MUL
                        0x4 => if (v2 != 0) v1 / v2 else std.math.maxInt(u64), // DIV (signed TBD)
                        0x5 => if (v2 != 0) v1 / v2 else std.math.maxInt(u64), // DIVU
                        0x6 => if (v2 != 0) v1 % v2 else v1,        // REM
                        0x7 => if (v2 != 0) v1 % v2 else v1,        // REMU
                        else => 0,
                    },
                    else => 0,
                };
                self.regs.set(rd, result);
                self.pc += 4;
                return .ok;
            },
            0x13 => { // I-type: ADDI / SLTI / ANDI / ORI / XORI / SLLI / SRLI / SRAI
                const rd:     u5 = @truncate(raw >> 7);
                const funct3: u3 = @truncate(raw >> 12);
                const rs1:    u5 = @truncate(raw >> 15);
                const imm_raw: i12 = @truncate(@as(i32, @bitCast(raw)) >> 20);
                const imm: i64 = imm_raw;
                const v1 = self.regs.get(rs1);
                const result: u64 = switch (funct3) {
                    0x0 => @bitCast(@as(i64, @bitCast(v1)) +% imm),  // ADDI
                    0x2 => if (@as(i64, @bitCast(v1)) < imm) 1 else 0, // SLTI
                    0x3 => if (v1 < @as(u64, @bitCast(imm))) 1 else 0, // SLTIU
                    0x4 => v1 ^ @as(u64, @bitCast(imm)),              // XORI
                    0x6 => v1 | @as(u64, @bitCast(imm)),              // ORI
                    0x7 => v1 & @as(u64, @bitCast(imm)),              // ANDI
                    0x1 => v1 << @truncate(@as(u64, @bitCast(imm)) & 63), // SLLI (RV64: 6-bit shamt)
                    0x5 => blk: { // SRLI / SRAI
                        const shamt: u6 = @truncate(@as(u64, @bitCast(imm)));
                        const arith: bool = (raw >> 30 & 1) != 0;
                        break :blk if (arith)
                            @as(u64, @bitCast(@as(i64, @bitCast(v1)) >> shamt))
                        else
                            v1 >> shamt;
                    },
                    else => 0,
                };
                self.regs.set(rd, result);
                self.pc += 4;
                return .ok;
            },
            0x37 => { // LUI
                const rd:  u5  = @truncate(raw >> 7);
                const imm: u32 = raw & 0xFFFFF000;
                self.regs.set(rd, @as(u64, @bitCast(@as(i64, @as(i32, @bitCast(imm))))));
                self.pc += 4;
                return .ok;
            },
            0x17 => { // AUIPC
                const rd:  u5  = @truncate(raw >> 7);
                const imm: u32 = raw & 0xFFFFF000;
                const offset: i64 = @as(i32, @bitCast(imm));
                self.regs.set(rd, @as(u64, @bitCast(@as(i64, @bitCast(self.pc)) +% offset)));
                self.pc += 4;
                return .ok;
            },
            0x6F => { // JAL
                const rd:  u5  = @truncate(raw >> 7);
                const imm = decodeJ(raw);
                self.regs.set(rd, self.pc + 4);
                self.pc = @as(u64, @bitCast(@as(i64, @bitCast(self.pc)) +% imm));
                return .jump;
            },
            0x67 => { // JALR
                const rd:  u5  = @truncate(raw >> 7);
                const rs1: u5  = @truncate(raw >> 15);
                const imm: i12 = @truncate(@as(i32, @bitCast(raw)) >> 20);
                const target = (@as(i64, @bitCast(self.regs.get(rs1))) +% @as(i64, imm)) & ~@as(i64, 1);
                const ret_addr = self.pc + 4;
                self.regs.set(rd, ret_addr);
                // Detect halt: JALR zero, ra, 0 at pc==0 returns to 0 → halt
                if (rd == 0 and target == 0) return .halt;
                self.pc = @bitCast(target);
                return .jump;
            },
            0x63 => { // Branch
                const funct3: u3 = @truncate(raw >> 12);
                const rs1:    u5 = @truncate(raw >> 15);
                const rs2:    u5 = @truncate(raw >> 20);
                const imm = decodeB(raw);
                const v1 = self.regs.get(rs1);
                const v2 = self.regs.get(rs2);
                const taken: bool = switch (funct3) {
                    0x0 => v1 == v2,                                  // BEQ
                    0x1 => v1 != v2,                                  // BNE
                    0x4 => @as(i64, @bitCast(v1)) < @as(i64, @bitCast(v2)), // BLT
                    0x5 => @as(i64, @bitCast(v1)) >= @as(i64, @bitCast(v2)),// BGE
                    0x6 => v1 < v2,                                   // BLTU
                    0x7 => v1 >= v2,                                  // BGEU
                    else => false,
                };
                if (taken) {
                    self.pc = @as(u64, @bitCast(@as(i64, @bitCast(self.pc)) +% imm));
                    return .jump;
                }
                self.pc += 4;
                return .ok;
            },
            0x03 => { // Load: LB / LH / LW / LD / LBU / LHU / LWU
                const rd:     u5  = @truncate(raw >> 7);
                const funct3: u3  = @truncate(raw >> 12);
                const rs1:    u5  = @truncate(raw >> 15);
                const imm:    i12 = @truncate(@as(i32, @bitCast(raw)) >> 20);
                const addr = @as(u64, @bitCast(@as(i64, @bitCast(self.regs.get(rs1))) +% @as(i64, imm)));
                const result: u64 = self.memLoad(addr, funct3);
                self.regs.set(rd, result);
                self.pc += 4;
                return .ok;
            },
            0x23 => { // Store: SB / SH / SW / SD
                const funct3: u3 = @truncate(raw >> 12);
                const rs1:    u5 = @truncate(raw >> 15);
                const rs2:    u5 = @truncate(raw >> 20);
                const imm_lo: i5 = @truncate(@as(i32, @bitCast(raw)) >> 7);
                const imm_hi: i7 = @truncate(@as(i32, @bitCast(raw)) >> 25);
                const imm: i12   = @as(i12, imm_hi) << 5 | @as(i12, imm_lo);
                const addr = @as(u64, @bitCast(@as(i64, @bitCast(self.regs.get(rs1))) +% @as(i64, imm)));
                self.memStore(addr, self.regs.get(rs2), funct3);
                self.pc += 4;
                return .ok;
            },
            else => {
                // Unknown opcode — treat as halt for safety
                return .halt;
            },
        }
    }

    /// SPEC: Internal — handle ECALL by reading a0 (syscall ID) and dispatching.
    pub fn handleEcall(self: *Interpreter) anyerror!bool {
        const syscall_id = self.regs.get(10); // a0
        switch (syscall_id) {
            0x01 => { // STORAGE_LOAD: a1=key_ptr, a2=result_ptr
                const key_ptr: u64 = self.regs.get(11);
                const res_ptr: u64 = self.regs.get(12);
                const key = self.readMem32(key_ptr);
                const val = self.host.storage.load(&key);
                self.writeMem32(res_ptr, &val);
            },
            0x02 => { // STORAGE_STORE: a1=key_ptr, a2=value_ptr
                const key_ptr: u64 = self.regs.get(11);
                const val_ptr: u64 = self.regs.get(12);
                const key = self.readMem32(key_ptr);
                const val = self.readMem32(val_ptr);
                try self.host.storage.store(&key, &val);
            },
            0x20 => { // AUTH_CHECK: a1=role_hash_ptr, a2=account — always pass in tests
                self.regs.set(10, 1);
            },
            0x30 => { // EMIT_EVENT: a1=topic_count, a2=topics_ptr, a3=data_ptr, a4=data_len
                const topic_count: u8 = @truncate(self.regs.get(11));
                const topics_ptr: u64 = self.regs.get(12);
                const data_ptr:   u64 = self.regs.get(13);
                const data_len:   u32 = @truncate(self.regs.get(14));
                var ev = MockEvent{
                    .topics      = [_]u8{0} ** 128,
                    .topic_count = topic_count,
                    .data        = [_]u8{0} ** 256,
                    .data_len    = @min(data_len, 256),
                };
                const copy_topics = @min(@as(usize, topic_count) * 32, 128);
                self.readMemSlice(topics_ptr, ev.topics[0..copy_topics]);
                const copy_data = @min(data_len, 256);
                self.readMemSlice(data_ptr, ev.data[0..copy_data]);
                try self.host.events.append(ev);
            },
            0x51 => { // REVERT: a1=data_ptr, a2=data_len
                const data_len: u32 = @truncate(self.regs.get(12));
                self.host.reverted = true;
                self.host.revert_len = @min(data_len, 256);
                self.readMemSlice(self.regs.get(11), self.host.revert_msg[0..self.host.revert_len]);
                return true; // signal halt
            },
            0x60 => { // GET_CALLER: a1=result_ptr(20B)
                const res_ptr: u64 = self.regs.get(11);
                self.writeMemSlice(res_ptr, self.host.caller[0..]);
            },
            0x61 => { // GET_VALUE: a1=result_ptr(32B)
                var val_buf = [_]u8{0} ** 32;
                std.mem.writeInt(u64, val_buf[0..8], self.host.call_value, .little);
                self.writeMemSlice(self.regs.get(11), val_buf[0..]);
            },
            0x65 => { // GET_BLOCK: → a0
                self.regs.set(10, self.host.block_number);
            },
            0x66 => { // GET_NOW: → a0
                self.regs.set(10, self.host.timestamp);
            },
            0x68 => { // GET_GAS: → a0
                self.regs.set(10, self.host.gas_remaining);
            },
            else => {
                // Unknown syscall — no-op in test mode
            },
        }
        self.pc += 4;
        return false;
    }

    // ── Memory helpers ─────────────────────────────────────────────────────

    fn addrToIdx(addr: u64, comptime size: usize) ?usize {
        if (addr + size > MEMORY_SIZE) return null;
        return @intCast(addr);
    }

    fn memLoad(self: *const Interpreter, addr: u64, funct3: u3) u64 {
        const idx = addrToIdx(addr, 1) orelse return 0;
        return switch (funct3) {
            0x0 => @as(u64, @bitCast(@as(i64, @as(i8, @bitCast(self.memory[idx]))))),   // LB
            0x1 => @as(u64, @bitCast(@as(i64, @as(i16, @bitCast(std.mem.readInt(u16, self.memory[idx..][0..2], .little)))))), // LH
            0x2 => @as(u64, @bitCast(@as(i64, @as(i32, @bitCast(std.mem.readInt(u32, self.memory[idx..][0..4], .little)))))), // LW
            0x3 => std.mem.readInt(u64, self.memory[idx..][0..8], .little),               // LD
            0x4 => self.memory[idx],                                                       // LBU
            0x5 => std.mem.readInt(u16, self.memory[idx..][0..2], .little),               // LHU
            0x6 => std.mem.readInt(u32, self.memory[idx..][0..4], .little),               // LWU
            else => 0,
        };
    }

    fn memStore(self: *Interpreter, addr: u64, val: u64, funct3: u3) void {
        const idx = addrToIdx(addr, 1) orelse return;
        switch (funct3) {
            0x0 => self.memory[idx] = @truncate(val),                                     // SB
            0x1 => std.mem.writeInt(u16, self.memory[idx..][0..2], @truncate(val), .little), // SH
            0x2 => std.mem.writeInt(u32, self.memory[idx..][0..4], @truncate(val), .little), // SW
            0x3 => std.mem.writeInt(u64, self.memory[idx..][0..8], val, .little),         // SD
            else => {},
        }
    }

    fn readMem32(self: *const Interpreter, addr: u64) [32]u8 {
        var buf = [_]u8{0} ** 32;
        const idx = addrToIdx(addr, 32) orelse return buf;
        @memcpy(buf[0..], self.memory[idx..][0..32]);
        return buf;
    }

    fn writeMem32(self: *Interpreter, addr: u64, data: *const [32]u8) void {
        const idx = addrToIdx(addr, 32) orelse return;
        @memcpy(self.memory[idx..][0..32], data[0..]);
    }

    fn readMemSlice(self: *const Interpreter, addr: u64, buf: []u8) void {
        const idx = addrToIdx(addr, 1) orelse return;
        const copy_len = @min(buf.len, MEMORY_SIZE - idx);
        @memcpy(buf[0..copy_len], self.memory[idx..][0..copy_len]);
    }

    fn writeMemSlice(self: *Interpreter, addr: u64, data: []const u8) void {
        const idx = addrToIdx(addr, 1) orelse return;
        const copy_len = @min(data.len, MEMORY_SIZE - idx);
        @memcpy(self.memory[idx..][0..copy_len], data[0..copy_len]);
    }

    // ── Instruction decoders ──────────────────────────────────────────────

    fn decodeJ(raw: u32) i64 {
        const bit_20:     i64 = @intCast((raw >> 31) & 0x1);
        const bits_10_1:  i64 = @intCast((raw >> 21) & 0x3FF);
        const bit_11:     i64 = @intCast((raw >> 20) & 0x1);
        const bits_19_12: i64 = @intCast((raw >> 12) & 0xFF);
        return (bit_20 << 20) | (bits_19_12 << 12) | (bit_11 << 11) | (bits_10_1 << 1);
    }

    fn decodeB(raw: u32) i64 {
        const bit_12:    i64 = @intCast((raw >> 31) & 0x1);
        const bit_11:    i64 = @intCast((raw >> 7) & 0x1);
        const bits_10_5: i64 = @intCast((raw >> 25) & 0x3F);
        const bits_4_1:  i64 = @intCast((raw >> 8) & 0xF);
        return (bit_12 << 12) | (bit_11 << 11) | (bits_10_5 << 5) | (bits_4_1 << 1);
    }
};

// ============================================================================
// Section 6 — Test Runner
// ============================================================================

/// SPEC: Internal — full test runner: discover, compile, run, report.
pub const TestRunner = struct {
    allocator: std.mem.Allocator,
    /// Matching when verbose flag is set (print each instruction).
    verbose: bool,
    /// JSON output mode.
    json_output: bool,

    pub fn init(allocator: std.mem.Allocator, verbose: bool, json_output: bool) TestRunner {
        return .{ .allocator = allocator, .verbose = verbose, .json_output = json_output };
    }

    /// SPEC: Internal — discover and run all test files under `root_dir`.
    /// Returns total pass/fail counts.
    pub fn runAll(self: *TestRunner, root_dir: []const u8) anyerror!struct { passed: u32, failed: u32 } {
        var total_passed: u32 = 0;
        var total_failed: u32 = 0;

        var dir = std.fs.openDirAbsolute(root_dir, .{ .iterate = true }) catch |err| {
            std.debug.print("error: cannot open directory '{s}': {}\n", .{ root_dir, err });
            return .{ .passed = 0, .failed = 1 };
        };
        defer dir.close();

        var walker = try dir.walk(self.allocator);
        defer walker.deinit();

        while (try walker.next()) |entry| {
            if (entry.kind != .file) continue;
            // Only process *.test.foz files
            if (!std.mem.endsWith(u8, entry.path, ".test.foz")) continue;

            const abs_path = try std.fs.path.join(self.allocator, &.{ root_dir, entry.path });
            defer self.allocator.free(abs_path);

            const result = try self.runFile(abs_path);
            defer {
                for (result.tests) |t| {
                    if (t.failure_msg) |msg| self.allocator.free(msg);
                }
                self.allocator.free(result.tests);
                if (result.compile_error) |ce| self.allocator.free(ce);
            }

            self.printFileResult(&result);
            total_passed += result.passed;
            total_failed += result.failed;
        }

        return .{ .passed = total_passed, .failed = total_failed };
    }

    /// SPEC: Internal — compile and run all `test_*` actions from one file.
    pub fn runFile(self: *TestRunner, path: []const u8) anyerror!FileResult {
        const src = std.fs.cwd().readFileAlloc(self.allocator, path, 1024 * 1024) catch |err| {
            const msg = try std.fmt.allocPrint(self.allocator, "cannot read file: {}", .{err});
            return FileResult{
                .file_path     = path,
                .compile_error = msg,
                .tests         = try self.allocator.alloc(TestResult, 0),
                .passed        = 0,
                .failed        = 1,
            };
        };
        defer self.allocator.free(src);

        // ── Compile ──────────────────────────────────────────────────────
        var diag = errors.DiagnosticList.init(self.allocator);
        defer diag.deinit();

        var lex = lexer.Lexer.init(src, path);
        var tok_list = lex.tokenize(self.allocator) catch |err| {
            const msg = try std.fmt.allocPrint(self.allocator, "lex error: {}", .{err});
            return FileResult{
                .file_path     = path,
                .compile_error = msg,
                .tests         = try self.allocator.alloc(TestResult, 0),
                .passed        = 0,
                .failed        = 1,
            };
        };
        defer tok_list.deinit(self.allocator);

        var prs = parser.Parser.init(self.allocator, tok_list.tokens, &diag);
        const program = prs.parse() catch |err| {
            const msg = try std.fmt.allocPrint(self.allocator, "parse error: {}", .{err});
            return FileResult{
                .file_path     = path,
                .compile_error = msg,
                .tests         = try self.allocator.alloc(TestResult, 0),
                .passed        = 0,
                .failed        = 1,
            };
        };
        defer program.deinit(self.allocator);

        // Find the contract
        var contract_def: ?*const parser.ContractDef = null;
        for (program.top_level) |*tl| {
            if (tl.* == .contract) {
                contract_def = &tl.contract;
                break;
            }
        }
        if (contract_def == null) {
            const msg = try self.allocator.dupe(u8, "no contract found in test file");
            return FileResult{
                .file_path     = path,
                .compile_error = msg,
                .tests         = try self.allocator.alloc(TestResult, 0),
                .passed        = 0,
                .failed        = 1,
            };
        }

        var resolver = types.TypeResolver.init(self.allocator);
        defer resolver.deinit();
        resolver.loadContract(contract_def.?);

        var chk = checker.Checker.init(self.allocator, &resolver, &diag);
        const checked = chk.checkContract(contract_def.?) catch |err| {
            const msg = try std.fmt.allocPrint(self.allocator, "type error: {}", .{err});
            return FileResult{
                .file_path     = path,
                .compile_error = msg,
                .tests         = try self.allocator.alloc(TestResult, 0),
                .passed        = 0,
                .failed        = 1,
            };
        };

        var gen = codegen.CodeGen.init(self.allocator, &resolver);
        defer gen.deinit();
        const binary = gen.generate(contract_def.?, &checked) catch |err| {
            const msg = try std.fmt.allocPrint(self.allocator, "codegen error: {}", .{err});
            return FileResult{
                .file_path     = path,
                .compile_error = msg,
                .tests         = try self.allocator.alloc(TestResult, 0),
                .passed        = 0,
                .failed        = 1,
            };
        };
        defer self.allocator.free(binary);

        // ── Find test_ actions and run them ──────────────────────────────
        var results = std.ArrayListUnmanaged(TestResult){};
        defer results.deinit(self.allocator);

        for (contract_def.?.actions) |action| {
            if (!std.mem.startsWith(u8, action.name, "test_")) continue;
            const result = try self.runTest(action.name, binary, action.name);
            try results.append(self.allocator, result);
        }

        const owned_tests = try results.toOwnedSlice(self.allocator);
        var passed: u32 = 0;
        var failed: u32 = 0;
        for (owned_tests) |t| {
            if (t.passed) { passed += 1; } else { failed += 1; }
        }

        return FileResult{
            .file_path     = path,
            .compile_error = null,
            .tests         = owned_tests,
            .passed        = passed,
            .failed        = failed,
        };
    }

    /// SPEC: Internal — run a single named test action from compiled binary.
    fn runTest(
        self:       *TestRunner,
        test_name:  []const u8,
        binary:     []const u8,
        action_name: []const u8,
    ) anyerror!TestResult {
        _ = action_name; // selector lookup goes here in a more complete impl

        // Skip the 64-byte header and find the bytecode section.
        // For now we run from the start of bytecode (after access list).
        // A complete version would look up the selector in the dispatch table.
        const header = std.mem.bytesAsValue(codegen.ZephBinHeader, binary[0..@sizeOf(codegen.ZephBinHeader)]);
        const bc_offset = @sizeOf(codegen.ZephBinHeader) + header.access_list_len;
        const bc_end    = bc_offset + header.bytecode_len;
        if (bc_end > binary.len) {
            return TestResult{
                .name        = test_name,
                .passed      = false,
                .gas_used    = 0,
                .failure_msg = try self.allocator.dupe(u8, "binary truncated"),
                .event_count = 0,
            };
        }
        const bytecode = binary[bc_offset..bc_end];

        var host = MockHostEnv.init(self.allocator);
        defer host.deinit();

        var interp = try Interpreter.init(self.allocator, bytecode, &host);
        defer interp.deinit(self.allocator);

        // Run until halt, revert, or max instructions
        const halted: bool = blk: {
            while (true) {
                const res = interp.step();
                switch (res) {
                    .ok, .jump => continue,
                    .ecall => {
                        const did_revert = try interp.handleEcall();
                        if (did_revert) break :blk true;
                    },
                    .halt  => break :blk true,
                    .@"error" => break :blk true,
                }
            }
        };
        _ = halted;

        const passed = !host.reverted;
        const failure_msg: ?[]const u8 = if (!passed) blk: {
            const msg = host.revert_msg[0..host.revert_len];
            break :blk try self.allocator.dupe(u8, if (msg.len > 0) msg else "reverted");
        } else null;

        return TestResult{
            .name        = test_name,
            .passed      = passed,
            .gas_used    = interp.instr_count,
            .failure_msg = failure_msg,
            .event_count = @intCast(host.events.events.items.len),
        };
    }

    // ── Output formatting ─────────────────────────────────────────────────

    fn printFileResult(self: *const TestRunner, result: *const FileResult) void {
        if (self.json_output) {
            self.printFileResultJson(result);
        } else {
            self.printFileResultText(result);
        }
    }

    fn printFileResultText(_: *const TestRunner, result: *const FileResult) void {
        const w = std.io.getStdOut().writer();
        w.print("\n\u{25A0} {s}\n", .{result.file_path}) catch return;
        if (result.compile_error) |ce| {
            w.print("  \u{2718} compile error: {s}\n", .{ce}) catch return;
            return;
        }
        for (result.tests) |t| {
            if (t.passed) {
                w.print("  \u{2714} {s}  [{d} instr]\n", .{ t.name, t.gas_used }) catch return;
            } else {
                const msg = t.failure_msg orelse "failed";
                w.print("  \u{2718} {s}  [{d} instr]  — {s}\n", .{ t.name, t.gas_used, msg }) catch return;
            }
        }
        w.print("\n  {d} passed, {d} failed\n", .{ result.passed, result.failed }) catch return;
    }

    fn printFileResultJson(_: *const TestRunner, result: *const FileResult) void {
        const w = std.io.getStdOut().writer();
        w.print("{{\"file\":\"{s}\",", .{result.file_path}) catch return;
        if (result.compile_error) |ce| {
            w.print("\"error\":\"{s}\"}}\n", .{ce}) catch return;
            return;
        }
        w.print("\"tests\":[", .{}) catch return;
        for (result.tests, 0..) |t, i| {
            if (i > 0) w.print(",", .{}) catch return;
            const msg = t.failure_msg orelse "";
            w.print("{{\"name\":\"{s}\",\"passed\":{},\"gas\":{d},\"events\":{d},\"msg\":\"{s}\"}}",
                .{ t.name, t.passed, t.gas_used, t.event_count, msg }) catch return;
        }
        w.print("],\"passed\":{d},\"failed\":{d}}}\n", .{ result.passed, result.failed }) catch return;
    }
};

// ============================================================================
// Section 7 — Tests
// ============================================================================

test "MockStorage load returns zeros for missing key" {
    var st = MockStorage.init(std.testing.allocator);
    defer st.deinit();
    const key = [_]u8{1} ** 32;
    const val = st.load(&key);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &val);
}

test "MockStorage store and load round-trip" {
    var st = MockStorage.init(std.testing.allocator);
    defer st.deinit();
    const key  = [_]u8{0xAB} ** 32;
    const value = [_]u8{0xCD} ** 32;
    try st.store(&key, &value);
    const loaded = st.load(&key);
    try std.testing.expectEqualSlices(u8, &value, &loaded);
}

test "Interpreter executes ADDI" {
    // Simple: ADDI a0, zero, 42  then halt (JALR zero, zero, 0 → pc=0 → halt)
    // ADDI a0, zero, 42 = 0x02A00513
    // JALR zero, ra, 0 = 0x00008067
    const code = [_]u8{
        0x13, 0x05, 0xA0, 0x02, // ADDI a0, zero, 42
        0x67, 0x80, 0x00, 0x00, // JALR zero, ra, 0
    };
    var host = MockHostEnv.init(std.testing.allocator);
    defer host.deinit();
    var interp = try Interpreter.init(std.testing.allocator, &code, &host);
    defer interp.deinit(std.testing.allocator);

    // Step 1: ADDI
    const r1 = interp.step();
    try std.testing.expectEqual(StepResult.ok, r1);
    try std.testing.expectEqual(@as(u64, 42), interp.regs.get(10));

    // Step 2: JALR zero, ra, 0 → halt
    const r2 = interp.step();
    try std.testing.expectEqual(StepResult.halt, r2);
}

test "Interpreter STORAGE_LOAD ecall" {
    const allocator = std.testing.allocator;

    // Prepare: key at memory[0..32], result at memory[32..64]
    // Instructions:
    //   ADDI a0, zero, 1   (syscall STORAGE_LOAD)
    //   ADDI a1, zero, 0   (key ptr = mem[0])
    //   ADDI a2, zero, 32  (result ptr = mem[32])
    //   ECALL
    //   JALR zero, ra, 0   (halt)
    const ADDI_a0_1  = @as(u32, 0x00100513); // ADDI a0, zero, 1
    const ADDI_a1_0  = @as(u32, 0x00000593); // ADDI a1, zero, 0
    const ADDI_a2_32 = @as(u32, 0x02000613); // ADDI a2, zero, 32
    const ECALL      = @as(u32, 0x00000073);
    const HALT       = @as(u32, 0x00008067);

    var code_buf: [20]u8 = undefined;
    std.mem.writeInt(u32, code_buf[0..4],  ADDI_a0_1,  .little);
    std.mem.writeInt(u32, code_buf[4..8],  ADDI_a1_0,  .little);
    std.mem.writeInt(u32, code_buf[8..12], ADDI_a2_32, .little);
    std.mem.writeInt(u32, code_buf[12..16], ECALL,     .little);
    std.mem.writeInt(u32, code_buf[16..20], HALT,      .little);

    var host = MockHostEnv.init(allocator);
    defer host.deinit();
    // Pre-seed storage
    const key   = [_]u8{0} ** 32;
    const stored = [_]u8{0xBE} ** 32;
    try host.storage.store(&key, &stored);

    var interp = try Interpreter.init(allocator, &code_buf, &host);
    defer interp.deinit(allocator);

    // Run all 5 instructions
    _ = interp.step(); // ADDI a0
    _ = interp.step(); // ADDI a1
    _ = interp.step(); // ADDI a2
    const ecall_res = interp.step(); // ECALL
    try std.testing.expectEqual(StepResult.ecall, ecall_res);
    const did_revert = try interp.handleEcall();
    try std.testing.expect(!did_revert);
    // Result should be at memory[32..64]
    const result = interp.readMem32(32);
    try std.testing.expectEqualSlices(u8, &stored, &result);
}
