# ZephyriaVM Runtime Reference — executor.zig, decoder.zig, sandbox.zig, gas/

## VM Architecture

```zig
// executor.zig — main execution entry point
pub const Vm = struct {
    // Core state
    pc:       u64 = 0,
    regs:     [32]u64 = std.mem.zeroes([32]u64),  // x0..x31; x0 always 0
    memory:   []u8,                                // sandbox memory
    // Forge-specific overlays
    storage:  *StorageDB,
    gas:      GasTracker,
    calldata: []const u8,
    return_data: []u8,
    logs:     std.ArrayListUnmanaged(Log),
    // Execution state
    halted:   bool = false,
    reverted: bool = false,
    allocator: std.mem.Allocator,
    // Context (injected per-call)
    ctx:      ExecContext,

    // Register ABI — NEVER clobber a5 (gas) or a6 (calldata base)
    pub const GAS_REG  = 15;  // a5
    pub const CD_REG   = 16;  // a6 = calldata base ptr

    pub fn init(allocator: std.mem.Allocator, mem_size: usize, storage: *StorageDB) !Vm {
        const mem = try allocator.alloc(u8, mem_size);
        return Vm{
            .memory   = mem,
            .storage  = storage,
            .gas      = GasTracker{ .limit = 0, .used = 0 },
            .calldata = &.{},
            .return_data = &.{},
            .logs     = .{},
            .ctx      = std.mem.zeroes(ExecContext),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Vm) void {
        self.allocator.free(self.memory);
        self.logs.deinit(self.allocator);
    }

    pub fn execute(self: *Vm) !ExecResult {
        // Set gas register from GasTracker
        self.regs[GAS_REG] = self.gas.limit - self.gas.used;

        while (!self.halted and self.pc < self.memory.len) {
            const instr = self.fetchInstruction() catch |e| switch (e) {
                error.PcOutOfBounds => return self.makeResult(.invalid),
                else => return e,
            };
            try self.executeInstruction(instr);
            // Sync gas used from register
            const gas_remaining = self.regs[GAS_REG];
            if (gas_remaining > self.gas.limit) {
                // Underflow: out of gas
                return self.makeResult(.oog);
            }
            self.gas.used = self.gas.limit - gas_remaining;
        }

        return self.makeResult(if (self.reverted) .revert else .success);
    }
};
```

## Instruction Decoder (decoder.zig)

```zig
pub const DecodedInstr = union(enum) {
    // R-type
    add:   RType, sub:   RType, mul:   RType,
    div:   RType, rem:   RType, and_r: RType,
    or_r:  RType, xor_r: RType, sll:   RType,
    srl:   RType, sra:   RType, sltu:  RType,
    // I-type
    addi:  IType, andi:  IType, ori:   IType,
    xori:  IType, slli:  IType, srli:  IType,
    srai:  IType, slti:  IType, sltiu: IType,
    ld:    IType, lw:    IType, lh:    IType, lb: IType,
    jalr:  IType,
    // S-type
    sd:    SType, sw:    SType, sh:    SType, sb: SType,
    // B-type
    beq:   BType, bne:   BType, blt:   BType,
    bge:   BType, bltu:  BType, bgeu:  BType,
    // U-type
    lui:   UType, auipc: UType,
    // J-type
    jal:   JType,
    // System
    ecall:  void,
    ebreak: void,
    // 32-bit word-sized versions (RV64: W suffix)
    addw:  RType, subw: RType, mulw: RType,
    divw:  RType, remw: RType,
    addiw: IType, slliw: IType, srliw: IType, sraiw: IType,

    pub fn decode(word: u32) !DecodedInstr {
        const opcode: u7 = @truncate(word & 0x7F);
        return switch (opcode) {
            0x33 => decodeRType(word),    // OP
            0x3B => decodeRType32(word),  // OP-32 (W suffix)
            0x13 => decodeITypeArith(word),
            0x1B => decodeITypeArith32(word),
            0x03 => decodeITypeLoad(word),
            0x67 => .{ .jalr = decodeI(word) },
            0x23 => decodeSType(word),
            0x63 => decodeBType(word),
            0x37 => .{ .lui   = decodeU(word) },
            0x17 => .{ .auipc = decodeU(word) },
            0x6F => .{ .jal   = decodeJ(word) },
            0x73 => if (word == 0x00000073) .ecall
                    else if (word == 0x00100073) .ebreak
                    else error.InvalidInstruction,
            else => error.InvalidInstruction,
        };
    }
};

pub const RType = struct { rd: u5, rs1: u5, rs2: u5 };
pub const IType = struct { rd: u5, rs1: u5, imm: i12 };
pub const SType = struct { rs1: u5, rs2: u5, imm: i12 };
pub const BType = struct { rs1: u5, rs2: u5, imm: i13 };
pub const UType = struct { rd: u5, imm: i20 };
pub const JType = struct { rd: u5, imm: i21 };
```

## Execution Dispatch (executor.zig)

```zig
pub fn executeInstruction(self: *Vm, instr: DecodedInstr) !void {
    switch (instr) {
        .add  => |r| self.regs[r.rd] = self.regs[r.rs1] +% self.regs[r.rs2],
        .sub  => |r| self.regs[r.rd] = self.regs[r.rs1] -% self.regs[r.rs2],
        .mul  => |r| self.regs[r.rd] = self.regs[r.rs1] *% self.regs[r.rs2],
        .div  => |r| {
            if (self.regs[r.rs2] == 0) { self.regs[r.rd] = std.math.maxInt(u64); return; }
            const a: i64 = @bitCast(self.regs[r.rs1]);
            const b: i64 = @bitCast(self.regs[r.rs2]);
            self.regs[r.rd] = @bitCast(@divTrunc(a, b));
        },
        .addi => |i| self.regs[i.rd] = self.regs[i.rs1] +% @as(u64, @bitCast(@as(i64, i.imm))),
        .ld   => |i| {
            const addr = self.regs[i.rs1] +% @as(u64, @bitCast(@as(i64, i.imm)));
            self.regs[i.rd] = try self.memLoad64(addr);
        },
        .sd   => |s| {
            const addr = self.regs[s.rs1] +% @as(u64, @bitCast(@as(i64, s.imm)));
            try self.memStore64(addr, self.regs[s.rs2]);
        },
        .beq  => |b| if (self.regs[b.rs1] == self.regs[b.rs2])
                        self.pc +%= @as(u64, @bitCast(@as(i64, b.imm))),
        .bne  => |b| if (self.regs[b.rs1] != self.regs[b.rs2])
                        self.pc +%= @as(u64, @bitCast(@as(i64, b.imm))),
        .blt  => |b| {
            const a: i64 = @bitCast(self.regs[b.rs1]);
            const c: i64 = @bitCast(self.regs[b.rs2]);
            if (a < c) self.pc +%= @as(u64, @bitCast(@as(i64, b.imm)));
        },
        .jal  => |j| {
            self.regs[j.rd] = self.pc + 4;
            self.pc +%= @as(u64, @bitCast(@as(i64, j.imm)));
            return;  // skip normal pc += 4
        },
        .jalr => |i| {
            const ret = self.pc + 4;
            self.pc = (self.regs[i.rs1] +% @as(u64, @bitCast(@as(i64, i.imm)))) & ~@as(u64, 1);
            self.regs[i.rd] = ret;
            return;
        },
        .ecall  => try self.handleSyscall(),
        .ebreak => self.halted = true,
        else => {},  // remaining instructions follow same pattern
    }
    // x0 is always zero
    self.regs[0] = 0;
    // Normal increment
    self.pc += 4;
}
```

## Syscall Handler (sandbox.zig)

```zig
pub fn handleSyscall(self: *Vm) !void {
    const number = self.regs[17]; // a7 = syscall number
    switch (number) {
        SYSCALL.RETURN => {
            const ptr = self.regs[10];  // a0
            const len = self.regs[11];  // a1
            self.return_data = try self.memSlice(ptr, len);
            self.halted = true;
        },
        SYSCALL.REVERT => {
            const ptr = self.regs[10];
            const len = self.regs[11];
            self.return_data = try self.memSlice(ptr, len);
            self.reverted = true;
            self.halted   = true;
        },
        SYSCALL.STORAGE_LOAD => {
            // a0 = key ptr (32 bytes), a1 = output ptr (32 bytes)
            const key_ptr = self.regs[10];
            const out_ptr = self.regs[11];
            const key: [32]u8 = self.memLoad32(key_ptr) catch return error.MemFault;
            const val = self.storage.load(self.ctx.contract, @byteSwap(@as(u256, @bitCast(key))));
            const val_bytes: [32]u8 = @bitCast(@byteSwap(val));
            try self.memStore32(out_ptr, val_bytes);
        },
        SYSCALL.STORAGE_STORE => {
            // a0 = key ptr, a1 = value ptr
            const key_bytes: [32]u8 = self.memLoad32(self.regs[10]) catch return error.MemFault;
            const val_bytes: [32]u8 = self.memLoad32(self.regs[11]) catch return error.MemFault;
            const key = @byteSwap(@as(u256, @bitCast(key_bytes)));
            const val = @byteSwap(@as(u256, @bitCast(val_bytes)));
            try self.gas.charge(GasTable.STORAGE_STORE);
            self.storage.store(self.ctx.contract, key, val);
        },
        SYSCALL.GET_CALLER => {
            // a0 = output ptr (32 bytes)
            try self.memStore32(self.regs[10], self.ctx.caller);
        },
        SYSCALL.GET_TIMESTAMP => {
            self.regs[10] = self.ctx.timestamp;
        },
        SYSCALL.GET_BLOCK => {
            self.regs[10] = self.ctx.block_num;
        },
        SYSCALL.LOG_EVENT => {
            // a0 = topics ptr (n × 32 bytes), a1 = n_topics, a2 = data ptr, a3 = data_len
            const n_topics = self.regs[11];
            if (n_topics > 4) return error.TooManyTopics;
            var topics: [4][32]u8 = std.mem.zeroes([4][32]u8);
            const topics_base = self.regs[10];
            for (0..n_topics) |i| {
                topics[i] = self.memLoad32(topics_base + i * 32) catch return error.MemFault;
            }
            const data_slice = try self.memSlice(self.regs[12], self.regs[13]);
            const data_copy  = try self.allocator.dupe(u8, data_slice);
            try self.gas.charge(GasTable.LOG_BASE + n_topics * GasTable.LOG_PER_TOPIC +
                                data_slice.len * GasTable.LOG_PER_BYTE);
            try self.logs.append(self.allocator, .{
                .address = self.ctx.contract,
                .topics  = topics,
                .data    = data_copy,
            });
        },
        else => return error.UnknownSyscall,
    }
}
```

## Gas Tracker (gas/meter.zig)

```zig
pub const GasTracker = struct {
    limit:   u64,
    used:    u64,
    refund:  u64 = 0,

    pub fn charge(self: *GasTracker, cost: u64) !void {
        const new_used, const overflow = @addWithOverflow(self.used, cost);
        if (overflow != 0 or new_used > self.limit) return error.OutOfGas;
        self.used = new_used;
    }

    pub fn remaining(self: *const GasTracker) u64 {
        return self.limit - self.used;
    }

    pub fn addRefund(self: *GasTracker, amount: u64) void {
        // Zephyria Gas Refund: cap at 20% of total gas used.
        const cap = self.used / 5;
        self.refund += @min(amount, cap);
    }

    pub fn applyRefund(self: *GasTracker) void {
        // Applied at transaction end
        const actual = @min(self.refund, self.used / 5);
        self.used -= actual;
        self.refund = 0;
    }

    pub fn toRegisterValue(self: *const GasTracker) u64 {
        return self.limit - self.used;
    }

    pub fn syncFromRegister(self: *GasTracker, reg_val: u64) void {
        if (reg_val > self.limit) {
            // Underflow in register means gas went negative → OOG
            self.used = self.limit + 1;
        } else {
            self.used = self.limit - reg_val;
        }
    }
};
```

## Memory Safety (sandbox.zig)

```zig
// All memory ops go through bounds-checked helpers
pub fn memLoad64(self: *const Vm, addr: u64) !u64 {
    const end = addr + 8;
    if (end > self.memory.len or addr > end) return error.MemFault;
    return std.mem.readInt(u64, self.memory[addr..][0..8], .little);
}

pub fn memStore64(self: *Vm, addr: u64, val: u64) !void {
    const end = addr + 8;
    if (end > self.memory.len or addr > end) return error.MemFault;
    std.mem.writeInt(u64, self.memory[addr..][0..8], val, .little);
}

pub fn memLoad32(self: *const Vm, addr: u64) ![32]u8 {
    const end = addr + 32;
    if (end > self.memory.len or addr > end) return error.MemFault;
    return self.memory[addr..][0..32].*;
}

pub fn memStore32(self: *Vm, addr: u64, val: [32]u8) !void {
    const end = addr + 32;
    if (end > self.memory.len or addr > end) return error.MemFault;
    @memcpy(self.memory[addr..][0..32], &val);
}

pub fn memSlice(self: *const Vm, addr: u64, len: u64) ![]const u8 {
    const end = addr + len;
    if (end > self.memory.len or addr > end) return error.MemFault;
    return self.memory[addr..][0..len];
}

// Stack pointer sanity check (prevent runaway stack growth)
pub fn checkStack(self: *const Vm) !void {
    const sp = self.regs[2]; // x2 = sp
    const STACK_TOP: u64  = 0x0006_FFF8;
    const STACK_BOTTOM: u64 = 0x0001_0000;
    if (sp > STACK_TOP or sp < STACK_BOTTOM) return error.StackOverflow;
}
```
