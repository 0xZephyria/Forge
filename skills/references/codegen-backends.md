# Codegen Backends Reference — RISC-V, EVM, PolkaVM, ABI

## RISC-V RV64IM Emitter (codegen.zig)

### Instruction Encoding Helpers

```zig
// R-type: funct7 | rs2 | rs1 | funct3 | rd | opcode
pub fn rv_r(funct7: u7, rs2: Reg, rs1: Reg, funct3: u3, rd: Reg, opcode: u7) u32 {
    return (@as(u32, funct7) << 25) | (@as(u32, @intFromEnum(rs2)) << 20) |
           (@as(u32, @intFromEnum(rs1)) << 15) | (@as(u32, funct3) << 12) |
           (@as(u32, @intFromEnum(rd)) << 7) | opcode;
}
// I-type: imm[11:0] | rs1 | funct3 | rd | opcode
pub fn rv_i(imm: i12, rs1: Reg, funct3: u3, rd: Reg, opcode: u7) u32 {
    const u_imm: u12 = @bitCast(imm);
    return (@as(u32, u_imm) << 20) | (@as(u32, @intFromEnum(rs1)) << 15) |
           (@as(u32, funct3) << 12) | (@as(u32, @intFromEnum(rd)) << 7) | opcode;
}
// S-type: imm[11:5] | rs2 | rs1 | funct3 | imm[4:0] | opcode
pub fn rv_s(imm: i12, rs2: Reg, rs1: Reg, funct3: u3, opcode: u7) u32 {
    const u_imm: u12 = @bitCast(imm);
    return (@as(u32, u_imm >> 5) << 25) | (@as(u32, @intFromEnum(rs2)) << 20) |
           (@as(u32, @intFromEnum(rs1)) << 15) | (@as(u32, funct3) << 12) |
           (@as(u32, u_imm & 0x1F) << 7) | opcode;
}
// B-type: imm[12,10:5] | rs2 | rs1 | funct3 | imm[4:1,11] | opcode
pub fn rv_b(imm: i13, rs2: Reg, rs1: Reg, funct3: u3, opcode: u7) u32 {
    const u_imm: u13 = @bitCast(imm);
    return ((@as(u32, u_imm >> 12) & 1) << 31) |
           ((@as(u32, u_imm >> 5) & 0x3F) << 25) |
           (@as(u32, @intFromEnum(rs2)) << 20) |
           (@as(u32, @intFromEnum(rs1)) << 15) |
           (@as(u32, funct3) << 12) |
           (((@as(u32, u_imm >> 1) & 0xF) << 8) |
            ((@as(u32, u_imm >> 11) & 1) << 7)) |
           opcode;
}

// Common instructions
pub fn rv_add(rd: Reg, rs1: Reg, rs2: Reg) u32 { return rv_r(0,rs2,rs1,0,rd,0x33); }
pub fn rv_sub(rd: Reg, rs1: Reg, rs2: Reg) u32 { return rv_r(0x20,rs2,rs1,0,rd,0x33); }
pub fn rv_mul(rd: Reg, rs1: Reg, rs2: Reg) u32 { return rv_r(1,rs2,rs1,0,rd,0x33); }
pub fn rv_addi(rd: Reg, rs1: Reg, imm: i12) u32 { return rv_i(imm,rs1,0,rd,0x13); }
pub fn rv_ld(rd: Reg, rs1: Reg, imm: i12) u32   { return rv_i(imm,rs1,3,rd,0x03); }  // 64-bit load
pub fn rv_sd(rs2: Reg, rs1: Reg, imm: i12) u32  { return rv_s(imm,rs2,rs1,3,0x23); } // 64-bit store
pub fn rv_beq(rs1: Reg, rs2: Reg, imm: i13) u32 { return rv_b(imm,rs2,rs1,0,0x63); }
pub fn rv_bne(rs1: Reg, rs2: Reg, imm: i13) u32 { return rv_b(imm,rs2,rs1,1,0x63); }
pub fn rv_blt(rs1: Reg, rs2: Reg, imm: i13) u32 { return rv_b(imm,rs2,rs1,4,0x63); }
pub fn rv_bge(rs1: Reg, rs2: Reg, imm: i13) u32 { return rv_b(imm,rs2,rs1,5,0x63); }
pub fn rv_jalr(rd: Reg, rs1: Reg, imm: i12) u32 { return rv_i(imm,rs1,0,rd,0x67); }
pub fn rv_ecall() u32 { return 0x00000073; }
pub fn rv_ebreak() u32 { return 0x00100073; }

pub const Reg = enum(u5) {
    zero=0,ra=1,sp=2,gp=3,tp=4,
    t0=5,t1=6,t2=7,
    s0=8,s1=9,
    a0=10,a1=11,a2=12,a3=13,a4=14,a5=15,a6=16,a7=17,
    s2=18,s3=19,s4=20,s5=21,s6=22,s7=23,s8=24,s9=25,s10=26,s11=27,
    t3=28,t4=29,t5=30,t6=31,
};
```

### Action Prologue / Epilogue Pattern

```zig
pub fn emitActionPrologue(self: *CodegenCtx, action: ActionDecl) !void {
    const frame_size: i12 = 16; // ra + s0 = 2 × 8 bytes; expand for more locals
    try self.emit(rv_addi(.sp, .sp, -frame_size));
    try self.emit(rv_sd(.ra, .sp, frame_size - 8));
    try self.emit(rv_sd(.s0, .sp, frame_size - 16));
    try self.emit(rv_addi(.s0, .sp, frame_size));
    // Charge entry gas
    try self.emitGasCharge(self.gas_table.actionEntry(action.name));
}

pub fn emitActionEpilogue(self: *CodegenCtx, frame_size: i12) !void {
    try self.emit(rv_ld(.ra, .sp, frame_size - 8));
    try self.emit(rv_ld(.s0, .sp, frame_size - 16));
    try self.emit(rv_addi(.sp, .sp, frame_size));
    try self.emit(rv_jalr(.zero, .ra, 0));   // ret
}

pub fn emitRevert(self: *CodegenCtx, reason_ptr: Reg, reason_len: Reg) !void {
    // SYSCALL_REVERT = 0x10 (ForgeVM syscall number)
    try self.emit(rv_addi(.a7, .zero, 0x10));
    if (reason_ptr != .a0) try self.emit(rv_add(.a0, reason_ptr, .zero));
    if (reason_len  != .a1) try self.emit(rv_add(.a1, reason_len,  .zero));
    try self.emit(rv_ecall());
}
```

### SYSCALL Table (ForgeVM reserved numbers)

```zig
pub const SYSCALL = struct {
    pub const RETURN         = 0x00;
    pub const REVERT         = 0x10;
    pub const STORAGE_LOAD   = 0x20;
    pub const STORAGE_STORE  = 0x21;
    pub const LOG_EVENT      = 0x30;
    pub const GET_CALLER     = 0x40;
    pub const GET_VALUE      = 0x41;
    pub const GET_TIMESTAMP  = 0x42;
    pub const GET_BLOCK      = 0x43;
    pub const GET_THIS       = 0x44;
    pub const TRANSFER_NATIVE= 0x50;
    pub const CREATE_ACCOUNT = 0x60;
    pub const CALL_CONTRACT  = 0x70;
    pub const DELEGATE_CALL  = 0x71;
    pub const STATIC_CALL    = 0x72;
    pub const BLAKE3         = 0x81;
    pub const KECCAK256_LEGACY = 0x80;
    pub const VRF_RANDOM     = 0x100;  // pending
    pub const ORACLE_READ    = 0x101;  // pending
    pub const DELEGATE_GAS   = 0x102;  // pending (gas sponsorship)
    pub const ZK_VERIFY      = 0x103;  // pending
    pub const SCHEDULE_CALL  = 0x104;  // pending
    pub const GOV_CHECK      = 0x105;  // pending
};
```

---

## EVM Codegen (codegen_evm.zig)

### EVM Push helpers

```zig
pub fn evmPush(self: *EvmCtx, value: u256) !void {
    // Determine minimal byte width
    var bytes: [32]u8 = @bitCast(@byteSwap(value));
    var len: u8 = 32;
    while (len > 1 and bytes[32 - len] == 0) len -= 1;
    try self.buf.append(self.allocator, 0x5F + len);  // PUSH1..PUSH32
    try self.buf.appendSlice(self.allocator, bytes[32 - len ..]);
}

pub fn evmPushSelector(self: *EvmCtx, action: ActionDecl) !void {
    const sel = computeSelector(action);
    try self.buf.append(self.allocator, 0x63);  // PUSH4
    try self.buf.appendSlice(self.allocator, &sel);
}

pub fn computeSelector(action: ActionDecl) [4]u8 {
    // Build signature: "transfer(address,uint256)"
    var sig = std.ArrayList(u8).init(std.heap.page_allocator);
    defer sig.deinit();
    sig.appendSlice(action.name) catch unreachable;
    sig.append('(') catch unreachable;
    for (action.params, 0..) |p, i| {
        if (i > 0) sig.append(',') catch unreachable;
        sig.appendSlice(typeToAbiString(p.typ)) catch unreachable;
    }
    sig.append(')') catch unreachable;
    var h: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(sig.items, &h, .{});
    return h[0..4].*;
}

pub fn typeToAbiString(t: ResolvedType) []const u8 {
    return switch (t) {
        .u8   => "uint8",   .u16 => "uint16",  .u32  => "uint32",
        .u64  => "uint64",  .u128 => "uint128", .u256,.uint => "uint256",
        .i8   => "int8",    .i16 => "int16",   .i32  => "int32",
        .i64  => "int64",   .i128 => "int128",  .i256,.int => "int256",
        .bool => "bool",
        .account,.wallet,.program,.system => "address",
        .hash,.bytes32,.commitment => "bytes32",
        .bytes => "bytes",
        .string => "string",
        .fixed,.price9,.price18,.percent => "uint256",  // encoded as fixed-point integer
        .timestamp,.duration,.block_number,.epoch => "uint64",
        .tuple => |ts| blk: {
            // (T1,T2,...) — encode as tuple ABI type
            _ = ts;
            break :blk "tuple";
        },
        else => "bytes",  // fallback
    };
}
```

### Event Emission (EVM)

```zig
pub fn emitTellStmt(self: *EvmCtx, tell: TellStmt, event: EventDecl) !void {
    // Separate indexed and non-indexed fields
    var indexed: std.ArrayList(EventField) = .init(self.allocator);
    var data_fields: std.ArrayList(EventField) = .init(self.allocator);
    defer indexed.deinit();
    defer data_fields.deinit();
    for (event.fields) |f| {
        if (f.indexed) try indexed.append(f) else try data_fields.append(f);
    }

    // Encode data (non-indexed) into memory at 0x00
    var data_offset: u256 = 0;
    for (tell.args, 0..) |arg, i| {
        if (!event.fields[i].indexed) {
            try self.emitExpr(arg);
            try self.evmPush(data_offset);
            try self.buf.append(self.allocator, 0x52); // MSTORE
            data_offset += 32;
        }
    }

    // Push memory size + offset for LOG
    try self.evmPush(data_offset);   // size
    try self.evmPush(0);             // offset

    // Push topic hashes (indexed fields + event signature)
    // Topic 0 = keccak256("EventName(type1,type2,...)")
    const event_sig_hash = computeEventTopicHash(event);
    try self.evmPush(@byteSwap(@as(u256, @bitCast(event_sig_hash))));

    // Topics 1–3: indexed field values
    for (tell.args, 0..) |arg, i| {
        if (event.fields[i].indexed) {
            try self.emitExpr(arg);
            // address types must be padded: AND with address mask
            if (isAddressType(event.fields[i].typ)) {
                try self.evmPush(0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
                try self.buf.append(self.allocator, 0x16); // AND
            }
        }
    }

    // LOG0..LOG4 opcode based on total topic count
    const n_topics = 1 + indexed.items.len; // 1 for signature
    try self.buf.append(self.allocator, 0xA0 + @as(u8, @intCast(n_topics)));
}
```

---

## ABI Encoding (abi.zig)

```zig
pub fn encodeAbi(allocator: std.mem.Allocator, contract: ContractDef) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    try buf.appendSlice("[\n");

    // Encode each action
    for (contract.actions) |action| {
        try buf.appendSlice("  {\n");
        try buf.appendSlice("    \"type\": \"function\",\n");
        try buf.writer().print("    \"name\": \"{s}\",\n", .{action.name});
        // Inputs
        try buf.appendSlice("    \"inputs\": [\n");
        for (action.params, 0..) |p, i| {
            try buf.writer().print(
                "      {{\"name\": \"{s}\", \"type\": \"{s}\"}}",
                .{ p.name, typeToAbiString(try resolveTypeExpr(p.type_expr)) });
            if (i < action.params.len - 1) try buf.append(',');
            try buf.append('\n');
        }
        try buf.appendSlice("    ],\n");
        // Outputs
        if (action.return_type) |rt| {
            try buf.writer().print(
                "    \"outputs\": [{{\"name\": \"\", \"type\": \"{s}\"}}],\n",
                .{typeToAbiString(try resolveTypeExpr(rt))});
        } else {
            try buf.appendSlice("    \"outputs\": [],\n");
        }
        try buf.appendSlice("    \"stateMutability\": \"nonpayable\"\n");
        // Novel: complexity class
        if (action.complexity_class) |cc| {
            try buf.writer().print("    ,\"x_forge_complexity\": \"{s}\"\n",
                .{ complexityToString(cc) });
        }
        try buf.appendSlice("  },\n");
    }

    // Encode events
    for (contract.events) |event| {
        try buf.appendSlice("  {\n");
        try buf.appendSlice("    \"type\": \"event\",\n");
        try buf.writer().print("    \"name\": \"{s}\",\n", .{event.name});
        try buf.appendSlice("    \"inputs\": [\n");
        for (event.fields, 0..) |f, i| {
            try buf.writer().print(
                "      {{\"name\": \"{s}\", \"type\": \"{s}\", \"indexed\": {s}}}",
                .{ f.name, typeToAbiString(try resolveTypeExpr(f.type_expr)),
                   if (f.indexed) "true" else "false" });
            if (i < event.fields.len - 1) try buf.append(',');
            try buf.append('\n');
        }
        try buf.appendSlice("    ]\n  },\n");
    }

    // Encode errors
    for (contract.errors) |err| {
        try buf.appendSlice("  {\n    \"type\": \"error\",\n");
        try buf.writer().print("    \"name\": \"{s}\",\n    \"inputs\": [\n", .{err.name});
        for (err.fields, 0..) |f, i| {
            try buf.writer().print(
                "      {{\"name\": \"{s}\", \"type\": \"{s}\"}}",
                .{ f.name, typeToAbiString(try resolveTypeExpr(f.type_expr)) });
            if (i < err.fields.len - 1) try buf.append(',');
            try buf.append('\n');
        }
        try buf.appendSlice("    ]\n  },\n");
    }

    // Remove trailing comma and close
    if (buf.items[buf.items.len - 2] == ',')
        buf.items.len -= 2;
    try buf.appendSlice("\n]\n");
    return buf.toOwnedSlice();
}
```

---

## Gas Table (gas/table.zig)

```zig
pub const GasTable = struct {
    pub const ACTION_ENTRY:    u64 = 21_000;
    pub const STORAGE_LOAD:    u64 = 2_100;   // cold
    pub const STORAGE_LOAD_WARM: u64 = 100;
    pub const STORAGE_STORE:   u64 = 20_000;  // cold, dirty
    pub const STORAGE_STORE_WARM: u64 = 100;
    pub const LOG_BASE:        u64 = 375;
    pub const LOG_PER_TOPIC:   u64 = 375;
    pub const LOG_PER_BYTE:    u64 = 8;
    pub const CALL_BASE:       u64 = 100;
    pub const CALL_VALUE_SURCHARGE: u64 = 9_000;
    pub const CREATE:          u64 = 32_000;
    pub const KECCAK256_BASE:  u64 = 30;
    pub const KECCAK256_WORD:  u64 = 6;
    pub const COPY_PER_WORD:   u64 = 3;
    pub const ECRECOVER:       u64 = 3_000;
    pub const ORACLE_READ:     u64 = 5_000;   // ForgeVM custom
    pub const VRF_RANDOM:      u64 = 10_000;  // ForgeVM custom
    pub const ZK_VERIFY:       u64 = 150_000; // ForgeVM custom
    pub const SCHEDULE_CALL:   u64 = 25_000;  // ForgeVM custom

    pub fn opCost(op: RvOpcode) u64 {
        return switch (op) {
            .add,.sub,.and_op,.or_op,.xor,.not => 3,
            .mul                               => 5,
            .div,.mod                          => 5,
            .storage_load                      => STORAGE_LOAD,
            .storage_store                     => STORAGE_STORE,
            .blake3                            => BLAKE3_BASE,
            .call                              => CALL_BASE,
            .create                            => CREATE,
            else                               => 1,
        };
    }
};
```
