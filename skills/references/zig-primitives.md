# ZVM-Native Blockchain Primitives

These primitives are optimized for the **Zephyria ZVM (RISC-V 64IM)** and the Zephyria blockchain. For EVM compatibility (RLP, Keccak256, MPT), see [evm-compat.md](file:///Users/karan/forge/skills/references/evm-compat.md).

## 1. Blake3 Hashing (ZVM Syscall 0x81)
Blake3 is the primary hashing algorithm for Zephyria.
```zig
pub const Blake3 = struct {
    pub fn hash(data: []const u8, out: *[32]u8) void {
        // ZVM Hardware Accelerated Syscall
        // a7=0x81, a0=data_ptr, a1=data_len, a2=out_ptr
        asm volatile ("ecall"
            :
            : [sys] "{a7}" (0x81),
              [ptr] "{a0}" (@intFromPtr(data.ptr)),
              [len] "{a1}" (data.len),
              [out] "{a2}" (@intFromPtr(out))
            : "memory"
        );
    }
};
```

## 2. Structured State (Field-Based)
ZVM state is organized by Field IDs rather than a flat hashed keyspace.
```zig
pub const State = struct {
    pub fn read(field_id: u32, key: [32]u8) u256 {
        var out: [32]u8 = undefined;
        // a7=0x00 (STATE_READ), a0=field_id, a1=key_ptr, a2=out_ptr
        // ... syscall logic ...
        return @as(u256, @bitCast(out));
    }

    pub fn write(field_id: u32, key: [32]u8, val: u256) void {
        const val_bytes: [32]u8 = @bitCast(val);
        // a7=0x01 (STATE_WRITE), a0=field_id, a1=key_ptr, a2=val_ptr
    }
};
```

## 3. U256 Safe Math (64-bit Optimized)
Since ZVM is 64-bit RISC-V, U256 math is implemented as a sequence of 64-bit operations.
```zig
pub const SafeMath = struct {
    pub fn add(a: u256, b: u256) !u256 {
        const result, const overflow = @addWithOverflow(a, b);
        if (overflow != 0) return error.Overflow;
        return result;
    }
    // ... sub, mul, div, mod ...
};
```

## 4. Sparse Merkle Trees (SMT)
Zephyria uses SMTs for state commitment instead of Merkle Patricia Tries.
```zig
pub const Smt = struct {
    pub fn getProof(key: [32]u8) ![]const [32]u8 { ... }
    pub fn verifyProof(root: [32]u8, key: [32]u8, val: [32]u8, proof: [][32]u8) bool { ... }
};
```
