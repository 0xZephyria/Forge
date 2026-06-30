# EVM Compatibility & Legacy Primitives

These primitives are maintained for the `codegen_evm.zig` backend and for cross-chain bridging. They are **not** native to the Zephyria ZVM (RISC-V 64IM).

## 1. RLP Encoding (Recursive Length Prefix)
Standard EVM serialization for transactions and MPT nodes.
```zig
pub const Rlp = struct {
    pub fn encodeString(data: []const u8, out: *std.ArrayList(u8)) !void { ... }
    pub fn encodeList(items: []const []const u8, out: *std.ArrayList(u8)) !void { ... }
};
```

## 2. Compact Merkle Patricia Trie (MPT)
Used for state root, transaction root, and receipt root in EVM blockchains.
```zig
pub const Mpt = struct {
    nodes: std.AutoHashMap([32]u8, Node),
    pub fn rootHash(self: *Mpt, out: *[32]u8) !void {
        // Serialize root node -> RLP -> Keccak256
    }
};
```

## 3. Solidity Mapping Slot Calculation
Solidity flattens mapping storage by hashing the key and the base slot: `keccak256(key, slot)`.
```zig
pub fn mappingSlot(key_bytes: []const u8, base_slot: u256) [32]u8 {
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..key_bytes.len], key_bytes);
    const slot_be: [32]u8 = @bitCast(@byteSwap(base_slot));
    @memcpy(buf[32..], &slot_be);
    var out: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&buf, &out, .{});
    return out;
}
```

## 4. Keccak256 & EIP-55 Checksumming
```zig
pub fn addressToChecksum(addr: Address, out: []u8) void {
    // EIP-55 checksum encoding using Keccak256
    std.crypto.hash.sha3.Keccak256.hash(&hex_lower, &h, .{});
    // ... bit manipulation ...
}
```
