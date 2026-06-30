# Forge API — Compiler Flags, ABI, Keystore & RPC

## Compiler Flags (forge build)

```bash
# Build with optimizations
forge build --optimize ReleaseFast

# Cross-compile for Linux x86_64
forge build --target x86_64-linux-musl

# Output ABI JSON alongside bytecode
forge build --emit-abi

# Verify source on Zephyria Explorer
forge verify --rpc-url https://rpc.zephyria.io --contract src/Token.zig --address 0x...
```

## Project Config (forge.json)

```json
{
  "project": "my-zephyria-contracts",
  "chain_id": 7171,
  "rpc_url": "https://rpc.zephyria.io",
  "gas_price": "auto",
  "optimizer": {
    "enabled": true,
    "runs": 200
  },
  "paths": {
    "src":       "src/",
    "artifacts": "artifacts/",
    "cache":     ".forge-cache/"
  },
  "dependencies": {
    "zrc-std": "github.com/zephyria/zrc-std@v1.0.0"
  }
}
```

## Forge RPC Client

```zig
pub const RpcClient = struct {
    url:       []const u8,
    client:    std.http.Client,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, url: []const u8) !RpcClient {
        return .{
            .url       = url,
            .client    = std.http.Client{ .allocator = allocator },
            .allocator = allocator,
        };
    }

    pub fn call(self: *RpcClient, method: []const u8, params: anytype) !std.json.Value {
        var body_buf = std.ArrayList(u8).init(self.allocator);
        defer body_buf.deinit();
        try std.json.stringify(.{
            .jsonrpc = "2.0",
            .method  = method,
            .params  = params,
            .id      = 1,
        }, .{}, body_buf.writer());

        var resp_buf = std.ArrayList(u8).init(self.allocator);
        defer resp_buf.deinit();
        const res = try self.client.fetch(.{
            .method       = .POST,
            .location     = .{ .url = self.url },
            .extra_headers= &.{.{ .name = "Content-Type", .value = "application/json" }},
            .payload      = body_buf.items,
            .response_storage = .{ .dynamic = &resp_buf },
        });
        _ = res;

        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, resp_buf.items, .{});
        defer parsed.deinit();
        return parsed.value.object.get("result") orelse error.NoResult;
    }

    pub fn getBalance(self: *RpcClient, addr: Address) !u256 {
        const hex = try addrToHex(addr, self.allocator);
        defer self.allocator.free(hex);
        const result = try self.call("zph_getBalance", .{ hex, "latest" });
        return try parseHexUint256(result.string);
    }

    pub fn gasPrice(self: *RpcClient) !u256 {
        const result = try self.call("zph_gasPrice", .{});
        return try parseHexUint256(result.string);
    }

    pub fn sendRawTransaction(self: *RpcClient, raw: []const u8) !Hash32 {
        const hex = try bytesToHex(raw, self.allocator);
        defer self.allocator.free(hex);
        const result = try self.call("zph_sendRawTransaction", .{hex});
        return hexToHash32(result.string);
    }

    pub fn waitForReceipt(self: *RpcClient, hash: Hash32, opts: struct { timeout_ms: u64 }) !Receipt {
        const deadline = std.time.milliTimestamp() + @as(i64, @intCast(opts.timeout_ms));
        while (std.time.milliTimestamp() < deadline) {
            const hex = try hashToHex(hash, self.allocator);
            defer self.allocator.free(hex);
            const result = try self.call("zph_getTransactionReceipt", .{hex});
            if (result != .null) return parseReceipt(result);
            std.time.sleep(2_000_000_000); // 2s
        }
        return error.ReceiptTimeout;
    }
};
```

## Zephyria Network Constants

```zig
pub const ZEPHYRIA_MAINNET_CHAIN_ID: u64 = 7171;
pub const ZEPHYRIA_TESTNET_CHAIN_ID: u64 = 7172;

pub const MAINNET_RPC = "https://rpc.zephyria.io";
pub const TESTNET_RPC = "https://rpc-testnet.zephyria.io";

pub const NATIVE_TOKEN_DECIMALS: u8  = 18;
pub const NATIVE_TOKEN_SYMBOL: []const u8 = "ZEPH";

pub const BLOCK_TIME_SECONDS: u64 = 2;
pub const MAX_BLOCK_GAS: GasAmount = 30_000_000;
pub const BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8;
pub const ELASTICITY_MULTIPLIER: u64 = 2;

// Precompile addresses
pub const PRECOMPILE_ECRECOVER:   Address = addressFromInt(0x01);
pub const PRECOMPILE_SHA256:      Address = addressFromInt(0x02);
pub const PRECOMPILE_RIPEMD160:   Address = addressFromInt(0x03);
pub const PRECOMPILE_IDENTITY:    Address = addressFromInt(0x04);
pub const PRECOMPILE_MODEXP:      Address = addressFromInt(0x05);
pub const PRECOMPILE_BN_ADD:      Address = addressFromInt(0x06);
pub const PRECOMPILE_BN_MUL:      Address = addressFromInt(0x07);
pub const PRECOMPILE_BN_PAIRING:  Address = addressFromInt(0x08);
pub const PRECOMPILE_BLAKE2F:     Address = addressFromInt(0x09);
```

## ZRC-std Library Usage

```zig
// Add to build.zig.zon:
// .zrc_std = .{ .url = "https://pkg.zephyria.io/zrc-std/v1.0.0.tar.gz" }

const zrc = @import("zrc_std");

// Use ZRC-20 interface
const token = try zrc.Zrc20.at(allocator, client, token_address);
const bal = try token.balanceOf(my_address);
try token.transfer(recipient, 1000 * zrc.WAD);  // 1000 tokens

// Use ZRC-721
const nft = try zrc.Zrc721.at(allocator, client, nft_address);
const owner = try nft.ownerOf(token_id);
try nft.safeTransferFrom(from, to, token_id, &.{});
```

## Error Taxonomy

```zig
// Global error set — use these consistently across all modules
pub const ChainError = error{
    // Transaction
    InvalidSignature,
    NonceTooLow,
    NonceTooHigh,
    InsufficientBalance,
    GasLimitExceeded,
    InvalidChainId,
    TransactionTooLarge,

    // VM Execution
    OutOfGas,
    StackOverflow,
    StackUnderflow,
    InvalidJump,
    InvalidJumpDest,
    InvalidOpcode,
    WriteInStaticCall,
    Reentrant,
    ReturnDataOutOfBounds,

    // State
    StorageCorrupted,
    InvalidStateRoot,
    AccountNotFound,
    CodeNotFound,

    // Block
    InvalidBlockHash,
    InvalidParentHash,
    InvalidTimestamp,
    BlockGasLimitExceeded,
    InvalidMixHash,

    // Contract
    DeployFailed,
    ContractNotFound,
    TransferToZero,
    Overflow,
    Underflow,
    DivByZero,
    NotOwner,
    NotApproved,
    TokenExists,
    TokenNotFound,
    RevertWithReason,

    // Network
    PeerDisconnected,
    SyncFailed,
    RpcError,
    ReceiptTimeout,
};
```
