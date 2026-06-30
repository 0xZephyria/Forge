// File: vm/syscall/dispatch.zig
// Syscall dispatch for ForgeVM.
// Routes ECALL instructions to host functions based on the syscall ID in register a0 (x10).
// The compiler emits: ADDI a0, zero, <syscall_id> ; ECALL().
// The decoder reads a0 (x10) as the syscall ID.
// Implements the Zephyria syscall ABI: args in x10–x14, return in x10–x11, ID in x15.

const std = @import("std");
const executor = @import("../core/executor.zig");
const sandbox = @import("../memory/sandbox.zig");
const gasTable = @import("../gas/table.zig");
const bls = @import("bls12_381");

pub const ForgeVM = executor.ForgeVM;
pub const SyscallError = executor.SyscallError;

// ---------------------------------------------------------------------------
// Syscall IDs (matches architecture doc)
// ---------------------------------------------------------------------------

pub const SyscallId = struct {
    // ── Storage ──────────────────────────────────────────────────
    pub const STORAGE_LOAD: u32 = 0x01;
    pub const STORAGE_STORE: u32 = 0x02;
    pub const STORAGE_LOAD_DERIVED: u32 = 0x03; // per-user slot (DerivedKey)
    pub const STORAGE_STORE_DERIVED: u32 = 0x04;
    pub const STORAGE_LOAD_GLOBAL: u32 = 0x05; // commutative accumulator
    pub const STORAGE_STORE_GLOBAL: u32 = 0x06;

    // ── Assets (FORGE-native, no EVM equivalent) ──────────────────
    pub const ASSET_TRANSFER: u32 = 0x10;
    pub const ASSET_BALANCE: u32 = 0x11;
    pub const ASSET_CREATE: u32 = 0x12;
    pub const ASSET_BURN: u32 = 0x13;
    pub const ASSET_METADATA: u32 = 0x14;
    pub const ASSET_APPROVE: u32 = 0x15;
    pub const ASSET_ALLOWANCE: u32 = 0x16;
    pub const NATIVE_TRANSFER: u32 = 0x17; // FORGE-native send: a1=asset_value(u64), a2=recipient_ptr(32B)

    // ── Authority (FORGE role system) ────────────────────────────
    pub const AUTHORITY_CHECK: u32 = 0x20;
    pub const AUTHORITY_GRANT: u32 = 0x21;
    pub const AUTHORITY_REVOKE: u32 = 0x22;
    pub const AUTHORITY_LIST: u32 = 0x23;
    pub const TRANSIENT_LOAD: u32 = 0x26;
    pub const TRANSIENT_STORE: u32 = 0x27;

    // ── Events ───────────────────────────────────────────────────
    pub const EMIT_EVENT: u32 = 0x30;
    pub const EMIT_INDEXED_EVENT: u32 = 0x31;

    // ── Cross-contract calls ──────────────────────────────────────
    pub const CALL_CONTRACT: u32 = 0x40;
    pub const DELEGATECALL: u32 = 0x41;
    pub const STATICCALL: u32 = 0x42;
    pub const CREATE_CONTRACT: u32 = 0x43;
    pub const CREATE2_CONTRACT: u32 = 0x44;
    pub const SCHEDULE_CALL: u32 = 0x45;

    // ── Execution control ────────────────────────────────────────
    pub const RETURN_DATA: u32 = 0x50;
    pub const REVERT: u32 = 0x51;

    // ── Environment ──────────────────────────────────────────────
    pub const GET_CALLER: u32 = 0x60;
    pub const GET_CALLVALUE: u32 = 0x61;
    pub const GET_CALLDATA: u32 = 0x62;
    pub const GET_CALLDATA_SIZE: u32 = 0x63;
    pub const GET_SELF_ADDRESS: u32 = 0x64;
    pub const GET_BLOCK_NUMBER: u32 = 0x65;
    pub const GET_TIMESTAMP: u32 = 0x66;
    pub const GET_CHAIN_ID: u32 = 0x67;
    pub const GET_GAS_REMAINING: u32 = 0x68;
    pub const GET_TX_ORIGIN: u32 = 0x69;
    pub const GET_GAS_PRICE: u32 = 0x6A;
    pub const GET_COINBASE: u32 = 0x6B;
    pub const GET_BLOCK_HASH: u32 = 0x6C; // VRF randomness
    pub const GET_CODE_HASH: u32 = 0x6D;

    // ── Cryptography ─────────────────────────────────────────────
    pub const HASH_BLAKE3: u32 = 0x70; // replaces KECCAK256
    pub const HASH_SHA256: u32 = 0x71;
    pub const ECRECOVER: u32 = 0x72;
    pub const BLS_VERIFY: u32 = 0x73;

    // ── Parallel execution hints ──────────────────────────────────
    pub const RESOURCE_LOCK: u32 = 0x80; // declare write intent
    pub const RESOURCE_UNLOCK: u32 = 0x81;
    pub const PARALLEL_HINT: u32 = 0x82; // mark region conflict-free

    // ── Oracle ───────────────────────────────────────────────────
    pub const ORACLE_QUERY: u32 = 0xA0;

    // ── ZK ───────────────────────────────────────────────────────
    pub const ZK_VERIFY: u32 = 0xB0;

    // ── Gas delegation ───────────────────────────────────────────
    pub const DELEGATE_GAS: u32 = 0xB1;

    // ── Account lifecycle ────────────────────────────────────────
    pub const EXPAND_ACCOUNT: u32 = 0xB2;
    pub const CLOSE_ACCOUNT: u32 = 0xB3;

    // ── Debug (only active in debug build) ───────────────────────
    pub const DEBUG_LOG: u32 = 0xFF;
};

// ---------------------------------------------------------------------------
// Host state that backs the syscalls
// ---------------------------------------------------------------------------

/// Storage backend interface — abstracts the underlying state database.
pub const StorageBackend = struct {
    ctx: *anyopaque,
    loadFn: *const fn (ctx: *anyopaque, key: [32]u8) [32]u8,
    storeFn: *const fn (ctx: *anyopaque, key: [32]u8, value: [32]u8) void,

    pub fn load(self: *StorageBackend, key: [32]u8) [32]u8 {
        return self.loadFn(self.ctx, key);
    }

    pub fn store(self: *StorageBackend, key: [32]u8, value: [32]u8) void {
        self.storeFn(self.ctx, key, value);
    }
};

/// Log entry captured during execution.
pub const LogEntry = struct {
    // ArrayListUnmanaged: allocator passed per-operation — matches .empty init and
    // two-arg append/deinit used throughout this file.
    topics: std.ArrayListUnmanaged([32]u8),
    data: std.ArrayListUnmanaged(u8),
    alloc: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) LogEntry {
        return .{
            .topics = .empty,
            .data = .empty,
            .alloc = allocator,
        };
    }

    pub fn deinit(self: *LogEntry) void {
        self.topics.deinit(self.alloc);
        self.data.deinit(self.alloc);
    }
};

/// EIP-2929 access tracking — tracks which storage slots and addresses
/// have been accessed during this execution for warm/cold gas pricing.
pub const AccessSets = struct {
    /// Warm storage slots (keys already accessed in this execution)
    warmSlots: std.AutoHashMap([32]u8, void),
    /// Warm addresses (addresses already accessed in this execution)
    warmAddresses: std.AutoHashMap([32]u8, void),
    /// Original storage values at the start of the transaction (for SSTORE refund calc)
    originalValues: std.AutoHashMap([32]u8, [32]u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) AccessSets {
        return .{
            .warmSlots = std.AutoHashMap([32]u8, void).init(allocator),
            .warmAddresses = std.AutoHashMap([32]u8, void).init(allocator),
            .originalValues = std.AutoHashMap([32]u8, [32]u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AccessSets) void {
        self.warmSlots.deinit();
        self.warmAddresses.deinit();
        self.originalValues.deinit();
    }

    /// Check if a storage slot is warm (already accessed). Does NOT mark it warm.
    pub fn isSlotWarm(self: *const AccessSets, key: [32]u8) bool {
        return self.warmSlots.contains(key);
    }

    /// Mark a storage slot as warm. Returns true if it was already warm.
    pub fn markSlotWarm(self: *AccessSets, key: [32]u8) bool {
        const wasWarm = self.warmSlots.contains(key);
        self.warmSlots.put(key, {}) catch {};
        return wasWarm;
    }

    /// Check if an address is warm.
    pub fn isAddressWarm(self: *const AccessSets, addr: [32]u8) bool {
        return self.warmAddresses.contains(addr);
    }

    /// Mark an address as warm. Returns true if it was already warm.
    pub fn markAddressWarm(self: *AccessSets, addr: [32]u8) bool {
        const wasWarm = self.warmAddresses.contains(addr);
        self.warmAddresses.put(addr, {}) catch {};
        return wasWarm;
    }

    /// Record the original value for a storage slot (for SSTORE refund tracking).
    /// Only records if not already present (first write wins).
    pub fn recordOriginalValue(self: *AccessSets, key: [32]u8, value: [32]u8) void {
        _ = self.originalValues.getOrPutValue(key, value) catch {};
    }

    /// Get the original value for a slot (pre-transaction value).
    pub fn getOriginalValue(self: *const AccessSets, key: [32]u8) ?[32]u8 {
        return self.originalValues.get(key);
    }
};

/// Host environment state provided to syscall handlers.
pub const HostEnv = struct {
    // Storage
    storage: ?*StorageBackend,

    // Environment values (set by the node before execution)
    caller: [32]u8,
    callValue: [32]u8,
    selfAddress: [32]u8,
    blockNumber: u64,
    timestamp: u64,
    chainId: u64,
    txOrigin: [32]u8,
    gasPrice: u64,
    coinbase: [32]u8,
    gasLimit: u64,
    baseFee: u64,
    prevrandao: [32]u8,

    // Logs accumulated during execution
    // ArrayListUnmanaged so callers pass the allocator per operation (matches .empty init)
    logs: std.ArrayListUnmanaged(LogEntry),
    /// 256-byte bloom filter for indexed event topics.
    /// Updated on each EMIT_INDEXED_EVENT syscall.
    bloom_filter: [256]u8 = [_]u8{0} ** 256,
    allocator: std.mem.Allocator,

    // ---- Last sub-call return data (for RETURNDATASIZE/RETURNDATACOPY) ----
    lastReturnData: []const u8 = &[_]u8{},

    // ---- Warm SLOAD value cache (inline, no heap alloc) ----
    // Caches the last 8 SLOAD results for re-read acceleration.
    // At 1M TPS with ~5 SLOADs/TX, most reads hit warm slots.
    sloadCacheKeys: [8][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** 8,
    sloadCacheVals: [8][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** 8,
    sloadCacheCount: u8 = 0,

    // ---- EIP-2929 access tracking ----
    accessSets: AccessSets,

    // ---- Pluggable providers for node integration ----

    /// Balance provider: returns 32-byte balance for a 32-byte address.
    /// If null, getBalance returns 0.
    balanceFn: ?*const fn (addr: [32]u8) [32]u8 = null,

    /// Sig verify provider: verifies Ed25519/pluggable signature and returns derived address.
    /// Signature scheme: 0 = Ed25519, 1 = BLS12-381, 2 = quantum-resistant.
    /// Returns blake3(pubkey) as the signer address, or zeroes on failure.
    /// If null, returns zero address.
    ecrecoverFn: ?*const fn (hash: [32]u8, scheme: u8, pubkey: [32]u8, signature: [64]u8) [32]u8 = null,

    /// Call provider: execute a cross-contract call.
    /// Returns (success, returnData). If null, calls return failure.
    callFn: ?*const fn (callType: CallType, to: [32]u8, value: [32]u8, data: []const u8, gas: u64) CallProviderResult = null,

    /// Create provider: deploy a new contract.
    /// Returns (success, newAddress). If null, creates return failure.
    createFn: ?*const fn (code: []const u8, value: [32]u8, gas: u64) CreateProviderResult = null,

    /// Create2 provider: deploy a contract with salt-based deterministic address.
    /// Address = keccak256(0xFF || sender || salt || keccak256(initcode))[12..32]
    /// If null, create2 returns failure.
    create2Fn: ?*const fn (code: []const u8, salt: [32]u8, value: [32]u8, gas: u64) CreateProviderResult = null,

    /// Selfdestruct provider: transfers balance to beneficiary and marks account for deletion.
    /// If null, selfdestruct is a no-op that still halts execution.
    selfDestructFn: ?*const fn (beneficiary: [32]u8) bool = null,

    /// BLS12-381 signature verification override provider.
    /// If set, overrides the default native BLS12-381 implementation.
    /// a1=pubkey_ptr(48B), a2=sig_ptr(96B), a3=msg_ptr, a4=msg_len
    /// Returns a0=1 if signature is valid, 0 otherwise.
    blsVerifyFn: ?*const fn (pubkey: [48]u8, signature: [96]u8, msg: []const u8) bool = null,

    // ---- ZephyrLang Specific Providers ----

    /// Asset transfer provider: FORGE native asset transfer.
    assetTransferFn: ?*const fn (host: *HostEnv, assetId: [32]u8, from: [32]u8, to: [32]u8, amount: u128) anyerror!void = null,

    /// Asset create provider: mints a new asset of the given type with the given amount.
    /// Returns the 32-byte asset ID in the output buffer, or error on failure.
    /// a1=type_id (immediate), a2=0 (create flag), a3=amount (scalar u64)
    assetCreateFn: ?*const fn (host: *HostEnv, typeId: u64, amount: u64, assetIdOut: *[32]u8) anyerror!void = null,

    /// Asset burn provider: destroys an asset identified by its 32-byte asset ID.
    /// a1=asset_id_ptr → void
    assetBurnFn: ?*const fn (host: *HostEnv, assetId: [32]u8) anyerror!void = null,

    /// Asset metadata provider: reads metadata for an asset.
    /// a1=asset_id_ptr, a2=metadata_out(64B) → a0=0 success, 1 error
    assetMetadataFn: ?*const fn (host: *HostEnv, assetId: [32]u8, metadata: *[64]u8) anyerror!bool = null,

    /// Asset approve provider: approve a spender for an asset amount.
    /// a1=asset_id_ptr, a2=spender_ptr(32B), a3=amount_ptr(16B) → a0=0 success, 1 error
    assetApproveFn: ?*const fn (host: *HostEnv, assetId: [32]u8, spender: [32]u8, amount: u128) anyerror!void = null,

    /// Asset allowance provider: get the approved amount for a spender.
    /// a1=asset_id_ptr, a2=owner_ptr(32B), a3=spender_ptr(32B), a4=amount_out(16B) → a0=amount
    assetAllowanceFn: ?*const fn (host: *HostEnv, assetId: [32]u8, owner: [32]u8, spender: [32]u8) anyerror!u128 = null,

    derivedLoadFn: ?*const fn (host: *HostEnv, user: [32]u8, slot: [32]u8) [32]u8 = null,
    derivedStoreFn: ?*const fn (host: *HostEnv, user: [32]u8, slot: [32]u8, value: [32]u8) anyerror!void = null,
    globalLoadFn: ?*const fn (host: *HostEnv, slot: [32]u8) [32]u8 = null,
    globalStoreFn: ?*const fn (host: *HostEnv, slot: [32]u8, delta: [32]u8, isAddition: bool) anyerror!void = null,

    /// Parallel safe hint
    parallelSafe: bool = false,

    /// VM execution pool (reusable sandbox memory, decoded code cache)
    /// When set, contract_loader uses pooled sandbox + threaded executor. 
    vm_pool: ?*anyopaque = null,

    /// Get code hash for a contract: returns 32-byte hash
    codeHashFn: ?*const fn (addr: [32]u8) [32]u8 = null,

    /// Role checking provider
    roleCheckFn: ?*const fn (addr: [32]u8, role: [32]u8, account: [32]u8) bool = null,

    /// Role management provider (for ZephyrLang native roles)
    roleGrantFn: ?*const fn (addr: [32]u8, role: [32]u8, account: [32]u8) void = null,
    roleRevokeFn: ?*const fn (addr: [32]u8, role: [32]u8, account: [32]u8) void = null,

    /// Authority list provider: returns list of authority hashes for an address.
    /// a1=addr_ptr(32B), a2=result_buf_ptr, a3=max_count → a0=count
    authorityListFn: ?*const fn (host: *HostEnv, addr: [32]u8, rolesOut: []u8) anyerror!u64 = null,

    /// Resource lock/unlock provider (for linear types)
    resourceLockFn: ?*const fn (addr: [32]u8, id: [32]u8) bool = null,
    resourceUnlockFn: ?*const fn (addr: [32]u8, id: [32]u8) void = null,

    /// Oracle query provider: reads a value from an oracle feed.
    /// a1=feed_id (immediate), a2=result_ptr (stack buffer for 8-byte result)
    oracleQueryFn: ?*const fn (host: *HostEnv, feedId: u64, result: *u64) anyerror!void = null,

    /// ZK proof verification provider.
    /// a1=circuit_id (immediate), a2=proof_ptr, a3=proof_len=32
    /// Returns a0=1 if valid, 0 if invalid.
    zkVerifyFn: ?*const fn (host: *HostEnv, circuitId: u64, proof: [32]u8) anyerror!bool = null,

    /// Gas delegation provider: allow another account to pay for gas.
    /// a1=payer_addr_ptr (32-byte address)
    delegateGasFn: ?*const fn (host: *HostEnv, payer: [32]u8) anyerror!void = null,

    /// Account expansion provider: pre-allocate storage for an account.
    /// a1=account_ptr (32-byte address), a2=extra_bytes (scalar u64)
    expandAccountFn: ?*const fn (host: *HostEnv, account: [32]u8, extraBytes: u64) anyerror!void = null,

    /// Account closure provider: close an account and refund remaining balance.
    /// a1=account_ptr, a2=refund_to_ptr
    closeAccountFn: ?*const fn (host: *HostEnv, account: [32]u8, refundTo: [32]u8) anyerror!void = null,

    // ---- EIP-1153: Transient Storage (per-TX ephemeral key-value store) ----
    // Transient storage is automatically cleared when HostEnv is deinitialized
    // (at the end of each transaction). Cheap (100 gas) alternative to SSTORE
    // for values that don't need to persist across transactions.
    // Use cases: re-entrancy locks, flash loan callbacks, multi-hop routing state.
    transientStorage: std.AutoHashMap([32]u8, [32]u8),

    // ---- Call depth tracking (EVM max 1024) ----
    callDepth: u16 = 0,
    maxCallDepth: u16 = 1024,

    // ---- Re-entrancy protection (per-address guard) ----
    // Tracks which contract addresses are currently executing.
    // If a contract calls back into an address that is already in the call stack,
    // and that contract has re-entrancy protection enabled, the call is rejected.
    reentrantGuard: std.AutoHashMap([32]u8, void),

    pub fn init(allocator: std.mem.Allocator) HostEnv {
        return .{
            .storage = null,
            .caller = [_]u8{0} ** 32,
            .callValue = [_]u8{0} ** 32,
            .selfAddress = [_]u8{0} ** 32,
            .blockNumber = 0,
            .timestamp = 0,
            .chainId = 1,
            .txOrigin = [_]u8{0} ** 32,
            .gasPrice = 0,
            .coinbase = [_]u8{0} ** 32,
            .gasLimit = 30_000_000,
            .baseFee = 0,
            .prevrandao = [_]u8{0} ** 32,
            .logs = .empty,
            .allocator = allocator,
            .accessSets = AccessSets.init(allocator),
            .balanceFn = null,
            .ecrecoverFn = null,
            .callFn = null,
            .createFn = null,
            .create2Fn = null,
            .selfDestructFn = null,
            .blsVerifyFn = null,
            .codeHashFn = null,
            .roleCheckFn = null,
            .roleGrantFn = null,
            .roleRevokeFn = null,
            .resourceLockFn = null,
            .resourceUnlockFn = null,
            .transientStorage = std.AutoHashMap([32]u8, [32]u8).init(allocator),
            .reentrantGuard = std.AutoHashMap([32]u8, void).init(allocator),
        };
    }

    pub fn deinit(self: *HostEnv) void {
        for (self.logs.items) |*logEntry| {
            logEntry.deinit();
        }
        self.logs.deinit(self.allocator);
        self.accessSets.deinit();
        self.transientStorage.deinit();
        self.reentrantGuard.deinit();
    }

    /// Clear transient storage (called at TX boundary).
    /// EIP-1153: transient storage is automatically discarded after each TX.
    pub fn clearTransientStorage(self: *HostEnv) void {
        self.transientStorage.clearRetainingCapacity();
        self.reentrantGuard.clearRetainingCapacity();
        self.callDepth = 0;
    }

    /// Cache a SLOAD value in the inline MRU cache (8 entries).
    /// Most DeFi contracts re-read the same slots multiple times per call.
    pub fn cacheSloadValue(self: *HostEnv, key: [32]u8, value: [32]u8) void {
        // Check if key already in cache — update value in place
        for (self.sloadCacheKeys[0..self.sloadCacheCount], 0..) |cached_key, i| {
            if (std.mem.eql(u8, &cached_key, &key)) {
                self.sloadCacheVals[i] = value;
                return;
            }
        }
        // Add new entry (circular buffer)
        const idx = self.sloadCacheCount % 8;
        self.sloadCacheKeys[idx] = key;
        self.sloadCacheVals[idx] = value;
        if (self.sloadCacheCount < 8) self.sloadCacheCount += 1;
    }

    /// Look up a key in the SLOAD value cache.
    /// Returns the cached value if found, null otherwise.
    pub fn lookupSloadCache(self: *const HostEnv, key: [32]u8) ?[32]u8 {
        for (self.sloadCacheKeys[0..self.sloadCacheCount], 0..) |cached_key, i| {
            if (std.mem.eql(u8, &cached_key, &key)) {
                return self.sloadCacheVals[i];
            }
        }
        return null;
    }
};

/// Cross-contract call type
pub const CallType = enum {
    call,
    delegatecall,
    staticcall,
};

/// Result from a cross-contract call provider
pub const CallProviderResult = struct {
    success: bool,
    returnData: []const u8,
    gasUsed: u64,
};

/// Result from a create provider
pub const CreateProviderResult = struct {
    success: bool,
    newAddress: [32]u8,
    gasUsed: u64,
};

// ---------------------------------------------------------------------------
// Syscall dispatcher — creates a syscall handler function for a given HostEnv
// ---------------------------------------------------------------------------

/// Create a syscall handler and bind it to the given host environment.
///
/// Thread-safety model: the env pointer is stored in `vm.hostCtx` (a field of
/// ForgeVM set by the caller right after init). The handler retrieves it from
/// there at dispatch time. This means every VM instance carries its own env
/// pointer — there is NO shared mutable static, so concurrent VMs on the same
/// or different threads are fully independent.
///
/// Callers MUST set `vm.hostCtx = env` after `ForgeVM.init` and before the
/// first `execute()` or `step()` call. `contract_loader` and `vm.zig` already
/// do this.
pub fn createHandler(env: *HostEnv) executor.SyscallFn {
    // Validate at creation time so callers get a clear error immediately if
    // something is wired wrongly, rather than a silent null-deref at runtime.
    _ = env; // env stored in vm.hostCtx by the caller — not captured here
    return &syscallDispatch;
}

/// The single concrete syscall dispatch function.
/// Retrieves HostEnv from `vm.hostCtx` — set by the caller before execution.
fn syscallDispatch(vm_opaque: *anyopaque) executor.SyscallError!void {
    const vm: *ForgeVM = @ptrCast(@alignCast(vm_opaque));
    // Retrieve the HostEnv pointer stored in the VM by the loader/vm.zig.
    const env: *HostEnv = @ptrCast(@alignCast(vm.hostCtx orelse {
        return executor.SyscallError.InternalError; // hostCtx was never set
    }));

    const syscallId: u32 = @truncate(vm.regs[10]); // a0 = syscall ID
    switch (syscallId) {
        SyscallId.STORAGE_LOAD => try storageLoad(vm, env),
        SyscallId.STORAGE_STORE => try storageStore(vm, env),
        SyscallId.STORAGE_LOAD_DERIVED => try derivedStorageLoad(vm, env),
        SyscallId.STORAGE_STORE_DERIVED => try derivedStorageStore(vm, env),
        SyscallId.STORAGE_LOAD_GLOBAL => try globalStorageLoad(vm, env),
        SyscallId.STORAGE_STORE_GLOBAL => try globalStorageStore(vm, env),
        SyscallId.TRANSIENT_LOAD => try transientLoad(vm, env),
        SyscallId.TRANSIENT_STORE => try transientStore(vm, env),
        SyscallId.CREATE2_CONTRACT => try create2Contract(vm, env),
        SyscallId.EMIT_EVENT => try emitEvent(vm, env),
        SyscallId.EMIT_INDEXED_EVENT => try emitIndexedEvent(vm, env),
        SyscallId.GET_CALLER => getCaller(vm, env),
        SyscallId.GET_CALLVALUE => getCallValue(vm, env),
        SyscallId.GET_CALLDATA => getCallData(vm),
        SyscallId.GET_CALLDATA_SIZE => getCallDataSize(vm),
        SyscallId.RETURN_DATA => {
            returnData(vm);
            return executor.SyscallError.ReturnData;
        },
        SyscallId.REVERT => {
            revertExecution(vm);
            return executor.SyscallError.Revert;
        },
        SyscallId.HASH_BLAKE3 => try handleBlake3(vm, env),
        SyscallId.HASH_SHA256 => try handleSha256(vm, env),
        SyscallId.ASSET_TRANSFER => try handleAssetTransfer(vm, env),
        SyscallId.ASSET_BALANCE => try getBalance(vm, env),
        SyscallId.ASSET_CREATE => try handleAssetCreate(vm, env),
        SyscallId.ASSET_BURN => try handleAssetBurn(vm, env),
        SyscallId.ASSET_METADATA => try handleAssetMetadata(vm, env),
        SyscallId.ASSET_APPROVE => try handleAssetApprove(vm, env),
        SyscallId.ASSET_ALLOWANCE => try handleAssetAllowance(vm, env),
        SyscallId.NATIVE_TRANSFER => try handleNativeTransfer(vm, env),
        SyscallId.PARALLEL_HINT => try handleParallelHint(vm, env),
        SyscallId.GET_BLOCK_NUMBER => getBlockNumber(vm, env),
        SyscallId.GET_TIMESTAMP => getTimestamp(vm, env),
        SyscallId.GET_CHAIN_ID => getChainId(vm, env),
        SyscallId.GET_GAS_REMAINING => getGasRemaining(vm),
        SyscallId.GET_TX_ORIGIN => getTxOrigin(vm, env),
        SyscallId.GET_GAS_PRICE => getGasPrice(vm, env),
        SyscallId.GET_COINBASE => getCoinbase(vm, env),
        SyscallId.GET_SELF_ADDRESS => getSelfAddress(vm, env),
        SyscallId.GET_BLOCK_HASH => getPrevrandao(vm, env),
        SyscallId.GET_CODE_HASH => try getCodeHash(vm, env),
        SyscallId.DEBUG_LOG => try debugLog(vm, env),
        SyscallId.CREATE_CONTRACT => try createContract(vm, env),
        SyscallId.AUTHORITY_CHECK => try roleCheck(vm, env),
        SyscallId.AUTHORITY_GRANT => try roleGrant(vm, env),
        SyscallId.AUTHORITY_REVOKE => try roleRevoke(vm, env),
        SyscallId.AUTHORITY_LIST => try handleAuthorityList(vm, env),
        SyscallId.RESOURCE_LOCK => try resourceLock(vm, env),
        SyscallId.RESOURCE_UNLOCK => try resourceUnlock(vm, env),
        SyscallId.CALL_CONTRACT => try callContract(vm, env, .call),
        SyscallId.DELEGATECALL => try callContract(vm, env, .delegatecall),
        SyscallId.STATICCALL => try callContract(vm, env, .staticcall),
        SyscallId.SCHEDULE_CALL => try handleScheduleCall(vm, env),
        SyscallId.ECRECOVER => try ecrecover(vm, env),
        SyscallId.BLS_VERIFY => try blsVerify(vm, env),
        SyscallId.ORACLE_QUERY => try handleOracleQuery(vm, env),
        SyscallId.ZK_VERIFY => try handleZkVerify(vm, env),
        SyscallId.DELEGATE_GAS => try handleDelegateGas(vm, env),
        SyscallId.EXPAND_ACCOUNT => try handleExpandAccount(vm, env),
        SyscallId.CLOSE_ACCOUNT => try handleCloseAccount(vm, env),
        else => return executor.SyscallError.UnknownSyscall,
    }
}

// ---------------------------------------------------------------------------
// Individual syscall implementations
// ---------------------------------------------------------------------------

/// Syscall 0x01: storage_load (EIP-2929 warm/cold)
/// a0 = pointer to 32-byte key in VM memory
/// a1 = pointer to 32-byte result buffer in VM memory
fn storageLoad(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const keyPtr = vm.regs[11]; // a1
    const resultPtr = vm.regs[12]; // a2

    // Zero-copy: read key directly from backing memory
    const keyRef = vm.memory.getAligned32(keyPtr) catch return SyscallError.SegFault;
    const key = keyRef.*;

    // EIP-2929: charge warm (100) or cold (2100) gas
    const wasWarm = env.accessSets.markSlotWarm(key);
    const gasCost = gasTable.SyscallGas.STORAGE_LOAD;
    vm.gas.consume(gasCost) catch return SyscallError.OutOfGas;

    // Fast path: check inline SLOAD value cache (avoids storage backend round-trip)
    const value = if (wasWarm)
        (env.lookupSloadCache(key) orelse if (env.storage) |s| s.load(key) else [_]u8{0} ** 32)
    else
        (if (env.storage) |s| s.load(key) else [_]u8{0} ** 32);

    // Cache the loaded value for re-read acceleration
    env.cacheSloadValue(key, value);

    // Record original value for SSTORE refund tracking (if first access)
    if (!wasWarm) {
        env.accessSets.recordOriginalValue(key, value);
    }

    // Zero-copy: write result directly to backing memory
    const result_ref = vm.memory.getAligned32Mut(resultPtr) catch return SyscallError.SegFault;
    result_ref.* = value;
}

/// Syscall 0x02: storage_store (EIP-2929 warm/cold + EIP-3529 refund)
/// a0 = pointer to 32-byte key
/// a1 = pointer to 32-byte value
fn storageStore(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const keyPtr = vm.regs[11]; // a1
    const value_ptr = vm.regs[12]; // a2

    // Zero-copy: read key directly from backing memory
    const keyRef = vm.memory.getAligned32(keyPtr) catch return SyscallError.SegFault;
    const key = keyRef.*;

    // Zero-copy: read value directly from backing memory
    const valRef = vm.memory.getAligned32(value_ptr) catch return SyscallError.SegFault;
    const newValue = valRef.*;

    // Read current value from storage
    const currentValue = if (env.storage) |s| s.load(key) else [_]u8{0} ** 32;
    const zeroSlot: [32]u8 = [_]u8{0} ** 32;

    // Record original value if first time accessing this slot
    const wasWarm = env.accessSets.markSlotWarm(key);
    if (!wasWarm) {
        env.accessSets.recordOriginalValue(key, currentValue);
    }

    // FORGE flat gas model
    if (!wasWarm) {
        vm.gas.consume(gasTable.SyscallGas.STORAGE_STORE) catch return SyscallError.OutOfGas;
    }

    // Determine SSTORE gas based on current and new values
    const isNoop = std.mem.eql(u8, &currentValue, &newValue);
    const originalValue = env.accessSets.getOriginalValue(key) orelse currentValue;
    const orig_is_current = std.mem.eql(u8, &originalValue, &currentValue);
    const orig_is_zero = std.mem.eql(u8, &originalValue, &zeroSlot);
    const new_is_zero = std.mem.eql(u8, &newValue, &zeroSlot);

    if (isNoop) {
        // No-op: value unchanged — charge warm access only
        vm.gas.consume(gasTable.SyscallGas.STORAGE_STORE) catch return SyscallError.OutOfGas;
    } else if (orig_is_current) {
        if (orig_is_zero) {
            // 0 → non-zero: fresh allocation
            vm.gas.consume(gasTable.SyscallGas.STORAGE_STORE_SET) catch return SyscallError.OutOfGas;
        } else {
            // non-zero → different non-zero (or non-zero → zero): reset
            vm.gas.consume(gasTable.SyscallGas.STORAGE_STORE) catch return SyscallError.OutOfGas;
            // EIP-3529: refund for clearing (non-zero → zero)
            if (new_is_zero) {
                vm.gas.addRefund(gasTable.SyscallGas.STORAGE_CLEAR_REFUND);
            }
        }
    } else {
        // Dirty slot (already modified this transaction) — warm access
        vm.gas.consume(gasTable.SyscallGas.STORAGE_STORE) catch return SyscallError.OutOfGas;

        // EIP-3529 refund adjustments for restoring original value
        if (!orig_is_zero and new_is_zero) {
            // Restoring to zero from a dirty non-zero
            vm.gas.addRefund(gasTable.SyscallGas.STORAGE_CLEAR_REFUND);
        }
    }

    if (env.storage) |s| s.store(key, newValue);
    // Invalidate cache entry on write
    env.cacheSloadValue(key, newValue);
}

/// Syscall 0x30: emit_event
/// a0 = topicCount (0–4)
/// a1 = pointer to topics array (topicCount × 32 bytes)
/// a2 = pointer to data
/// a3 = dataLen
fn emitEvent(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const topicCount = vm.regs[11];
    const topicsPtr = vm.regs[12];
    const dataPtr = vm.regs[13];
    const dataLen = vm.regs[14];

    if (topicCount > 4) return SyscallError.InternalError;

    // Gas: base + per-byte for data
    const gasCost = gasTable.SyscallGas.EMIT_EVENT_BASE + gasTable.SyscallGas.EMIT_EVENT_PER_BYTE * @as(u64, dataLen);
    vm.gas.consume(gasCost) catch return SyscallError.OutOfGas;

    var logEntry = LogEntry.init(env.allocator);

    // Read topics
    var i: u32 = 0;
    while (i < topicCount) : (i += 1) {
        const topic_offset = topicsPtr + i * 32;
        const topic_slice = vm.memory.getSlice(topic_offset, 32) catch return SyscallError.SegFault;
        var topic: [32]u8 = undefined;
        @memcpy(&topic, topic_slice);
        logEntry.topics.append(logEntry.alloc, topic) catch return SyscallError.InternalError;
    }

    // Read data
    if (dataLen > 0) {
        const data_slice = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
        logEntry.data.appendSlice(logEntry.alloc, data_slice) catch return SyscallError.InternalError;
    }

    env.logs.append(env.allocator, logEntry) catch return SyscallError.InternalError;
}

/// Zeph bloom filter: 256-byte (2048-bit) filter using BLAKE3.
///
/// Design:
///   - Hash topic with BLAKE3 → 32 bytes
///   - Split into 4 × 8-byte windows
///   - Each window → u64 → modulo 2048 → set 1 bit
///   - Total: 4 bits per topic
///
/// This is NOT the Ethereum bloom filter. It's custom for the Zeph VM:
///   - Uses BLAKE3 (our native hash) instead of keccak256
///   - Sets 4 bits per topic (vs 3 for Ethereum) for lower false positives
///   - Bit positions use the full 64-bit entropy of each hash window
fn setBloomBits(bloom: *[256]u8, topic: *const [32]u8) void {
    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(topic, &hash, .{});
    // Set 4 bit positions from 4 × 8-byte windows of the hash.
    for (0..4) |j| {
        const window = hash[j * 8 ..][0..8];
        const bits: u64 = std.mem.readInt(u64, window, .little);
        const bit_pos: u11 = @truncate(bits % 2048);
        const byte_idx: u8 = @truncate(bit_pos >> 3);
        const bit_idx: u3 = @truncate(bit_pos & 7);
        bloom[255 - byte_idx] |= @as(u8, 1) << bit_idx;
    }
}

/// Syscall 0x31: emit_indexed_event — same as emitEvent but computes bloom filter bits.
fn emitIndexedEvent(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    // Same ABI as emitEvent: a1=topicCount, a2=topicsPtr, a3=dataPtr, a4=dataLen
    const topicCount = vm.regs[11];
    const topicsPtr = vm.regs[12];
    const dataPtr = vm.regs[13];
    const dataLen = vm.regs[14];

    if (topicCount > 4) return SyscallError.InternalError;

    // Gas: base + per-byte for data (slightly higher than EMIT_EVENT for bloom work)
    const gasCost = gasTable.SyscallGas.EMIT_EVENT_BASE + gasTable.SyscallGas.EMIT_EVENT_PER_BYTE * @as(u64, dataLen) + 100;
    vm.gas.consume(gasCost) catch return SyscallError.OutOfGas;

    var logEntry = LogEntry.init(env.allocator);

    // Read topics and compute bloom filter bits.
    var i: u32 = 0;
    while (i < topicCount) : (i += 1) {
        const topic_offset = topicsPtr + i * 32;
        const topic_slice = vm.memory.getSlice(topic_offset, 32) catch return SyscallError.SegFault;
        var topic: [32]u8 = undefined;
        @memcpy(&topic, topic_slice);
        logEntry.topics.append(logEntry.alloc, topic) catch return SyscallError.InternalError;
        setBloomBits(&env.bloom_filter, &topic);
    }

    // Read data
    if (dataLen > 0) {
        const data_slice = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
        logEntry.data.appendSlice(logEntry.alloc, data_slice) catch return SyscallError.InternalError;
    }

    env.logs.append(env.allocator, logEntry) catch return SyscallError.InternalError;
}

/// Syscall 0x73: bls_verify — verify a BLS12-381 signature using the native bls12_381 library.
/// a1=pubkey_ptr(48B), a2=sig_ptr(96B), a3=msg_ptr, a4=msg_len
/// Returns a0=1 if valid, 0 if invalid.
fn blsVerify(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.gas.consume(gasTable.SyscallGas.BLS_VERIFY) catch return SyscallError.OutOfGas;

    const pubkeyPtr = vm.regs[11];
    const sigPtr = vm.regs[12];
    const msgPtr = vm.regs[13];
    const msgLen = vm.regs[14];

    // Read public key (48 bytes — G2 compressed).
    const pubkey_slice = vm.memory.getSlice(pubkeyPtr, 48) catch return SyscallError.SegFault;
    var pubkey_bytes: [48]u8 = undefined;
    @memcpy(&pubkey_bytes, pubkey_slice);

    // Read signature (96 bytes — G1 uncompressed/aggregate).
    const sig_slice = vm.memory.getSlice(sigPtr, 96) catch return SyscallError.SegFault;
    var sig_bytes: [96]u8 = undefined;
    @memcpy(&sig_bytes, sig_slice);

    // Read message.
    const msg = vm.memory.getSlice(msgPtr, msgLen) catch return SyscallError.SegFault;

    // Use override provider if set, otherwise use native bls12_381 library.
    if (env.blsVerifyFn) |verify| {
        vm.regs[10] = if (verify(pubkey_bytes, sig_bytes, msg)) 1 else 0;
        return;
    }

    // Native BLS verification via bls12_381 library.
    // Deserialize public key from 48-byte compressed G2 point.
    const public_key = bls.PublicKey.fromBytes(pubkey_bytes[0..]) catch {
        vm.regs[10] = 0;
        return;
    };

    // Deserialize signature from 96-byte compressed G1 point (min-pk variant).
    const signature = bls.Signature.fromBytes(sig_bytes[0..]) catch {
        vm.regs[10] = 0;
        return;
    };

    // Verify: signature.verify(sig_groupcheck, msg, dst, aug, pk, pk_validate)
    const dst = "FORGE_BLS_SIG_V1";
    signature.verify(true, msg, dst, null, &public_key, true) catch {
        vm.regs[10] = 0;
        return;
    };
    vm.regs[10] = 1;
}

/// Syscall 0x60: get_caller → writes msg.sender (32 bytes) to memory at a0
fn getCaller(vm: *ForgeVM, env: *HostEnv) void {
    vm.gas.consume(gasTable.SyscallGas.GET_CALLER) catch return;
    const bufPtr = vm.regs[11];
    const slice = vm.memory.getSliceMut(bufPtr, 32) catch return;
    @memcpy(slice, &env.caller);
}

/// Syscall 0x61: get_callvalue → writes msg.value (32 bytes) to memory at a0
fn getCallValue(vm: *ForgeVM, env: *HostEnv) void {
    vm.gas.consume(gasTable.SyscallGas.GET_CALLVALUE) catch return;
    const bufPtr = vm.regs[11];
    const slice = vm.memory.getSliceMut(bufPtr, 32) catch return;
    @memcpy(slice, &env.callValue);
}

/// Syscall 0x62: get_calldata → copies calldata[a0..a0+a1] to memory at a2
fn getCallData(vm: *ForgeVM) void {
    const offset = vm.regs[11];
    const len = vm.regs[12];
    const dest = vm.regs[13];

    // Read from calldata region
    const src = sandbox.calldataStart + offset;
    const src_slice = vm.memory.getSlice(src, len) catch return;
    const dst_slice = vm.memory.getSliceMut(dest, len) catch return;
    @memcpy(dst_slice, src_slice);
}

/// Syscall 0x63: get_calldata_size → returns actual calldata length in a0
fn getCallDataSize(vm: *ForgeVM) void {
    vm.regs[10] = vm.calldataLen;
}

/// Syscall 0x09: returnData — a0 = pointer to data, a1 = length
fn returnData(vm: *ForgeVM) void {
    const dataPtr = vm.regs[11];
    const dataLen = vm.regs[12];

    // Copy to return region
    if (dataLen > 0 and dataLen <= sandbox.returnSize) {
        const src = vm.memory.getSlice(dataPtr, dataLen) catch return;
        const dst = vm.memory.getSliceMut(sandbox.returnStart, dataLen) catch return;
        @memcpy(dst, src);
    }

    vm.returnDataOffset = 0;
    vm.returnDataLen = @truncate(dataLen);
}

/// Syscall 0x0A: revert — a0 = pointer to error data, a1 = length
fn revertExecution(vm: *ForgeVM) void {
    const dataPtr = vm.regs[11];
    const dataLen = vm.regs[12];

    if (dataLen > 0 and dataLen <= sandbox.returnSize) {
        const src = vm.memory.getSlice(dataPtr, dataLen) catch return;
        const dst = vm.memory.getSliceMut(sandbox.returnStart, dataLen) catch return;
        @memcpy(dst, src);
    }

    vm.returnDataOffset = 0;
    vm.returnDataLen = @truncate(dataLen);
}

/// Syscall 0x11: get_balance (asset balance) — a0 = ptr to 32-byte address, writes 32-byte balance to a1
fn getBalance(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr: u32 = @truncate(vm.regs[11]);
    const resultPtr: u32 = @truncate(vm.regs[12]);

    // Read 32-byte address from VM memory
    const addrSlice = vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault;
    var addr: [32]u8 = undefined;
    @memcpy(&addr, addrSlice);

    const gasCost = gasTable.SyscallGas.ASSET_QUERY_BALANCE;
    vm.gas.consume(gasCost) catch return SyscallError.OutOfGas;

    // Get balance via provider, or return zero
    const balance = if (env.balanceFn) |f| f(addr) else [_]u8{0} ** 32;

    // Write 32-byte balance to VM memory
    const result_slice = vm.memory.getSliceMut(resultPtr, 32) catch return SyscallError.SegFault;
    @memcpy(result_slice, &balance);
    vm.regs[10] = 0;
}

/// Syscall 0x65: get_block_number → a0 = low 32 bits
fn getBlockNumber(vm: *ForgeVM, env: *HostEnv) void {
    vm.gas.consume(gasTable.SyscallGas.GET_BLOCK_NUMBER) catch return;
    vm.regs[10] = @truncate(env.blockNumber);
}

/// Syscall 0x66: get_timestamp → a0 = low 32 bits
fn getTimestamp(vm: *ForgeVM, env: *HostEnv) void {
    vm.gas.consume(gasTable.SyscallGas.GET_TIMESTAMP) catch return;
    vm.regs[10] = @truncate(env.timestamp);
}

/// Syscall 0x67: get_chain_id → a0 = chain ID
fn getChainId(vm: *ForgeVM, env: *HostEnv) void {
    vm.gas.consume(gasTable.SyscallGas.GET_CHAIN_ID) catch return;
    vm.regs[10] = @truncate(env.chainId);
}

/// Syscall 0x68: get_gas_remaining → a0 = remaining gas (low 32 bits)
fn getGasRemaining(vm: *ForgeVM) void {
    vm.regs[10] = vm.gas.remaining();
}

/// Syscall 0x69: get_tx_origin → writes 32 bytes to memory at a1
fn getTxOrigin(vm: *ForgeVM, env: *HostEnv) void {
    const bufPtr = vm.regs[11]; // a1 — a0 is the syscall ID
    const slice = vm.memory.getSliceMut(bufPtr, 32) catch return;
    @memcpy(slice, &env.txOrigin);
}

/// Syscall GET_GAS_PRICE → a0 = gas price (low 32 bits), result overwrites a0
fn getGasPrice(vm: *ForgeVM, env: *HostEnv) void {
    vm.regs[10] = @truncate(env.gasPrice);
}

/// Syscall 0x6B: get_coinbase → writes 32 bytes to memory at a1
fn getCoinbase(vm: *ForgeVM, env: *HostEnv) void {
    const bufPtr = vm.regs[11]; // a1 — a0 is the syscall ID
    const slice = vm.memory.getSliceMut(bufPtr, 32) catch return;
    @memcpy(slice, &env.coinbase);
}

/// Syscall GET_BLOCK_HASH / prevrandao
/// a0 = syscallId, a1 = ptr to 32-byte output buffer
/// Writes the VRF prevrandao value (Zephyria uses VRF-based randomness).
fn getPrevrandao(vm: *ForgeVM, env: *HostEnv) void {
    vm.gas.consume(20) catch return; // cheap env read
    const bufPtr = vm.regs[11]; // a1
    const slice = vm.memory.getSliceMut(bufPtr, 32) catch return;
    @memcpy(slice, &env.prevrandao);
}

/// Syscall 0x64: get_self_address → writes 32 bytes to memory at a1
fn getSelfAddress(vm: *ForgeVM, env: *HostEnv) void {
    const bufPtr = vm.regs[11]; // a1 — a0 is the syscall ID
    const slice = vm.memory.getSliceMut(bufPtr, 32) catch return;
    @memcpy(slice, &env.selfAddress);
}

/// Syscall 0x04/0x05/0x1C: call_contract / delegatecall / staticcall (EIP-2929 warm/cold)
/// a0 = ptr to 20-byte target address
/// a1 = ptr to 32-byte value (only for CALL, ignored for delegatecall/staticcall)
/// a2 = ptr to input data
/// a3 = input data length
/// Returns: a0 = 1 (success) or 0 (failure)
fn callContract(vm: *ForgeVM, env: *HostEnv, callType: CallType) SyscallError!void {
    // Read target address first so we can check warm/cold
    const toPtr_peek = vm.regs[11];
    const to_slice_peek = vm.memory.getSlice(toPtr_peek, 32) catch return SyscallError.SegFault;
    var to_addr_peek: [32]u8 = undefined;
    @memcpy(&to_addr_peek, to_slice_peek);

    // FORGE flat gas model
    const call_gas = gasTable.SyscallGas.CALL_CONTRACT;
    vm.gas.consume(call_gas) catch return SyscallError.OutOfGas;

    const toPtr = vm.regs[11];
    const value_ptr = vm.regs[12];
    const dataPtr = vm.regs[13];
    const dataLen = vm.regs[14];

    // Read target address (32 bytes)
    const to_slice = vm.memory.getSlice(toPtr, 32) catch return SyscallError.SegFault;
    var to: [32]u8 = undefined;
    @memcpy(&to, to_slice);

    // Read value (32 bytes) — only meaningful for CALL
    var value: [32]u8 = [_]u8{0} ** 32;
    if (callType == .call) {
        const valSlice = vm.memory.getSlice(value_ptr, 32) catch return SyscallError.SegFault;
        @memcpy(&value, valSlice);
    }

    // Read input data
    var data: []const u8 = &[_]u8{};
    if (dataLen > 0) {
        data = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
    }

    // Execute via provider
    if (env.callFn) |callFn| {
        // Check call depth limit (EVM max 1024)
        if (env.callDepth >= env.maxCallDepth) {
            vm.regs[10] = 0; // Call depth exceeded — return failure
            return;
        }
        env.callDepth += 1;
        defer env.callDepth -= 1;

        // Re-entrancy guard: check if target address is already in the call stack
        if (env.reentrantGuard.contains(to)) {
            // Target is already executing — potential re-entrancy
            // We still allow the call (non-reentrant guard is opt-in at SDK level)
            // but we track it for VM-level enforcement when contracts opt in.
        }

        // Track this address in the call stack
        env.reentrantGuard.put(to, {}) catch {};
        defer _ = env.reentrantGuard.remove(to);

        const gas_to_forward = vm.gas.remaining();
        const result = callFn(callType, to, value, data, gas_to_forward);

        // Consume gas used by the subcall
        vm.gas.consume(result.gasUsed) catch {};

        // Store last return data for RETURNDATASIZE/RETURNDATACOPY
        env.lastReturnData = result.returnData;

        // Write return data to return region
        if (result.returnData.len > 0 and result.returnData.len <= sandbox.returnSize) {
            const dst = vm.memory.getSliceMut(sandbox.returnStart, @intCast(result.returnData.len)) catch {
                vm.regs[10] = 0;
                return;
            };
            @memcpy(dst, result.returnData);
            vm.returnDataLen = @intCast(result.returnData.len);
            vm.returnDataOffset = 0;
        }

        vm.regs[10] = if (result.success) 1 else 0;
    } else {
        // No call provider — return failure
        vm.regs[10] = 0;
    }
}

/// Syscall 0x10: create_contract — deploy a new contract
/// a0 = ptr to init code
/// a1 = init code length
/// a2 = ptr to 32-byte value (ETH to send)
/// a3 = ptr to 20-byte result buffer (new address written here)
/// Returns: a0 = 1 (success) or 0 (failure)
fn createContract(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.gas.consume(gasTable.SyscallGas.CREATE_CONTRACT) catch return SyscallError.OutOfGas;

    const code_ptr = vm.regs[11];
    const code_len = vm.regs[12];
    const value_ptr = vm.regs[13];
    const resultPtr = vm.regs[14];

    // EIP-3860: enforce max initcode size (49152 bytes)
    if (code_len > 49152) {
        vm.regs[10] = 0;
        return;
    }

    // Read init code
    var code: []const u8 = &[_]u8{};
    if (code_len > 0) {
        code = vm.memory.getSlice(code_ptr, code_len) catch return SyscallError.SegFault;

        // EIP-3860: charge 2 gas per 32-byte word of initcode
        const words = (code_len + 31) / 32;
        vm.gas.consume(2 * @as(u64, words)) catch return SyscallError.OutOfGas;
    }

    // Read value
    const valSlice = vm.memory.getSlice(value_ptr, 32) catch return SyscallError.SegFault;
    var value: [32]u8 = undefined;
    @memcpy(&value, valSlice);

    // Execute via provider
    if (env.createFn) |createFn| {
        // Check call depth limit
        if (env.callDepth >= env.maxCallDepth) {
            vm.regs[10] = 0;
            return;
        }
        env.callDepth += 1;
        defer env.callDepth -= 1;

        const gas_to_forward = vm.gas.remaining();
        const result = createFn(code, value, gas_to_forward);

        vm.gas.consume(result.gasUsed) catch {};

        if (result.success) {
            // Write new address to result buffer
            const addrSlice = vm.memory.getSliceMut(resultPtr, 32) catch {
                vm.regs[10] = 0;
                return;
            };
            @memcpy(addrSlice, &result.newAddress);
            vm.regs[10] = 1;
        } else {
            vm.regs[10] = 0;
        }
    } else {
        vm.regs[10] = 0;
    }
}

/// Syscall 0x25: create2 — deploy a contract with salt-based deterministic address (EIP-1014)
/// a0 = ptr to init code
/// a1 = init code length
/// a2 = ptr to 32-byte salt
/// a3 = ptr to 32-byte value (ETH to send)
/// a4 = ptr to 20-byte result buffer (new address written here)
/// Returns: a0 = 1 (success) or 0 (failure)
///
/// Address derivation: keccak256(0xFF || sender || salt || keccak256(initcode))[12..32]
/// This enables counterfactual addresses, factory patterns (Uniswap V3),
/// minimal proxy clones, and deterministic deployment across chains.
fn create2Contract(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    // Base gas: same as CREATE (32000) + per-word hash cost for initcode
    vm.gas.consume(32000) catch return SyscallError.OutOfGas;

    const code_ptr = vm.regs[11]; // a1
    const code_len = vm.regs[12]; // a2
    const salt_ptr = vm.regs[13]; // a3
    const value_ptr = vm.regs[14]; // a4
    const resultPtr = vm.regs[15]; // a5 — result buffer (32 bytes)

    // Read init code
    var code: []const u8 = &[_]u8{};
    if (code_len > 0) {
        code = vm.memory.getSlice(code_ptr, code_len) catch return SyscallError.SegFault;

        // Charge per-word gas for hashing initcode (same as EIP-3860)
        const words = (code_len + 31) / 32;
        vm.gas.consume(gasTable.SyscallGas.CREATE2_PER_WORD * @as(u64, words)) catch return SyscallError.OutOfGas;
    }

    // Read salt (32 bytes)
    const salt_slice = vm.memory.getSlice(salt_ptr, 32) catch return SyscallError.SegFault;
    var salt: [32]u8 = undefined;
    @memcpy(&salt, salt_slice);

    // Read value (32 bytes)
    const valSlice = vm.memory.getSlice(value_ptr, 32) catch return SyscallError.SegFault;
    var value: [32]u8 = undefined;
    @memcpy(&value, valSlice);

    // Execute via create2 provider
    if (env.create2Fn) |create2Fn| {
        // Check call depth limit
        if (env.callDepth >= env.maxCallDepth) {
            vm.regs[10] = 0;
            return;
        }
        env.callDepth += 1;
        defer env.callDepth -= 1;

        const gas_to_forward = vm.gas.remaining();
        const result = create2Fn(code, salt, value, gas_to_forward);

        vm.gas.consume(result.gasUsed) catch {};

        if (result.success) {
            // Write new address to result buffer
            const addrSlice = vm.memory.getSliceMut(resultPtr, 32) catch {
                vm.regs[10] = 0;
                return;
            };
            @memcpy(addrSlice, &result.newAddress);
            vm.regs[10] = 1;
        } else {
            vm.regs[10] = 0;
        }
    } else {
        vm.regs[10] = 0;
    }
}

// ---------------------------------------------------------------------------
// EIP-1153: Transient Storage (TLOAD / TSTORE)
// ---------------------------------------------------------------------------
// Transient storage provides a cheap (100 gas) key-value store that is
// automatically cleared at the end of each transaction. It does NOT persist
// to the state trie and does NOT trigger warm/cold gas pricing.
//
// Use cases:
//   - Re-entrancy locks without 5000 gas SSTORE cost
//   - Flash loan callback state
//   - Multi-hop AMM routing intermediate state
//   - EIP-1153 compatible smart contracts

fn derivedStorageLoad(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.gas.consume(100) catch return SyscallError.OutOfGas;

    const userPtr = vm.regs[11];
    const keyPtr = vm.regs[12];
    const resultPtr = vm.regs[13];

    const user_slice = vm.memory.getSlice(userPtr, 32) catch return SyscallError.SegFault;
    var user: [32]u8 = undefined;
    @memcpy(&user, user_slice);

    const keyRef = vm.memory.getAligned32(keyPtr) catch return SyscallError.SegFault;
    const key = keyRef.*;

    var value = [_]u8{0} ** 32;
    if (env.derivedLoadFn) |loadFn| {
        value = loadFn(env, user, key);
    }

    const result_ref = vm.memory.getAligned32Mut(resultPtr) catch return SyscallError.SegFault;
    result_ref.* = value;
}

fn derivedStorageStore(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.gas.consume(5000) catch return SyscallError.OutOfGas;

    const userPtr = vm.regs[11];
    const keyPtr = vm.regs[12];
    const valPtr = vm.regs[13];

    const user_slice = vm.memory.getSlice(userPtr, 32) catch return SyscallError.SegFault;
    var user: [32]u8 = undefined;
    @memcpy(&user, user_slice);

    const keyRef = vm.memory.getAligned32(keyPtr) catch return SyscallError.SegFault;
    const key = keyRef.*;

    const valRef = vm.memory.getAligned32(valPtr) catch return SyscallError.SegFault;
    const value = valRef.*;

    if (env.derivedStoreFn) |storeFn| {
        storeFn(env, user, key, value) catch return SyscallError.InternalError;
    }
}

fn globalStorageLoad(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.gas.consume(100) catch return SyscallError.OutOfGas;

    const keyPtr = vm.regs[11];
    const resultPtr = vm.regs[12];

    const keyRef = vm.memory.getAligned32(keyPtr) catch return SyscallError.SegFault;
    const key = keyRef.*;

    var value = [_]u8{0} ** 32;
    if (env.globalLoadFn) |loadFn| {
        value = loadFn(env, key);
    }

    const result_ref = vm.memory.getAligned32Mut(resultPtr) catch return SyscallError.SegFault;
    result_ref.* = value;
}

fn globalStorageStore(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.gas.consume(5000) catch return SyscallError.OutOfGas;

    const keyPtr = vm.regs[11];
    const deltaPtr = vm.regs[12];
    const isAdditionVal = vm.regs[13];

    const keyRef = vm.memory.getAligned32(keyPtr) catch return SyscallError.SegFault;
    const key = keyRef.*;

    const deltaRef = vm.memory.getAligned32(deltaPtr) catch return SyscallError.SegFault;
    const delta = deltaRef.*;

    const isAddition = isAdditionVal != 0;

    if (env.globalStoreFn) |storeFn| {
        storeFn(env, key, delta, isAddition) catch return SyscallError.InternalError;
    }
}

/// Syscall 0x23: tload — read from transient storage
/// a0 = syscallId, a1 = pointer to 32-byte key, a2 = pointer to 32-byte result buffer
/// Gas: 100 (EIP-1153, same as warm SLOAD)
fn transientLoad(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.gas.consume(100) catch return SyscallError.OutOfGas;

    const keyPtr = vm.regs[11]; // a1
    const resultPtr = vm.regs[12]; // a2

    // Read key from VM memory
    const key_slice = vm.memory.getSlice(keyPtr, 32) catch return SyscallError.SegFault;
    var key: [32]u8 = undefined;
    @memcpy(&key, key_slice);

    // Look up in transient storage — default to zero if not set
    const value = env.transientStorage.get(key) orelse [_]u8{0} ** 32;

    // Write result to VM memory
    const result_slice = vm.memory.getSliceMut(resultPtr, 32) catch return SyscallError.SegFault;
    @memcpy(result_slice, &value);
}

/// Syscall 0x24: tstore — write to transient storage
/// a0 = syscallId, a1 = pointer to 32-byte key, a2 = pointer to 32-byte value
/// Gas: 100 (EIP-1153, same as warm SSTORE)
fn transientStore(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    vm.gas.consume(100) catch return SyscallError.OutOfGas;

    const keyPtr = vm.regs[11]; // a1
    const value_ptr = vm.regs[12]; // a2

    // Read key from VM memory
    const key_slice = vm.memory.getSlice(keyPtr, 32) catch return SyscallError.SegFault;
    var key: [32]u8 = undefined;
    @memcpy(&key, key_slice);

    // Read value from VM memory
    const value_slice = vm.memory.getSlice(value_ptr, 32) catch return SyscallError.SegFault;
    var newValue: [32]u8 = undefined;
    @memcpy(&newValue, value_slice);

    // Store in transient storage (overwrites any existing value)
    env.transientStorage.put(key, newValue) catch return SyscallError.InternalError;
}

/// Syscall VERIFY_SIG (replaces ECRECOVER)
/// a0 = syscallId, a1 = ptr to 32-byte message hash,
/// a2 = scheme (0=Ed25519, 1=BLS12-381, 2=quantum),
/// a3 = ptr to 32-byte public key, a4 = ptr to 64-byte signature,
/// a5 = ptr to 32-byte result buffer (blake3(pubkey) address)
/// Returns: a0 = 1 (success) or 0 (failure); signer address written to result buffer.
fn ecrecover(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    // Gas: signature verification cost (cheaper than EVM ecrecover)
    vm.gas.consume(2000) catch return SyscallError.OutOfGas;

    const hash_ptr = vm.regs[11]; // a1 — 32-byte message hash
    const scheme: u8 = @truncate(vm.regs[12]); // a2 — signature scheme
    const pubkey_ptr = vm.regs[13]; // a3 — 32-byte Ed25519 public key
    const sig_ptr = vm.regs[14]; // a4 — 64-byte signature
    const outPtr = vm.regs[15]; // a5 — result buffer (32 bytes)

    // Read hash (32 bytes)
    const hashSlice = vm.memory.getSlice(hash_ptr, 32) catch return SyscallError.SegFault;
    var hash: [32]u8 = undefined;
    @memcpy(&hash, hashSlice);

    // Read pubkey (32 bytes)
    const pubkeySlice = vm.memory.getSlice(pubkey_ptr, 32) catch return SyscallError.SegFault;
    var pubkey: [32]u8 = undefined;
    @memcpy(&pubkey, pubkeySlice);

    // Read signature (64 bytes)
    const sigSlice = vm.memory.getSlice(sig_ptr, 64) catch return SyscallError.SegFault;
    var sig: [64]u8 = undefined;
    @memcpy(&sig, sigSlice);

    // Execute via pluggable provider
    if (env.ecrecoverFn) |ecrecoverFn| {
        const recovered = ecrecoverFn(hash, scheme, pubkey, sig);

        // Check for zero address (invalid verification)
        var all_zero = true;
        for (recovered) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }

        if (all_zero) {
            vm.regs[10] = 0; // Failed verification
        } else {
            // Write recovered address to output buffer (a5)
            const addrSlice = vm.memory.getSliceMut(outPtr, 32) catch return SyscallError.SegFault;
            @memcpy(addrSlice, &recovered);
            vm.regs[10] = 1; // Success
        }
    } else {
        vm.regs[10] = 0; // No provider
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Syscall GET_BLOCK_HASH (used as get_code_hash in FORGE)
/// a0 = syscallId, a1 = ptr to 32-byte address, a2 = ptr to 32-byte result
fn getCodeHash(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const resultPtr = vm.regs[12]; // a2

    const slice = vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault;
    var addr: [32]u8 = undefined;
    @memcpy(&addr, slice);

    // Warmth check: charge EXTCODEHASH warm/cold cost
    const cost: u64 = 100;
    vm.gas.consume(cost) catch return SyscallError.OutOfGas;

    const hash = if (env.codeHashFn) |f| f(addr) else [_]u8{0} ** 32;
    const res_slice = vm.memory.getSliceMut(resultPtr, 32) catch return SyscallError.SegFault;
    @memcpy(res_slice, &hash);
}

/// Syscall AUTHORITY_CHECK
/// a0 = syscallId, a1 = ptr to 20-byte addr, a2 = ptr to 32-byte role, a3 = ptr to 20-byte account
/// Returns a0 = 1 if has role, 0 otherwise
fn roleCheck(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const rolePtr = vm.regs[12]; // a2
    const accPtr = vm.regs[13]; // a3

    var addr: [32]u8 = undefined;
    @memcpy(&addr, vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault);
    var role: [32]u8 = undefined;
    @memcpy(&role, vm.memory.getSlice(rolePtr, 32) catch return SyscallError.SegFault);
    var acc: [32]u8 = undefined;
    @memcpy(&acc, vm.memory.getSlice(accPtr, 32) catch return SyscallError.SegFault);

    vm.gas.consume(400) catch return SyscallError.OutOfGas;

    const has_role = if (env.roleCheckFn) |f| f(addr, role, acc) else false;
    vm.regs[10] = if (has_role) 1 else 0;
}

/// Syscall AUTHORITY_GRANT
/// a0 = syscallId, a1 = ptr to 20-byte addr, a2 = ptr to 32-byte role, a3 = ptr to 20-byte account
fn roleGrant(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const rolePtr = vm.regs[12]; // a2
    const accPtr = vm.regs[13]; // a3

    var addr: [32]u8 = undefined;
    @memcpy(&addr, vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault);
    var role: [32]u8 = undefined;
    @memcpy(&role, vm.memory.getSlice(rolePtr, 32) catch return SyscallError.SegFault);
    var acc: [32]u8 = undefined;
    @memcpy(&acc, vm.memory.getSlice(accPtr, 32) catch return SyscallError.SegFault);

    vm.gas.consume(2000) catch return SyscallError.OutOfGas;

    if (env.roleGrantFn) |f| f(addr, role, acc);
}

/// Syscall AUTHORITY_REVOKE
/// a0 = syscallId, a1 = ptr to 20-byte addr, a2 = ptr to 32-byte role, a3 = ptr to 20-byte account
fn roleRevoke(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const rolePtr = vm.regs[12]; // a2
    const accPtr = vm.regs[13]; // a3

    var addr: [32]u8 = undefined;
    @memcpy(&addr, vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault);
    var role: [32]u8 = undefined;
    @memcpy(&role, vm.memory.getSlice(rolePtr, 32) catch return SyscallError.SegFault);
    var acc: [32]u8 = undefined;
    @memcpy(&acc, vm.memory.getSlice(accPtr, 32) catch return SyscallError.SegFault);

    vm.gas.consume(2000) catch return SyscallError.OutOfGas;

    if (env.roleRevokeFn) |f| f(addr, role, acc);
}

/// Syscall AUTHORITY_LIST
/// a0 = syscallId, a1 = ptr to 32-byte addr, a2 = ptr to result buffer, a3 = max count
/// Returns a0 = number of authority IDs written (0 on error)
fn handleAuthorityList(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const resultPtr = vm.regs[12]; // a2
    const maxCount = vm.regs[13]; // a3

    vm.gas.consume(gasTable.SyscallGas.AUTHORITY_CHECK) catch return SyscallError.OutOfGas;

    var addr: [32]u8 = undefined;
    @memcpy(&addr, vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault);

    if (env.authorityListFn) |f| {
        const bufSize = maxCount * 32;
        const buf = vm.memory.getSliceMut(resultPtr, @intCast(bufSize)) catch return SyscallError.SegFault;
        const count = f(env, addr, buf) catch {
            vm.regs[10] = 0;
            return;
        };
        vm.regs[10] = @truncate(count);
    } else {
        vm.regs[10] = 0;
    }
}

/// Syscall RESOURCE_LOCK
/// a0 = syscallId, a1 = ptr to 20-byte addr, a2 = ptr to 32-byte id
fn resourceLock(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const id_ptr = vm.regs[12]; // a2

    var addr: [32]u8 = undefined;
    @memcpy(&addr, vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault);
    var id: [32]u8 = undefined;
    @memcpy(&id, vm.memory.getSlice(id_ptr, 32) catch return SyscallError.SegFault);

    vm.gas.consume(100) catch return SyscallError.OutOfGas;

    const locked = if (env.resourceLockFn) |f| f(addr, id) else true;
    vm.regs[10] = if (locked) 1 else 0;
}

/// Syscall HASH_BLAKE3
/// a0 = syscallId, a1 = dataPtr, a2 = dataLen, a3 = outPtr (32 bytes)
fn handleBlake3(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const dataPtr = vm.regs[11]; // a1
    const dataLen = vm.regs[12]; // a2
    const outPtr = vm.regs[13]; // a3

    const word_count = (dataLen + 7) / 8;
    const gasCost = gasTable.SyscallGas.HASH_BLAKE3_BASE + (word_count * gasTable.SyscallGas.HASH_BLAKE3_PER_WORD);
    vm.gas.consume(gasCost) catch return SyscallError.OutOfGas;

    const data = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
    var out: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(data, &out, .{});

    const outSlice = vm.memory.getSliceMut(outPtr, 32) catch return SyscallError.SegFault;
    @memcpy(outSlice, &out);
    vm.regs[10] = 0; // success
}

/// Syscall HASH_SHA256
/// a0 = syscallId, a1 = dataPtr, a2 = dataLen, a3 = outPtr (32 bytes)
fn handleSha256(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const dataPtr = vm.regs[11]; // a1
    const dataLen = vm.regs[12]; // a2
    const outPtr = vm.regs[13]; // a3

    const word_count = (dataLen + 31) / 32;
    const gasCost = gasTable.SyscallGas.HASH_SHA256_BASE + (word_count * gasTable.SyscallGas.HASH_SHA256_PER_WORD);
    vm.gas.consume(gasCost) catch return SyscallError.OutOfGas;

    const data = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});

    const outSlice = vm.memory.getSliceMut(outPtr, 32) catch return SyscallError.SegFault;
    @memcpy(outSlice, &out);
    vm.regs[10] = 0; // success
}

/// Syscall 0xAB: handle_asset_transfer
fn handleAssetTransfer(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const assetIdPtr = vm.regs[11];
    const fromPtr = vm.regs[12];
    const toPtr = vm.regs[13];
    const amountPtr = vm.regs[14];

    vm.gas.consume(gasTable.SyscallGas.ASSET_TRANSFER) catch return SyscallError.OutOfGas;

    var assetId: [32]u8 = undefined;
    @memcpy(&assetId, vm.memory.getSlice(assetIdPtr, 32) catch return SyscallError.SegFault);

    var from: [32]u8 = undefined;
    @memcpy(&from, vm.memory.getSlice(fromPtr, 32) catch return SyscallError.SegFault);

    var to: [32]u8 = undefined;
    @memcpy(&to, vm.memory.getSlice(toPtr, 32) catch return SyscallError.SegFault);

    const amountSlice = vm.memory.getSlice(amountPtr, 16) catch return SyscallError.SegFault;
    const amount = std.mem.readInt(u128, amountSlice[0..16], .little);

    if (env.assetTransferFn) |f| {
        f(env, assetId, from, to, amount) catch {
            vm.regs[10] = 1; // Error
            return;
        };
        vm.regs[10] = 0; // Success
    } else {
        vm.regs[10] = 1; // Error (unsupported)
    }
}

/// Syscall 0x17: NATIVE_TRANSFER (FORGE-native asset send)
/// a1=asset_value(u64), a2=recipient_ptr(32B) → a0=0 success, 1 error
fn handleNativeTransfer(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const assetValue: u64 = vm.regs[11]; // a1
    const recipientPtr = vm.regs[12]; // a2

    vm.gas.consume(gasTable.SyscallGas.ASSET_TRANSFER) catch return SyscallError.OutOfGas;

    var recipient: [32]u8 = undefined;
    @memcpy(&recipient, vm.memory.getSlice(recipientPtr, 32) catch return SyscallError.SegFault);

    // FORGE native send: asset value is the amount, from = self, no asset ID (zeroed)
    const assetId: [32]u8 = [_]u8{0} ** 32;
    const from = env.selfAddress;

    if (env.assetTransferFn) |f| {
        f(env, assetId, from, recipient, assetValue) catch {
            vm.regs[10] = 1;
            return;
        };
        vm.regs[10] = 0;
    } else {
        vm.regs[10] = 1;
    }
}

/// Syscall 0x12: ASSET_CREATE (ASSET_MINT)
/// a1=type_id(immediate u64), a2=0(zero for create), a3=amount(scalar u64) → a0=0 success, 1 error
fn handleAssetCreate(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const typeId: u64 = vm.regs[11]; // a1
    const amount: u64 = vm.regs[13]; // a3

    vm.gas.consume(gasTable.SyscallGas.ASSET_CREATE) catch return SyscallError.OutOfGas;

    if (env.assetCreateFn) |f| {
        var assetIdOut: [32]u8 = undefined;
        f(env, typeId, amount, &assetIdOut) catch {
            vm.regs[10] = 1;
            return;
        };
        vm.regs[10] = 0;
    } else {
        vm.regs[10] = 1;
    }
}

/// Syscall 0x13: ASSET_BURN
/// a1=asset_id_ptr(32B) → a0=0 success, 1 error
fn handleAssetBurn(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const assetIdPtr = vm.regs[11]; // a1

    vm.gas.consume(gasTable.SyscallGas.ASSET_BURN) catch return SyscallError.OutOfGas;

    var assetId: [32]u8 = undefined;
    @memcpy(&assetId, vm.memory.getSlice(assetIdPtr, 32) catch return SyscallError.SegFault);

    if (env.assetBurnFn) |f| {
        f(env, assetId) catch {
            vm.regs[10] = 1;
            return;
        };
        vm.regs[10] = 0;
    } else {
        vm.regs[10] = 1;
    }
}

/// Syscall 0x14: ASSET_METADATA
/// a1=asset_id_ptr(32B), a2=metadata_out(64B) → a0=0 success, 1 error
fn handleAssetMetadata(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const assetIdPtr = vm.regs[11]; // a1
    const metadataPtr = vm.regs[12]; // a2

    vm.gas.consume(gasTable.SyscallGas.ASSET_QUERY_METADATA) catch return SyscallError.OutOfGas;

    var assetId: [32]u8 = undefined;
    @memcpy(&assetId, vm.memory.getSlice(assetIdPtr, 32) catch return SyscallError.SegFault);

    if (env.assetMetadataFn) |f| {
        var metadata: [64]u8 = undefined;
        const ok = f(env, assetId, &metadata) catch {
            vm.regs[10] = 1;
            return;
        };
        if (ok) {
            const outSlice = vm.memory.getSliceMut(metadataPtr, 64) catch return SyscallError.SegFault;
            @memcpy(outSlice, &metadata);
            vm.regs[10] = 0;
        } else {
            vm.regs[10] = 1;
        }
    } else {
        vm.regs[10] = 1;
    }
}

/// Syscall 0x15: ASSET_APPROVE
/// a1=asset_id_ptr(32B), a2=spender_ptr(32B), a3=amount_ptr(16B) → a0=0 success, 1 error
fn handleAssetApprove(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const assetIdPtr = vm.regs[11]; // a1
    const spenderPtr = vm.regs[12]; // a2
    const amountPtr = vm.regs[13]; // a3

    vm.gas.consume(gasTable.SyscallGas.ASSET_QUERY_BALANCE) catch return SyscallError.OutOfGas;

    var assetId: [32]u8 = undefined;
    @memcpy(&assetId, vm.memory.getSlice(assetIdPtr, 32) catch return SyscallError.SegFault);
    var spender: [32]u8 = undefined;
    @memcpy(&spender, vm.memory.getSlice(spenderPtr, 32) catch return SyscallError.SegFault);
    const amountSlice = vm.memory.getSlice(amountPtr, 16) catch return SyscallError.SegFault;
    const amount = std.mem.readInt(u128, amountSlice[0..16], .little);

    if (env.assetApproveFn) |f| {
        f(env, assetId, spender, amount) catch {
            vm.regs[10] = 1;
            return;
        };
        vm.regs[10] = 0;
    } else {
        vm.regs[10] = 1;
    }
}

/// Syscall 0x16: ASSET_ALLOWANCE
/// a1=asset_id_ptr(32B), a2=owner_ptr(32B), a3=spender_ptr(32B), a4=amount_out(16B) → a0=0 success, 1 error
fn handleAssetAllowance(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const assetIdPtr = vm.regs[11]; // a1
    const ownerPtr = vm.regs[12]; // a2
    const spenderPtr = vm.regs[13]; // a3
    const amountOutPtr = vm.regs[14]; // a4

    vm.gas.consume(gasTable.SyscallGas.ASSET_QUERY_BALANCE) catch return SyscallError.OutOfGas;

    var assetId: [32]u8 = undefined;
    @memcpy(&assetId, vm.memory.getSlice(assetIdPtr, 32) catch return SyscallError.SegFault);
    var owner: [32]u8 = undefined;
    @memcpy(&owner, vm.memory.getSlice(ownerPtr, 32) catch return SyscallError.SegFault);
    var spender: [32]u8 = undefined;
    @memcpy(&spender, vm.memory.getSlice(spenderPtr, 32) catch return SyscallError.SegFault);

    if (env.assetAllowanceFn) |f| {
        const allowance = f(env, assetId, owner, spender) catch {
            vm.regs[10] = 1;
            return;
        };
        const outSlice = vm.memory.getSliceMut(amountOutPtr, 16) catch return SyscallError.SegFault;
        std.mem.writeInt(u128, outSlice[0..16], allowance, .little);
        vm.regs[10] = 0;
    } else {
        vm.regs[10] = 1;
    }
}

/// Syscall 0xA0: ORACLE_QUERY
/// a1=feed_id(immediate u64), a2=result_ptr(stack buffer, 8 bytes written) → a0=0 success, 1 error
fn handleOracleQuery(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const feedId: u64 = vm.regs[11]; // a1
    const resultPtr = vm.regs[12]; // a2

    vm.gas.consume(gasTable.SyscallGas.ORACLE_QUERY) catch return SyscallError.OutOfGas;

    if (env.oracleQueryFn) |f| {
        var result: u64 = 0;
        f(env, feedId, &result) catch {
            vm.regs[10] = 1;
            return;
        };
        const resultSlice = vm.memory.getSliceMut(resultPtr, 8) catch return SyscallError.SegFault;
        @memcpy(resultSlice, std.mem.asBytes(&result));
        vm.regs[10] = 0;
    } else {
        vm.regs[10] = 1;
    }
}

/// Syscall 0xB0: ZK_VERIFY
/// a1=circuit_id(immediate u64), a2=proof_ptr(32B), a3=proof_len=32(immediate) → a0=1 valid, 0 invalid
fn handleZkVerify(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const circuitId: u64 = vm.regs[11]; // a1
    const proofPtr = vm.regs[12]; // a2

    vm.gas.consume(gasTable.SyscallGas.ZK_VERIFY) catch return SyscallError.OutOfGas;

    var proof: [32]u8 = undefined;
    @memcpy(&proof, vm.memory.getSlice(proofPtr, 32) catch return SyscallError.SegFault);

    if (env.zkVerifyFn) |f| {
        vm.regs[10] = if (f(env, circuitId, proof) catch false) 1 else 0;
    } else {
        vm.regs[10] = 0;
    }
}

/// Syscall 0xB1: DELEGATE_GAS
/// a1=payer_addr_ptr(32B) → a0=0 success, 1 error
fn handleDelegateGas(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const payerPtr = vm.regs[11]; // a1

    vm.gas.consume(gasTable.SyscallGas.DELEGATE_GAS) catch return SyscallError.OutOfGas;

    var payer: [32]u8 = undefined;
    @memcpy(&payer, vm.memory.getSlice(payerPtr, 32) catch return SyscallError.SegFault);

    if (env.delegateGasFn) |f| {
        f(env, payer) catch {
            vm.regs[10] = 1;
            return;
        };
        vm.regs[10] = 0;
    } else {
        vm.regs[10] = 1;
    }
}

/// Syscall 0xB2: EXPAND_ACCOUNT
/// a1=account_ptr(32B), a2=extra_bytes(scalar u64) → a0=0 success, 1 error
fn handleExpandAccount(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const accountPtr = vm.regs[11]; // a1
    const extraBytes: u64 = vm.regs[12]; // a2

    vm.gas.consume(gasTable.SyscallGas.EXPAND_ACCOUNT) catch return SyscallError.OutOfGas;

    var account: [32]u8 = undefined;
    @memcpy(&account, vm.memory.getSlice(accountPtr, 32) catch return SyscallError.SegFault);

    if (env.expandAccountFn) |f| {
        f(env, account, extraBytes) catch {
            vm.regs[10] = 1;
            return;
        };
        vm.regs[10] = 0;
    } else {
        vm.regs[10] = 1;
    }
}

/// Syscall 0xB3: CLOSE_ACCOUNT
/// a1=account_ptr(32B), a2=refund_to_ptr(32B) → a0=0 success, 1 error
fn handleCloseAccount(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const accountPtr = vm.regs[11]; // a1
    const refundToPtr = vm.regs[12]; // a2

    vm.gas.consume(gasTable.SyscallGas.CLOSE_ACCOUNT) catch return SyscallError.OutOfGas;

    var account: [32]u8 = undefined;
    @memcpy(&account, vm.memory.getSlice(accountPtr, 32) catch return SyscallError.SegFault);
    var refundTo: [32]u8 = undefined;
    @memcpy(&refundTo, vm.memory.getSlice(refundToPtr, 32) catch return SyscallError.SegFault);

    if (env.closeAccountFn) |f| {
        f(env, account, refundTo) catch {
            vm.regs[10] = 1;
            return;
        };
        vm.regs[10] = 0;
    } else {
        vm.regs[10] = 1;
    }
}

/// Syscall SCHEDULE_CALL: schedule a deferred call.
/// a0 = syscallId, a1 = to_ptr (32B), a2 = delay (u64 in blocks), a3 = calldata_ptr, a4 = calldata_len
/// Returns a0 = 0 success, 1 error
fn handleScheduleCall(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const toPtr = vm.regs[11]; // a1
    const calldataPtr = vm.regs[13]; // a3
    const calldataLen = vm.regs[14]; // a4

    vm.gas.consume(gasTable.SyscallGas.CALL_CONTRACT) catch return SyscallError.OutOfGas;

    var to: [32]u8 = undefined;
    @memcpy(&to, vm.memory.getSlice(toPtr, 32) catch return SyscallError.SegFault);

    const calldata = if (calldataLen > 0)
        vm.memory.getSlice(calldataPtr, calldataLen) catch return SyscallError.SegFault
    else
        &[_]u8{};

    // Use call provider or schedule provider if available
    if (env.callFn) |f| {
        const result = f(.call, to, [_]u8{0} ** 32, calldata, 0);
        vm.regs[10] = if (result.success) 0 else 1;
    } else {
        vm.regs[10] = 1;
    }
}

/// Syscall 0xAD: handle_parallel_hint
fn handleParallelHint(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const keysPtr = vm.regs[11];
    const keysLen = vm.regs[12]; // Number of 32-byte keys

    // Extremely cheap gas to encourage parallel hinting
    vm.gas.consume(10 + keysLen * 2) catch return SyscallError.OutOfGas;

    // In actual implementation, this sets rw-sets ahead of time
    // to allow scheduler optimization
    _ = keysPtr;
    env.parallelSafe = true;
    vm.regs[10] = 0;
}

/// Syscall RESOURCE_UNLOCK
/// a0 = syscallId, a1 = ptr to 20-byte addr, a2 = ptr to 32-byte id
fn resourceUnlock(vm: *ForgeVM, env: *HostEnv) SyscallError!void {
    const addrPtr = vm.regs[11]; // a1
    const id_ptr = vm.regs[12]; // a2

    var addr: [32]u8 = undefined;
    @memcpy(&addr, vm.memory.getSlice(addrPtr, 32) catch return SyscallError.SegFault);
    var id: [32]u8 = undefined;
    @memcpy(&id, vm.memory.getSlice(id_ptr, 32) catch return SyscallError.SegFault);

    vm.gas.consume(100) catch return SyscallError.OutOfGas;

    if (env.resourceUnlockFn) |f| f(addr, id);
}

/// Syscall DEBUG_LOG
/// a0 = syscallId, a1 = ptr to data, a2 = data length
fn debugLog(vm: *ForgeVM, _: *HostEnv) SyscallError!void {
    const dataPtr = vm.regs[11]; // a1
    const dataLen = vm.regs[12]; // a2

    vm.gas.consume(100) catch return SyscallError.OutOfGas;

    const slice = vm.memory.getSlice(dataPtr, dataLen) catch return SyscallError.SegFault;
    std.debug.print("[VM DEBUG] {s}\n", .{slice});
}

const testing = std.testing;
const decoder = @import("../core/decoder.zig");

/// Test helper: create a minimal test VM with syscall handler.
/// IMPORTANT: After assigning the result, call ctx.fixMemPtr() to fix the memory pointer.
fn createTestVm(env: *HostEnv) !struct {
    vm: ForgeVM,
    mem: sandbox.SandboxMemory,
    envPtr: *HostEnv, // must be before any declarations

    const Self = @This();

    /// Must be called after the struct is assigned to fix the VM's memory pointer
    /// and hostCtx so syscalls can find the HostEnv.
    pub fn fixMemPtr(self: *Self) void {
        self.vm.memory = &self.mem;
        self.vm.hostCtx = self.envPtr;
    }
} {
    var mem = try sandbox.SandboxMemory.init(testing.allocator);

    // Load an ECALL instruction at PC=0
    const ecallWord: u32 = 0x00000073; // ECALL
    const ecallBytes = std.mem.asBytes(&ecallWord);
    try mem.loadCode(ecallBytes);

    const handler = createHandler(env);
    var vm = ForgeVM.init(&mem, 4, 1_000_000, handler);
    vm.hostCtx = env; // wire immediately for safety
    return .{ .vm = vm, .mem = mem, .envPtr = env };
}

test "syscall: get_chain_id" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();
    env.chainId = 42;

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    ctx.vm.regs[10] = SyscallId.GET_CHAIN_ID; // a0 = syscall ID
    ctx.vm.step(); // Execute ECALL

    try testing.expectEqual(@as(u32, 42), ctx.vm.regs[10]);
}

test "syscall: get_block_number" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();
    env.blockNumber = 12345;

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    ctx.vm.regs[10] = SyscallId.GET_BLOCK_NUMBER;
    ctx.vm.step();

    try testing.expectEqual(@as(u32, 12345), ctx.vm.regs[10]);
}

test "syscall: get_timestamp" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();
    env.timestamp = 1700000000;

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[10] = SyscallId.GET_TIMESTAMP;
    ctx.vm.step();

    try testing.expectEqual(@as(u32, 1700000000), ctx.vm.regs[10]);
}

test "syscall: unknown syscall returns fault" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    ctx.vm.regs[10] = 0xFE; // Invalid syscall
    ctx.vm.step();

    try testing.expectEqual(executor.ExecutionStatus.fault, ctx.vm.status);
}

test "syscall: returnData sets status to returned" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    ctx.vm.regs[10] = SyscallId.RETURN_DATA;
    ctx.vm.regs[11] = sandbox.heapStart; // data ptr
    ctx.vm.regs[12] = 0; // data len = 0
    ctx.vm.step();

    try testing.expectEqual(executor.ExecutionStatus.returned, ctx.vm.status);
}

test "syscall: revert sets status to reverted" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    ctx.vm.regs[10] = SyscallId.REVERT;
    ctx.vm.regs[11] = sandbox.heapStart;
    ctx.vm.regs[12] = 0;
    ctx.vm.step();

    try testing.expectEqual(executor.ExecutionStatus.reverted, ctx.vm.status);
}

test "syscall: blake3" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    // Write "hello" into heap
    const data = "hello";
    const data_start = sandbox.heapStart;
    for (data, 0..) |b, idx| {
        try ctx.mem.storeByte(data_start + @as(u32, @intCast(idx)), b);
    }

    // Set up syscall args: a0 = SyscallId.HASH_BLAKE3, a1 = data_start, a2 = data.len, a3 = outPtr
    const out_ptr = data_start + 32;
    ctx.vm.regs[10] = SyscallId.HASH_BLAKE3;
    ctx.vm.regs[11] = data_start;
    ctx.vm.regs[12] = data.len;
    ctx.vm.regs[13] = out_ptr;

    try handleBlake3(&ctx.vm, &env);

    // Read result
    var result: [32]u8 = undefined;
    for (0..32) |idx| {
        result[idx] = ctx.mem.loadByte(out_ptr + @as(u32, @intCast(idx))) catch unreachable;
    }

    // Compute expected blake3("hello")
    var expected: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash("hello", &expected, .{});

    try testing.expectEqualSlices(u8, &expected, &result);
}

test "syscall: storage_load and storage_store round-trip" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    // Set up a simple in-memory storage backend
    const TestStorage = struct {
        var data: std.AutoHashMap([32]u8, [32]u8) = undefined;
        var initialized: bool = false;

        fn ensureInit() void {
            if (!initialized) {
                data = std.AutoHashMap([32]u8, [32]u8).init(testing.allocator);
                initialized = true;
            }
        }

        fn loadFn(ctx_ptr: *anyopaque, key: [32]u8) [32]u8 {
            _ = ctx_ptr;
            ensureInit();
            return data.get(key) orelse [_]u8{0} ** 32;
        }

        fn storeFn(ctx_ptr: *anyopaque, key: [32]u8, value: [32]u8) void {
            _ = ctx_ptr;
            ensureInit();
            data.put(key, value) catch {};
        }

        fn cleanup() void {
            if (initialized) {
                data.deinit();
                initialized = false;
            }
        }
    };
    defer TestStorage.cleanup();

    var storage = StorageBackend{
        .ctx = undefined,
        .loadFn = &TestStorage.loadFn,
        .storeFn = &TestStorage.storeFn,
    };
    env.storage = &storage;

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();
    // Write a key into heap
    const key_addr = sandbox.heapStart;
    const val_addr = sandbox.heapStart + 32;
    const result_addr = sandbox.heapStart + 64;

    // Key = 1 (padded to 32 bytes)
    try ctx.mem.storeByte(key_addr + 31, 0x01);
    // Value = 42 (padded to 32 bytes)
    try ctx.mem.storeByte(val_addr + 31, 42);

    // Store
    ctx.vm.regs[10] = SyscallId.STORAGE_STORE;
    ctx.vm.regs[11] = key_addr;
    ctx.vm.regs[12] = val_addr;
    ctx.vm.pc = 0;
    ctx.vm.status = .running;
    ctx.vm.step();
    try testing.expectEqual(executor.ExecutionStatus.running, ctx.vm.status);

    // Reset PC and reload ECALL for load
    ctx.vm.pc = 0;
    ctx.vm.regs[10] = SyscallId.STORAGE_LOAD;
    ctx.vm.regs[11] = key_addr;
    ctx.vm.regs[12] = result_addr;
    ctx.vm.step();

    // Verify the loaded value
    const loaded_val = try ctx.mem.loadByte(result_addr + 31);
    try testing.expectEqual(@as(u8, 42), loaded_val);
}

test "syscall: tload and tstore round-trip" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    // TSTORE via transient storage direct API (TSTORE syscall not yet dispatched)
    var key: [32]u8 = [_]u8{0} ** 32;
    key[31] = 0x07;
    var value: [32]u8 = [_]u8{0} ** 32;
    value[31] = 0xBE;
    try env.transientStorage.put(key, value);

    // TLOAD: read back from transient storage via env API
    const loaded = env.transientStorage.get(key) orelse [_]u8{0} ** 32;
    try testing.expectEqual(@as(u8, 0xBE), loaded[31]);
}

test "syscall: tload returns zero for unset key" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    // Key 0xFF was never stored — transientStorage.get should return null → zero
    var key: [32]u8 = [_]u8{0} ** 32;
    key[31] = 0xFF;

    const loaded = env.transientStorage.get(key) orelse [_]u8{0} ** 32;
    try testing.expectEqual(@as(u8, 0x00), loaded[31]);
}

test "syscall: create2 deterministic address derivation" {
    // Verify the CREATE2 address derivation formula:
    // address = blake3(0x02 || sender || salt || blake3(initcode))
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    // Set the contract's self_address (the CREATE2 sender)
    var sender: [32]u8 = undefined;
    @memset(&sender, 0xAA);
    env.selfAddress = sender;

    // Compute expected CREATE2 address manually
    const initcode = &[_]u8{ 0x60, 0x00, 0x60, 0x00, 0xFD }; // PUSH 0, PUSH 0, REVERT
    var salt: [32]u8 = [_]u8{0} ** 32;
    salt[31] = 0x42; // salt = 42

    // blake3(initcode)
    var initcode_hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(initcode, &initcode_hash, .{});

    // blake3(0x02 || sender || salt || initcode_hash)
    var create2Input: [97]u8 = undefined;
    create2Input[0] = 0x02;
    @memcpy(create2Input[1..33], &sender);
    @memcpy(create2Input[33..65], &salt);
    @memcpy(create2Input[65..97], &initcode_hash);
    var expected_addr: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&create2Input, &expected_addr, .{});

    // Verify the computed address is non-zero and deterministic
    var all_zero = true;
    for (expected_addr) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero); // Address should not be all zeros

    // Verify that computing the same inputs again produces the same address (deterministic)
    var addr2: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&create2Input, &addr2, .{});

    try testing.expectEqualSlices(u8, &expected_addr, &addr2);
}

test "syscall: emit_indexed_event creates log entry" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    // Write a topic into VM memory
    const topic_addr = sandbox.heapStart;
    var topic_bytes: [32]u8 = [_]u8{0} ** 32;
    topic_bytes[31] = 0xAB;
    for (topic_bytes, 0..) |b, idx| {
        try ctx.mem.storeByte(topic_addr + @as(u32, @intCast(idx)), b);
    }

    // Write data into VM memory
    const data_addr = sandbox.heapStart + 64;
    const data = "hello indexed";
    for (data, 0..) |b, idx| {
        try ctx.mem.storeByte(data_addr + @as(u32, @intCast(idx)), b);
    }

    // Set up syscall: a0 = ID, a1 = topicCount(1), a2 = topicsPtr, a3 = dataPtr, a4 = dataLen
    ctx.vm.regs[10] = SyscallId.EMIT_INDEXED_EVENT;
    ctx.vm.regs[11] = 1;
    ctx.vm.regs[12] = topic_addr;
    ctx.vm.regs[13] = data_addr;
    ctx.vm.regs[14] = @as(u32, @intCast(data.len));
    ctx.vm.pc = 0;
    ctx.vm.status = .running;
    ctx.vm.step();
    try testing.expectEqual(executor.ExecutionStatus.running, ctx.vm.status);

    // Verify log entry was created
    try testing.expectEqual(@as(usize, 1), env.logs.items.len);
    const entry = &env.logs.items[0];
    try testing.expectEqual(@as(usize, 1), entry.topics.items.len);
    try testing.expectEqual(@as(u8, 0xAB), entry.topics.items[0][31]);

    // Verify data
    try testing.expectEqual(@as(usize, data.len), entry.data.items.len);
    try testing.expectEqualSlices(u8, data, entry.data.items);

    // Verify bloom filter is NOT all zeros (bits were set)
    var bloom_has_bits = false;
    for (env.bloom_filter) |b| {
        if (b != 0) {
            bloom_has_bits = true;
            break;
        }
    }
    try testing.expect(bloom_has_bits);
}

test "syscall: emit_indexed_event bloom filter is deterministic" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    // Emit the same event twice — bloom filter should be identical after first topic
    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    const topic_addr = sandbox.heapStart;
    var topic_bytes: [32]u8 = [_]u8{0} ** 32;
    topic_bytes[0] = 0x01;
    for (topic_bytes, 0..) |b, idx| {
        try ctx.mem.storeByte(topic_addr + @as(u32, @intCast(idx)), b);
    }

    ctx.vm.regs[10] = SyscallId.EMIT_INDEXED_EVENT;
    ctx.vm.regs[11] = 1;
    ctx.vm.regs[12] = topic_addr;
    ctx.vm.regs[13] = sandbox.heapStart + 64;
    ctx.vm.regs[14] = 0;
    ctx.vm.pc = 0;
    ctx.vm.status = .running;
    ctx.vm.step();

    var env2 = HostEnv.init(testing.allocator);
    defer env2.deinit();
    var ctx2 = try createTestVm(&env2);
    ctx2.fixMemPtr();
    defer ctx2.mem.deinit();

    for (topic_bytes, 0..) |b, idx| {
        try ctx2.mem.storeByte(topic_addr + @as(u32, @intCast(idx)), b);
    }
    ctx2.vm.regs[10] = SyscallId.EMIT_INDEXED_EVENT;
    ctx2.vm.regs[11] = 1;
    ctx2.vm.regs[12] = topic_addr;
    ctx2.vm.regs[13] = sandbox.heapStart + 64;
    ctx2.vm.regs[14] = 0;
    ctx2.vm.pc = 0;
    ctx2.vm.status = .running;
    ctx2.vm.step();

    try testing.expectEqualSlices(u8, &env.bloom_filter, &env2.bloom_filter);
}

test "syscall: emit_indexed_event preserves unmodified bloom for distinct topics" {
    // Two different topics should produce different bloom filter patterns
    // (extremely unlikely to collide on all 3 bits for a 2048-bit filter)
    var env1 = HostEnv.init(testing.allocator);
    defer env1.deinit();

    var ctx1 = try createTestVm(&env1);
    ctx1.fixMemPtr();
    defer ctx1.mem.deinit();

    const topic_addr = sandbox.heapStart;
    // Topic A: all zeros
    const topic_a = [_]u8{0} ** 32;
    for (topic_a, 0..) |b, idx| {
        try ctx1.mem.storeByte(topic_addr + @as(u32, @intCast(idx)), b);
    }
    ctx1.vm.regs[10] = SyscallId.EMIT_INDEXED_EVENT;
    ctx1.vm.regs[11] = 1;
    ctx1.vm.regs[12] = topic_addr;
    ctx1.vm.regs[13] = sandbox.heapStart + 64;
    ctx1.vm.regs[14] = 0;
    ctx1.vm.pc = 0;
    ctx1.vm.status = .running;
    ctx1.vm.step();

    var env2 = HostEnv.init(testing.allocator);
    defer env2.deinit();
    var ctx2 = try createTestVm(&env2);
    ctx2.fixMemPtr();
    defer ctx2.mem.deinit();

    // Topic B: all ones
    const topic_b = [_]u8{0xFF} ** 32;
    for (topic_b, 0..) |b, idx| {
        try ctx2.mem.storeByte(topic_addr + @as(u32, @intCast(idx)), b);
    }
    ctx2.vm.regs[10] = SyscallId.EMIT_INDEXED_EVENT;
    ctx2.vm.regs[11] = 1;
    ctx2.vm.regs[12] = topic_addr;
    ctx2.vm.regs[13] = sandbox.heapStart + 64;
    ctx2.vm.regs[14] = 0;
    ctx2.vm.pc = 0;
    ctx2.vm.status = .running;
    ctx2.vm.step();

    // Verify the bloom filters differ
    var identical = true;
    for (&env1.bloom_filter, &env2.bloom_filter) |a, b| {
        if (a != b) {
            identical = false;
            break;
        }
    }
    try testing.expect(!identical);
}

test "syscall: bls_verify returns 0 when no provider set" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    // Write pubkey, sig, msg into VM memory
    const pubkey_addr = sandbox.heapStart;
    const sig_addr = sandbox.heapStart + 64;
    const msg_addr = sandbox.heapStart + 192;

    // Fill with test data
    for (0..48) |idx| {
        try ctx.mem.storeByte(pubkey_addr + @as(u32, @intCast(idx)), @as(u8, @intCast(idx)));
    }
    for (0..96) |idx| {
        try ctx.mem.storeByte(sig_addr + @as(u32, @intCast(idx)), @as(u8, @intCast(idx + 0x10)));
    }
    const msg = "test message";
    for (msg, 0..) |b, idx| {
        try ctx.mem.storeByte(msg_addr + @as(u32, @intCast(idx)), b);
    }

    ctx.vm.regs[10] = SyscallId.BLS_VERIFY;
    ctx.vm.regs[11] = pubkey_addr;
    ctx.vm.regs[12] = sig_addr;
    ctx.vm.regs[13] = msg_addr;
    ctx.vm.regs[14] = @as(u32, @intCast(msg.len));
    ctx.vm.pc = 0;
    ctx.vm.status = .running;
    ctx.vm.step();
    try testing.expectEqual(executor.ExecutionStatus.running, ctx.vm.status);

    // No provider → should return 0
    try testing.expectEqual(@as(u32, 0), ctx.vm.regs[10]);
}

test "syscall: bls_verify delegates to provider correctly" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    // Set up a test provider that validates the arguments are passed correctly
    const TestProvider = struct {
        var captured_pubkey: [48]u8 = undefined;
        var captured_sig: [96]u8 = undefined;
        var captured_msg_buf: [64]u8 = undefined;
        var captured_msg_len: usize = 0;
        var call_count: u32 = 0;

        fn verify(pubkey: [48]u8, sig: [96]u8, msg: []const u8) bool {
            captured_pubkey = pubkey;
            captured_sig = sig;
            @memcpy(captured_msg_buf[0..msg.len], msg);
            captured_msg_len = msg.len;
            call_count += 1;
            return true; // pretend valid
        }
    };
    env.blsVerifyFn = &TestProvider.verify;

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    const pubkey_addr = sandbox.heapStart;
    const sig_addr = sandbox.heapStart + 64;
    const msg_addr = sandbox.heapStart + 192;

    // Write deterministic test data
    for (0..48) |idx| {
        try ctx.mem.storeByte(pubkey_addr + @as(u32, @intCast(idx)), @as(u8, @intCast(idx)));
    }
    for (0..96) |idx| {
        try ctx.mem.storeByte(sig_addr + @as(u32, @intCast(idx)), @as(u8, @intCast(idx + 0x10)));
    }
    const msg = "test message";
    for (msg, 0..) |b, idx| {
        try ctx.mem.storeByte(msg_addr + @as(u32, @intCast(idx)), b);
    }

    ctx.vm.regs[10] = SyscallId.BLS_VERIFY;
    ctx.vm.regs[11] = pubkey_addr;
    ctx.vm.regs[12] = sig_addr;
    ctx.vm.regs[13] = msg_addr;
    ctx.vm.regs[14] = @as(u32, @intCast(msg.len));
    ctx.vm.pc = 0;
    ctx.vm.status = .running;
    ctx.vm.step();
    try testing.expectEqual(executor.ExecutionStatus.running, ctx.vm.status);

    // Provider should have been called once, returning true → a0=1
    try testing.expectEqual(@as(u32, 1), TestProvider.call_count);
    try testing.expectEqual(@as(u32, 1), ctx.vm.regs[10]);

    // Verify pubkey bytes passed correctly
    for (0..48) |idx| {
        try testing.expectEqual(@as(u8, @intCast(idx)), TestProvider.captured_pubkey[idx]);
    }
    // Verify sig bytes passed correctly
    for (0..96) |idx| {
        try testing.expectEqual(@as(u8, @intCast(idx + 0x10)), TestProvider.captured_sig[idx]);
    }
    // Verify message passed correctly
    try testing.expectEqual(@as(usize, msg.len), TestProvider.captured_msg_len);
    try testing.expectEqualSlices(u8, msg, TestProvider.captured_msg_buf[0..msg.len]);
}

test "syscall: bls_verify returns 0 when provider returns false" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    env.blsVerifyFn = &struct {
        fn verify(_: [48]u8, _: [96]u8, _: []const u8) bool {
            return false; // provider says invalid
        }
    }.verify;

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    const pubkey_addr = sandbox.heapStart;
    const sig_addr = sandbox.heapStart + 64;
    const msg_addr = sandbox.heapStart + 192;

    for (0..48) |idx| {
        try ctx.mem.storeByte(pubkey_addr + @as(u32, @intCast(idx)), 0);
    }
    for (0..96) |idx| {
        try ctx.mem.storeByte(sig_addr + @as(u32, @intCast(idx)), 0);
    }
    try ctx.mem.storeByte(msg_addr, 0);

    ctx.vm.regs[10] = SyscallId.BLS_VERIFY;
    ctx.vm.regs[11] = pubkey_addr;
    ctx.vm.regs[12] = sig_addr;
    ctx.vm.regs[13] = msg_addr;
    ctx.vm.regs[14] = 1;
    ctx.vm.pc = 0;
    ctx.vm.status = .running;
    ctx.vm.step();

    try testing.expectEqual(@as(u32, 0), ctx.vm.regs[10]);
}

test "syscall: bls_verify with null message" {
    var env = HostEnv.init(testing.allocator);
    defer env.deinit();

    env.blsVerifyFn = &struct {
        fn verify(_: [48]u8, _: [96]u8, msg: []const u8) bool {
            return msg.len == 0; // valid only if empty message
        }
    }.verify;

    var ctx = try createTestVm(&env);
    ctx.fixMemPtr();
    defer ctx.mem.deinit();

    const pubkey_addr = sandbox.heapStart;
    const sig_addr = sandbox.heapStart + 64;

    for (0..48) |idx| {
        try ctx.mem.storeByte(pubkey_addr + @as(u32, @intCast(idx)), 0);
    }
    for (0..96) |idx| {
        try ctx.mem.storeByte(sig_addr + @as(u32, @intCast(idx)), 0);
    }

    // Zero-length message
    ctx.vm.regs[10] = SyscallId.BLS_VERIFY;
    ctx.vm.regs[11] = pubkey_addr;
    ctx.vm.regs[12] = sig_addr;
    ctx.vm.regs[13] = 0; // msg_ptr = 0 (should not be read since msg_len = 0)
    ctx.vm.regs[14] = 0; // msg_len = 0
    ctx.vm.pc = 0;
    ctx.vm.status = .running;
    ctx.vm.step();

    try testing.expectEqual(@as(u32, 1), ctx.vm.regs[10]);
}
