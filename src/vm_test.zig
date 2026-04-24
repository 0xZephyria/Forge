// ============================================================================
// Forge VM Test Harness — Standalone Zephyria VM test suite
// ============================================================================
//
// Mirrors the EVM test suite pattern:
//   1. Compile each .foz contract → .fozbin via the Forge compiler.
//   2. Parse the .fozbin header via ZephBinPackage.
//   3. Load the action bytecode into ForgeVM.
//   4. Execute with a mock HostEnv and report results.
//
// Usage:
//   zig build vmtest
//   zig build vmtest -- contracts/TokenTest.foz
//
// SPEC REFERENCE: Part 5 (Contract Anatomy), Part 14 (VM ABI)

const std = @import("std");

// ── Forge compiler pipeline ──────────────────────────────────────────────────
const lexer   = @import("lexer.zig");
const parser  = @import("parser.zig");
const types   = @import("types.zig");
const checker = @import("checker.zig");
const mir_mod = @import("mir.zig");
const codegen = @import("codegen.zig");
const errors  = @import("errors.zig");

// ── Zephyria VM (single module entry point — vm.zig owns all sub-files) ──────
const vm_mod = @import("zephyria_vm");

const ForgeVM         = vm_mod.ForgeVM;
const HostEnv         = vm_mod.HostEnv;
const ExecutionStatus = vm_mod.ExecutionStatus;
const StorageBackend  = vm_mod.StorageBackend;
// zephbin_loader is accessed via vm_mod.zephbin_loader (re-exported from vm.zig)
const zephbin         = vm_mod.zephbin_loader;
const ZephBinPackage  = zephbin.ZephBinPackage;

// ── Test result ──────────────────────────────────────────────────────────────

/// Result of running a single action against the VM.
pub const ActionResult = struct {
    /// Action selector (0 = constructor/setup).
    selector: u32,
    /// Final execution status.
    status: ExecutionStatus,
    /// Gas consumed by this invocation.
    gas_used: u64,
    /// Number of events emitted.
    events: usize,
    /// Revert message bytes (if status == .reverted).
    revert_data: []const u8,
};

/// Result of testing one full contract.
pub const ContractTestResult = struct {
    contract_name: []const u8,
    /// One entry per action in the binary.
    actions: []ActionResult,
    /// True if every action completed without panic/revert.
    passed: bool,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ContractTestResult) void {
        self.allocator.free(self.actions);
    }
};

// ── In-memory storage backend ────────────────────────────────────────────────

/// Simple HashMap-backed storage for testing (no disk I/O needed).
const MemStorage = struct {
    map: std.AutoHashMap([32]u8, [32]u8),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) MemStorage {
        return .{ .map = std.AutoHashMap([32]u8, [32]u8).init(allocator),
                  .allocator = allocator };
    }

    fn deinit(self: *MemStorage) void {
        self.map.deinit();
    }

    fn load(ctx: *anyopaque, key: [32]u8) [32]u8 {
        const self: *MemStorage = @ptrCast(@alignCast(ctx));
        return self.map.get(key) orelse [_]u8{0} ** 32;
    }

    fn store(ctx: *anyopaque, key: [32]u8, value: [32]u8) void {
        const self: *MemStorage = @ptrCast(@alignCast(ctx));
        self.map.put(key, value) catch {};
    }

    fn backend(self: *MemStorage) StorageBackend {
        return .{
            .ctx     = self,
            .loadFn  = load,
            .storeFn = store,
        };
    }
};

// ── Compile .foz → .fozbin bytes ─────────────────────────────────────────────

/// Compile Forge source text into a .fozbin byte slice (heap-allocated).
/// Caller owns the returned slice.
pub fn compileFoz(
    allocator: std.mem.Allocator,
    source: []const u8,
    source_name: []const u8,
) anyerror![]u8 {
    var diags = errors.DiagnosticList.init(allocator);
    defer diags.deinit();

    // Lex
    var lxr = lexer.Lexer.init(source, source_name);
    const tokens = try lxr.tokenize(allocator);
    defer allocator.free(tokens);

    // Parse
    var prs = parser.Parser.init(allocator, tokens, source, &diags);
    const contract_def = try prs.parseContract();
    defer contract_def.deinitAll(allocator);

    // Type-resolve
    var resolver = types.TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    // Semantic check
    var chkr = checker.Checker.init(allocator, &resolver, &diags);
    const checked = try chkr.check(&contract_def);

    // Lower to MIR
    var lowerer = mir_mod.MirLowerer.init(allocator, &resolver, &diags);
    defer lowerer.deinit();
    const mir_module = try lowerer.lowerContract(&contract_def, &checked);

    // Emit binary
    var gen = codegen.CodeGen.init(allocator, &diags, &resolver);
    defer gen.deinit();
    return gen.generateFromMir(&mir_module, &checked);
}

// ── Run one action through the VM ─────────────────────────────────────────────

/// Execute a single action's bytecode and return an ActionResult.
fn runAction(
    allocator: std.mem.Allocator,
    action_code: []const u8,
    selector: u32,
    calldata: []const u8,
    storage: *MemStorage,
    gas_limit: u64,
) anyerror!ActionResult {
    var stor_backend = storage.backend();
    var host = HostEnv.init(allocator);
    defer host.deinit();
    host.storage = &stor_backend;
    host.block_number = 1;
    host.timestamp    = 1_700_000_000;
    host.chain_id     = 42;

    var vm = try ForgeVM.create(allocator, action_code, calldata, gas_limit, &host);
    defer vm.deinit();

    const result = vm.run();
    const n_events = host.logs.items.len;

    var revert_bytes: []const u8 = &.{};
    if (result.status == .reverted) {
        if (vm.getReturnData()) |rd| {
            revert_bytes = rd;
        } else |_| {}
    }

    return ActionResult{
        .selector    = selector,
        .status      = result.status,
        .gas_used    = result.gas_used,
        .events      = n_events,
        .revert_data = revert_bytes,
    };
}

// ── Full contract test ────────────────────────────────────────────────────────

/// Compile a .foz source, parse the binary, and run every action in order.
/// Storage is shared across action calls (simulates contract state persistence).
pub fn testContract(
    allocator: std.mem.Allocator,
    source: []const u8,
    source_name: []const u8,
    gas_limit: u64,
) anyerror!ContractTestResult {
    // Compile
    const binary = try compileFoz(allocator, source, source_name);
    defer allocator.free(binary);

    // Parse ZephBin
    var pkg = try zephbin.parse(allocator, binary);
    defer pkg.deinit();

    const contract_name = blk: {
        var end: usize = 0;
        while (end < 32 and pkg.header.contract_name[end] != 0) end += 1;
        break :blk pkg.header.contract_name[0..end];
    };

    // Shared storage across all action calls.
    var storage = MemStorage.init(allocator);
    defer storage.deinit();

    const action_results = try allocator.alloc(ActionResult, pkg.actions.len);
    errdefer allocator.free(action_results);

    var all_passed = true;
    for (pkg.actions, 0..) |action, i| {
        const res = try runAction(
            allocator,
            action.code,
            action.selector,
            &.{}, // no calldata by default
            &storage,
            gas_limit,
        );
        action_results[i] = res;
        if (res.status != .halted and res.status != .breakpoint) {
            all_passed = false;
        }
    }

    return ContractTestResult{
        .contract_name = contract_name,
        .actions       = action_results,
        .passed        = all_passed,
        .allocator     = allocator,
    };
}
