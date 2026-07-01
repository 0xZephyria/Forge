// ============================================================================
// Forge Compiler — WebAssembly Interface
// ============================================================================
//
// SPEC REFERENCE: Part 5 (Contract Anatomy), full pipeline in Wasm.
// SPEC REFERENCE: Part 14.5 — Wasm Interactive Testing Sandbox.
//
// Exports `compile_forge` function to be called from JavaScript.
// It returns a JSON string containing binary, abi, and errors.
//
// Also exports `run_forge_tests_json` to support Remix/Foundry-style
// in-browser contract execution and integration testing.
//
// ALLOCATOR DISCIPLINE: Uses std.heap.wasm_allocator for allocations.

const std = @import("std");
const ast = @import("ast.zig");
const errors = @import("errors.zig");
const types = @import("types.zig");
const checker = @import("checker.zig");
const codegen = @import("codegen.zig");
const codegen_evm = @import("codegen_evm.zig");
// const codegen_polkavm = @import("codegen_polkavm.zig");
const lexer = @import("lexer.zig");
const parser = @import("parser.zig");
const abi = @import("abi.zig");
const mir_mod = @import("mir.zig");

/// True when compiled as a freestanding WASM module.
/// All ZVM/RISC-V execution paths are stubbed out in that case because
/// the ZVM depends on OS threads and POSIX APIs not available in the browser.
const is_wasm: bool = @import("builtin").cpu.arch.isWasm();

/// Import the Zephyria VM only when not targeting WASM freestanding.
/// The VM uses threads, AOT compilation, and POSIX syscalls that are
/// unavailable in a freestanding Wasm environment.
const vm_mod = if (!is_wasm) @import("zephyria_vm") else struct {
    // ── Minimal stubs so the file compiles without the VM ────────────────
    pub const ExecutionStatus = enum { returned, breakpoint, reverted, outOfGas, fault };
    pub const StorageBackend = struct {
        ctx: *anyopaque,
        loadFn: *const fn (*anyopaque, [32]u8) [32]u8,
        storeFn: *const fn (*anyopaque, [32]u8, [32]u8) void,
    };
    pub const sandbox = struct {
        pub const codeSize: u32 = 0;
        pub const heapStart: u32 = 0;
        pub const scratchStart: u32 = 0;
    };
    pub const HostEnv = struct {
        pub fn init(_: std.mem.Allocator) @This() { return .{}; }
        pub fn deinit(_: *@This()) void {}
    };
    pub const ForgeVM = struct {
        pub fn create(_: std.mem.Allocator, _: []const u8, _: []const u8, _: u64, _: *anyopaque) !@This() { return error.VmUnsupported; }
    };
    pub const zephbinLoader = struct {
        pub fn parse(_: std.mem.Allocator, _: []const u8) !struct { pub fn deinit(_: *@This()) void {} pub fn pickAction(_: *@This(), _: u32) ?struct { code: []const u8 } { return null; } } { return error.VmUnsupported; }
    };
};

// ── Allocator setup for Freestanding Wasm ────────────────────────────────────
var wasm_allocator = if (@import("builtin").cpu.arch.isWasm())
    std.heap.wasm_allocator
else blk: {
    const Container = struct {
        var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = false }){};
    };
    break :blk Container.gpa.allocator();
};

// Override panic to avoid standard library calling abort on web
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = msg;
    _ = error_return_trace;
    _ = ret_addr;
    unreachable; // In WebAssembly, this traps
}

// ── Exported Memory Functions ────────────────────────────────────────────────

export fn allocate(size: usize) usize {
    const mem = wasm_allocator.alloc(u8, size) catch return 0;
    return @intFromPtr(mem.ptr);
}

export fn deallocate(ptr_val: usize, size: usize) void {
    const ptr: [*]u8 = @ptrFromInt(ptr_val);
    wasm_allocator.free(ptr[0..size]);
}

// ── JSON Output Data Structures ──────────────────────────────────────────────

const JsonError = struct {
    file: []const u8,
    line: u32,
    col: u32,
    code: u16,
    message: []const u8,
    source_line: []const u8,
};

const JsonResult = struct {
    success: bool,
    bytecode: ?[]const u8 = null,
    abi: ?[]const u8 = null,
    errors: ?[]JsonError = null,
};

/// Extract error code from diagnostic kind.
fn errorCodeFromDiag(d: errors.Diagnostic) u16 {
    return switch (d.kind) {
        error.UnexpectedCharacter => 0,
        error.UnterminatedString => 1,
        error.InvalidNumberLiteral => 2,
        error.InvalidHexLiteral => 3,
        error.UnexpectedToken => 4,
        error.ExpectedToken => 5,
        error.UnexpectedEOF => 6,
        error.MissingColon => 7,
        error.MissingArrow => 8,
        error.TypeMismatch => 9,
        error.UndeclaredIdentifier => 10,
        error.UndeclaredType => 11,
        error.UndeclaredAccount => 12,
        error.InvalidTypeForOperation => 13,
        error.CannotAssignToReadonly => 14,
        error.DuplicateDeclaration => 15,
        error.DuplicateField => 16,
        error.MissingSetupBlock => 17,
        error.AccountNotDeclared => 18,
        error.FieldNotInCapabilityList => 19,
        error.WriteToReadonlyAccount => 20,
        error.CrossProgramStateAccess => 21,
        error.UnknownAuthority => 22,
        error.AuthorityTypeMismatch => 23,
        error.UndeclaredWrite => 24,
        error.UndeclaredRead => 25,
        error.UnboundedLoopMissingAnnotation => 26,
        error.LinearAssetDropped => 27,
        error.LinearAssetUsedTwice => 28,
        error.ConservationViolated => 29,
        error.ComplexityViolated => 30,
        error.AttackSucceeded => 31,
        error.AttackBlocked => 32,
        error.ImmutableFieldViolation => 35,
        error.InvalidAnnotationArgument => 36,
        error.InvalidHookSignature => 37,
        error.IllegalInView => 38,
        error.ImportNotFound => 39,
        error.ImportCollision => 40,
        error.CyclicImport => 41,
        error.ConstructNotEmittedOnTarget => 42,
        error.NonExhaustiveMatch => 43,
        error.TooManyIndexedFields => 44,
        error.OutOfMemory => 33,
        error.InternalError => 34,
    };
}

// ── Internal Compile Logic ───────────────────────────────────────────────────

fn compileInternal(alloc: std.mem.Allocator, source: []const u8, target_evm: bool) anyerror![]u8 {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const temp_alloc = arena.allocator();

    var diagnostics = errors.DiagnosticList.init(temp_alloc);

    var json_out = JsonResult{ .success = false };

    // Stage 1: Lex
    var lex = lexer.Lexer.init(source, "main.foz");
    const tokens = try lex.tokenize(temp_alloc, &diagnostics);

    var top_levels: []ast.TopLevel = &[_]ast.TopLevel{};

    // Stage 2: Parse
    if (!diagnostics.hasErrors()) {
        var parse = parser.Parser.init(tokens, temp_alloc, &diagnostics, source, "main.foz");
        top_levels = parse.parse() catch blk: {
            break :blk &[_]ast.TopLevel{};
        };
    }

    var contract_ptr: ?*const ast.ContractDef = null;
    var checked: checker.CheckedContract = undefined;
    var binary: []u8 = &[_]u8{};
    var abi_str: []u8 = &[_]u8{};
    var resolver = types.TypeResolver.init(temp_alloc, &diagnostics);

    if (!diagnostics.hasErrors() and top_levels.len > 0) {
        // Stage 3: Resolve Types
        try resolver.registerTopLevel(top_levels);

        for (top_levels) |*tl| {
            if (tl.* == .contract) {
                contract_ptr = &tl.contract;
                break;
            }
        }

        if (contract_ptr == null) {
            try diagnostics.add(.{ .kind = error.ExpectedToken, .file = "main.foz", .line = 1, .col = 1, .len = 0, .message = "No contract definition found in source", .source_line = "" });
        }
    }

    if (!diagnostics.hasErrors() and contract_ptr != null) {
        const contract = contract_ptr.?;

        // Stage 4: Check
        var chk = checker.Checker.init(&resolver, &diagnostics, temp_alloc, "main.foz");
        checked = try chk.checkContract(contract);

        if (!diagnostics.hasErrors()) {
            // Stage 5: Code Gen
            if (target_evm) {
                // ── MIR-based EVM pipeline: AST → MIR → EVM bytecode ──────────
                var lowerer = mir_mod.MirLowerer.init(temp_alloc, &resolver, &diagnostics);
                defer lowerer.deinit();
                const mir_module = try lowerer.lowerContract(contract, &checked);

                var cg = codegen_evm.EVMCodeGen.init(temp_alloc, &diagnostics, &resolver);
                defer cg.deinit();
                cg.mir_data = mir_module.data_section;
                cg.mir_events = mir_module.events;
                cg.mir_errors = mir_module.errors_;
                const tmp_bin = try cg.generateFromMir(&mir_module);
                binary = try temp_alloc.dupe(u8, tmp_bin);
            } else {
                var lowerer = mir_mod.MirLowerer.init(temp_alloc, &resolver, &diagnostics);
                defer lowerer.deinit();
                const mir_module = try lowerer.lowerContract(contract, &checked);

                var cg = codegen.CodeGen.init(temp_alloc, &diagnostics, &resolver);
                defer cg.deinit();
                const tmp_bin = try cg.generateFromMir(&mir_module);
                binary = try temp_alloc.dupe(u8, tmp_bin);
            }

            // Stage 6: ABI
            var abi_gen = abi.AbiGenerator.init(temp_alloc, &resolver);
            if (target_evm) {
                abi_str = try abi_gen.generateEVMAbi(contract);
            } else {
                abi_str = try abi_gen.generateZephAbi(contract, &checked);
            }
        }
    }

    // Prepare JSON Response
    if (diagnostics.hasErrors()) {
        var json_errors = std.ArrayListUnmanaged(JsonError){};
        for (diagnostics.items.items) |d| {
            try json_errors.append(temp_alloc, .{
                .file = d.file,
                .line = d.line,
                .col = d.col,
                .code = errorCodeFromDiag(d),
                .message = d.message,
                .source_line = d.source_line,
            });
        }
        json_out.success = false;
        json_out.errors = json_errors.items;
    } else {
        // Hex encode the binary
        const hex_string = try temp_alloc.alloc(u8, binary.len * 2);
        const hex_chars = "0123456789abcdef";
        for (binary, 0..) |b, i| {
            hex_string[i * 2] = hex_chars[b >> 4];
            hex_string[i * 2 + 1] = hex_chars[b & 0x0F];
        }
        json_out.success = true;
        json_out.bytecode = hex_string;
        json_out.abi = abi_str;
    }

    // Convert to JSON
    const json_str = try abi.serializeJson(json_out, alloc);
    defer alloc.free(json_str);

    var out_str = std.ArrayListUnmanaged(u8){};
    errdefer out_str.deinit(alloc);

    try out_str.appendSlice(alloc, json_str);
    try out_str.append(alloc, 0); // null termination

    return out_str.toOwnedSlice(alloc);
}

// ── Exported Compile Function ────────────────────────────────────────────────

// State for freeing later if called multiple times, optional clean wrapper
var last_result_ptr: ?[*]u8 = null;
var last_result_len: usize = 0;

export fn compile_forge(source_ptr: [*]const u8, source_len: usize, target_evm: bool) usize {
    // Free previous result
    if (last_result_ptr) |ptr| {
        wasm_allocator.free(ptr[0..last_result_len]);
        last_result_ptr = null;
        last_result_len = 0;
    }

    const source = source_ptr[0..source_len];

    // Attempt compile, return null on panic basically (or unhandled err)
    // Though we shouldn't panic
    if (compileInternal(wasm_allocator, source, target_evm)) |result_slice| {
        last_result_ptr = result_slice.ptr;
        last_result_len = result_slice.len;
        return @intFromPtr(result_slice.ptr);
    } else |_| {
        const err_json = "{\"success\":false,\"errors\":[{\"file\":\"main.foz\",\"line\":1,\"col\":1,\"code\":30,\"message\":\"Internal compiler error during execution.\",\"source_line\":\"\"}]}\x00";
        const fallback = wasm_allocator.dupe(u8, err_json) catch return 0;
        last_result_ptr = fallback.ptr;
        last_result_len = fallback.len;
        return @intFromPtr(fallback.ptr);
    }
}

// ============================================================================
// Section ── ZVM Interactive Testing Sandbox for WebAssembly
// ============================================================================

/// SPEC: Part 14.5 — Wasm storage entry representing mapping key/value
const WasmStorageEntry = struct {
    key: []const u8,
    value: []const u8,
};

/// SPEC: Part 14.5 — Wasm step structure matching Foundry test config
const WasmScriptStep = struct {
    action: ?[]const u8 = null,
    view: ?[]const u8 = null,
    args: ?[]const std.json.Value = null,
    caller: ?[]const u8 = null,
    value: ?u64 = null,
    expect_revert: ?bool = null,
};

/// SPEC: Part 14.5 — Request payload containing sandbox steps
const WasmRunRequest = struct {
    storage: ?[]const WasmStorageEntry = null,
    steps: []const WasmScriptStep,
};

/// SPEC: Part 14.2 — Log details emitted during ZVM execution
const WasmEventLog = struct {
    topics: [][]const u8,
    data: []const u8,
};

/// SPEC: Part 14.5 — Step execution details in WebAssembly
const WasmStepOutcome = struct {
    step: u32,
    name: []const u8,
    status: []const u8,
    gas_used: u64,
    events: []const WasmEventLog,
    revert_data: []const u8,
    fault_reason: ?[]const u8,
    return_value: ?[]const u8,
};

/// SPEC: Part 14.5 — Persistent and updated storage entry after run
const WasmStorageOutputEntry = struct {
    key: []const u8,
    value: []const u8,
};

/// SPEC: Part 14.5 — Output response from contract testing execution
const WasmRunResponse = struct {
    success: bool,
    steps: []const WasmStepOutcome,
    storage: []const WasmStorageOutputEntry,
    error_message: ?[]const u8 = null,
};

/// ZVM argument options
const ParamVal = union(enum) {
    u64: u64,
    u256: [32]u8,
    boolean: bool,
    account: [20]u8,
};

/// SPEC: Part 14.1 — Storage Model
/// Only meaningful on native targets where the ZVM is available.
const MemStorage = struct {
    map: std.AutoHashMap([32]u8, [32]u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MemStorage {
        return .{
            .map = std.AutoHashMap([32]u8, [32]u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MemStorage) void {
        self.map.deinit();
    }

    pub fn load(ctx: *anyopaque, key: [32]u8) [32]u8 {
        const self: *MemStorage = @ptrCast(@alignCast(ctx));
        return self.map.get(key) orelse [_]u8{0} ** 32;
    }

    pub fn store(ctx: *anyopaque, key: [32]u8, value: [32]u8) void {
        const self: *MemStorage = @ptrCast(@alignCast(ctx));
        self.map.put(key, value) catch {};
    }

    pub fn backend(self: *MemStorage) vm_mod.StorageBackend {
        // On WASM the VM is stubbed — this path is never reached at runtime.
        return .{
            .ctx = self,
            .loadFn = load,
            .storeFn = store,
        };
    }
};

/// Step execution outcomes inside Wasm runner
const ActionResult = struct {
    selector: u32,
    name: []const u8,
    status: vm_mod.ExecutionStatus,
    gas_used: u64,
    events: []const WasmEventLog,
    revert_data: []const u8,
    fault_reason: ?[]const u8,
    return_value: ?[]const u8,
};

/// SPEC: Part 5.5 — FNV-1a Hash helper
fn fnvHash32(name: []const u8) u32 {
    var h: u32 = 0x811c9dc5;
    for (name) |b| {
        h ^= b;
        h *%= 0x01000193;
    }
    return h;
}

/// SPEC: Part 14.3 — u256 conversion helper
fn makeU256(val: u64) [32]u8 {
    var b = [_]u8{0} ** 32;
    std.mem.writeInt(u64, b[0..8], val, .little);
    return b;
}

/// Helper function to hex encode bytes in freestanding Wasm target
fn hexEncode(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const hex_chars = "0123456789abcdef";
    var result = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        result[i * 2] = hex_chars[b >> 4];
        result[i * 2 + 1] = hex_chars[b & 0x0F];
    }
    return result;
}

/// Parse Wasm json values into ParamVal
fn parseWasmJsonArg(val: std.json.Value) !ParamVal {
    switch (val) {
        .integer => |i| {
            return ParamVal{ .u64 = @intCast(i) };
        },
        .float => |f| {
            return ParamVal{ .u64 = @intFromFloat(f) };
        },
        .bool => |b| {
            return ParamVal{ .boolean = b };
        },
        .string => |s| {
            if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) {
                const hex_part = s[2..];
                if (hex_part.len == 40) {
                    var addr = [_]u8{0} ** 20;
                    _ = try std.fmt.hexToBytes(&addr, hex_part);
                    return ParamVal{ .account = addr };
                } else if (hex_part.len == 64) {
                    var bytes = [_]u8{0} ** 32;
                    _ = try std.fmt.hexToBytes(&bytes, hex_part);
                    return ParamVal{ .u256 = bytes };
                }
            }
            if (s.len == 64) {
                var bytes = [_]u8{0} ** 32;
                _ = try std.fmt.hexToBytes(&bytes, s);
                return ParamVal{ .u256 = bytes };
            }
            return error.InvalidArgType;
        },
        else => return error.InvalidArgType,
    }
}

/// Decode hex-encoded 32-byte addresses
fn parseWasmAddress(s: []const u8) ![32]u8 {
    var addr = [_]u8{0} ** 32;
    if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) {
        const hex = s[2..];
        if (hex.len <= 40) {
            var bytes = [_]u8{0} ** 20;
            _ = try std.fmt.hexToBytes(&bytes, hex);
            @memcpy(addr[0..20], &bytes);
        } else {
            var bytes = [_]u8{0} ** 32;
            _ = try std.fmt.hexToBytes(&bytes, hex[0..@min(hex.len, 64)]);
            @memcpy(&addr, &bytes);
        }
    } else {
        if (s.len <= 64) {
            var bytes = [_]u8{0} ** 32;
            _ = try std.fmt.hexToBytes(&bytes, s[0..@min(s.len, 64)]);
            @memcpy(&addr, &bytes);
        }
    }
    return addr;
}

/// SPEC: Part 5.2 — Wasm raw compilation helper with diagnostics
fn compileFozBytesWithDiags(
    allocator: std.mem.Allocator,
    source: []const u8,
    diags: *errors.DiagnosticList,
) ![]u8 {
    var lxr = lexer.Lexer.init(source, "main.foz");
    const tokens = try lxr.tokenize(allocator, diags);
    if (diags.hasErrors()) return error.CompileFailed;

    var prs = parser.Parser.init(tokens, allocator, diags, source, "main.foz");
    const top_levels = try prs.parse();
    if (diags.hasErrors()) return error.CompileFailed;

    var contract_ptr: ?*const ast.ContractDef = null;
    for (top_levels) |*tl| {
        if (tl.* == .contract) {
            contract_ptr = &tl.contract;
            break;
        }
    }
    if (contract_ptr == null) {
        try diags.add(.{
            .kind = error.ExpectedToken,
            .file = "main.foz",
            .line = 1,
            .col = 1,
            .len = 0,
            .message = "No contract definition found in source",
            .source_line = "",
        });
        return error.CompileFailed;
    }
    const contract_def = contract_ptr.?.*;

    var resolver = types.TypeResolver.init(allocator, diags);
    try resolver.registerTopLevel(top_levels);
    if (diags.hasErrors()) return error.CompileFailed;

    var chkr = checker.Checker.init(&resolver, diags, allocator, "main.foz");
    var checked = try chkr.checkContract(&contract_def);
    if (diags.hasErrors()) return error.CompileFailed;

    var lowerer = mir_mod.MirLowerer.init(allocator, &resolver, diags);
    const mir_module = try lowerer.lowerContract(&contract_def, &checked);
    if (diags.hasErrors()) return error.CompileFailed;

    var gen = codegen.CodeGen.init(allocator, diags, &resolver);
    const tmp_bin = try gen.generateFromMir(&mir_module);
    return allocator.dupe(u8, tmp_bin);
}

/// SPEC: Part 14.3 — Invocation in WebAssembly
/// On WASM targets the ZVM is not available; returns VmUnsupported.
fn runWasmAction(
    allocator: std.mem.Allocator,
    binary: []const u8,
    selector: u32,
    params: []const ParamVal,
    storage: *MemStorage,
    gas_limit: u64,
    caller: [32]u8,
    call_value: [32]u8,
) anyerror!ActionResult {
    if (is_wasm) {
        // ZVM execution requires OS threads and POSIX — not available in browser WASM.
        return error.VmUnsupported;
    }

    var pkg = try vm_mod.zephbinLoader.parse(allocator, binary);
    defer pkg.deinit();

    const action = pkg.pickAction(selector) orelse return error.ActionNotFound;
    if (action.code.len == 0) return error.CodeTooLarge;

    const actionCodeLen = action.code.len;
    const stubOffset: u32 = @intCast(actionCodeLen);
    const stubEnd: u32 = stubOffset + 8;
    if (stubEnd > vm_mod.sandbox.codeSize) return error.CodeTooLarge;

    var exe_bytecode = try allocator.alloc(u8, stubEnd);
    defer allocator.free(exe_bytecode);
    @memcpy(exe_bytecode[0..actionCodeLen], action.code);

    // Write exit stub: ADDI a0, zero, 0x50; ECALL
    std.mem.writeInt(u32, exe_bytecode[stubOffset..][0..4], 0x05000513, .little);
    // ECALL
    std.mem.writeInt(u32, exe_bytecode[stubOffset + 4..][0..4], 0x00000073, .little);

    var host = vm_mod.HostEnv.init(allocator);
    defer host.deinit();

    var stor_backend = storage.backend();
    host.storage = &stor_backend;
    host.caller = caller;
    host.callValue = call_value;
    host.blockNumber = 1;
    host.timestamp = 1_700_000_000;
    host.chainId = 42;

    var vm = try vm_mod.ForgeVM.create(
        allocator,
        exe_bytecode,
        &[_]u8{},
        gas_limit,
        &host,
    );
    defer vm.deinit();

    vm.setReg(3, vm_mod.sandbox.heapStart); // GP
    vm.setReg(1, stubOffset);        // RA

    var scratch_offset: u32 = vm_mod.sandbox.scratchStart;

    for (params, 0..) |p, i| {
        if (i >= 7) break;
        const reg: u5 = @intCast(10 + i);

        switch (p) {
            .u64 => |val| {
                vm.setReg(reg, val);
            },
            .boolean => |val| {
                vm.setReg(reg, if (val) @as(u64, 1) else @as(u64, 0));
            },
            .u256 => |val| {
                const slice = try vm.memory.getSliceMut(scratch_offset, 32);
                @memcpy(slice, &val);
                vm.setReg(reg, scratch_offset);
                scratch_offset += 32;
            },
            .account => |val| {
                var padded = [_]u8{0} ** 32;
                @memcpy(padded[0..20], &val);
                const slice = try vm.memory.getSliceMut(scratch_offset, 32);
                @memcpy(slice, &padded);
                vm.setReg(reg, scratch_offset);
                scratch_offset += 32;
            },
        }
    }

    const run_result = vm.run();

    var revert_bytes: []const u8 = &.{};
    if (run_result.status == .reverted) {
        if (vm.getReturnData()) |rd| {
            if (rd.len > 0) {
                revert_bytes = try allocator.dupe(u8, rd);
            }
        } else |_| {}
    }

    var fault_reason: ?[]const u8 = null;
    if (run_result.status == .fault) {
        if (run_result.faultReason) |fr| {
            fault_reason = try allocator.dupe(u8, fr);
        }
    }

    // Get return value if any (for view/action calls)
    var return_val_bytes: ?[]const u8 = null;
    if (run_result.status == .returned or run_result.status == .breakpoint) {
        if (vm.getReturnData()) |rd| {
            if (rd.len > 0) {
                return_val_bytes = try allocator.dupe(u8, rd);
            }
        } else |_| {}
    }

    var act_name: []const u8 = "setup";
    if (selector != 0) {
        act_name = "action";
    }

    // Allocate array of WasmEventLogs from host.logs
    const event_logs = try allocator.alloc(WasmEventLog, host.logs.items.len);
    errdefer {
        for (event_logs) |el| {
            for (el.topics) |t| allocator.free(t);
            allocator.free(el.topics);
            allocator.free(el.data);
        }
        allocator.free(event_logs);
    }

    for (host.logs.items, 0..) |log, idx| {
        const topics = try allocator.alloc([]const u8, log.topics.items.len);
        for (log.topics.items, 0..) |t, t_idx| {
            const enc_t = try hexEncode(allocator, &t);
            const hex_t = try std.fmt.allocPrint(allocator, "0x{s}", .{enc_t});
            topics[t_idx] = hex_t;
        }
        const enc_data = try hexEncode(allocator, log.data.items);
        const hex_data = try std.fmt.allocPrint(allocator, "0x{s}", .{enc_data});
        event_logs[idx] = .{
            .topics = topics,
            .data = hex_data,
        };
    }

    return ActionResult{
        .selector = selector,
        .name = act_name,
        .status = run_result.status,
        .gas_used = run_result.gasUsed,
        .events = event_logs,
        .revert_data = revert_bytes,
        .fault_reason = fault_reason,
        .return_value = return_val_bytes,
    };
}

/// Fallible sandbox script runner in WebAssembly
fn run_forge_steps_json_internal(
    allocator: std.mem.Allocator,
    source: []const u8,
    steps_json: []const u8,
) anyerror![]u8 {
    var response = WasmRunResponse{
        .success = false,
        .steps = &.{},
        .storage = &.{},
        .error_message = null,
    };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temp_alloc = arena.allocator();

    var diags = errors.DiagnosticList.init(temp_alloc);

    const run_result_json = run_result: {
        // 1. Parse request JSON (can be WasmRunRequest object, or bare list of WasmScriptStep)
        var req: WasmRunRequest = undefined;
        if (std.json.parseFromSlice(WasmRunRequest, temp_alloc, steps_json, .{ .ignore_unknown_fields = true })) |p| {
            req = p.value;
        } else |_| {
            if (std.json.parseFromSlice([]const WasmScriptStep, temp_alloc, steps_json, .{ .ignore_unknown_fields = true })) |p| {
                req = .{
                    .storage = null,
                    .steps = p.value,
                };
            } else |err| {
                response.error_message = try std.fmt.allocPrint(temp_alloc, "JSON parse error: {s}", .{@errorName(err)});
                break :run_result try abi.serializeJson(response, temp_alloc);
            }
        }

        // 2. Compile contract
        const bin = compileFozBytesWithDiags(temp_alloc, source, &diags) catch {
            var err_msg = std.ArrayListUnmanaged(u8){};
            defer err_msg.deinit(temp_alloc);
            for (diags.items.items) |d| {
                err_msg.writer(temp_alloc).print("main.foz:{d}:{d}: error: {s}\n", .{ d.line, d.col, d.message }) catch {};
            }
            response.error_message = if (err_msg.items.len > 0) try temp_alloc.dupe(u8, err_msg.items) else "Compilation failed.";
            break :run_result try abi.serializeJson(response, temp_alloc);
        };

        // 3. Initialize storage
        var storage = MemStorage.init(temp_alloc);
        defer storage.deinit();

        if (req.storage) |init_stor| {
            for (init_stor) |entry| {
                const k = parseWasmAddress(entry.key) catch {
                    response.error_message = "Invalid key format in initial storage (must be 0x hex).";
                    break :run_result try abi.serializeJson(response, temp_alloc);
                };
                const v = parseWasmAddress(entry.value) catch {
                    response.error_message = "Invalid value format in initial storage (must be 0x hex).";
                    break :run_result try abi.serializeJson(response, temp_alloc);
                };
                storage.map.put(k, v) catch {};
            }
        }

        // 4. Run steps
        var steps_out = std.ArrayListUnmanaged(WasmStepOutcome){};
        const default_caller = [_]u8{0x5B} ** 32;
        const default_val = [_]u8{0} ** 32;

        for (req.steps, 0..) |step, idx| {
            const step_num: u32 = @intCast(idx + 1);
            const call_name = step.action orelse step.view orelse "setup";
            const selector = if (step.action) |act| (if (std.mem.eql(u8, act, "setup")) @as(u32, 0) else fnvHash32(act)) else if (step.view) |v| fnvHash32(v) else @as(u32, 0);

            // Parse args
            var args_list = std.ArrayListUnmanaged(ParamVal){};
            defer args_list.deinit(temp_alloc);
            if (step.args) |args| {
                for (args) |arg| {
                    const parsed_arg = parseWasmJsonArg(arg) catch |err| {
                        response.error_message = try std.fmt.allocPrint(temp_alloc, "Step {d} argument parse error: {s}", .{ step_num, @errorName(err) });
                        break :run_result try abi.serializeJson(response, temp_alloc);
                    };
                    try args_list.append(temp_alloc, parsed_arg);
                }
            }

            const caller = if (step.caller) |c| (parseWasmAddress(c) catch {
                response.error_message = try std.fmt.allocPrint(temp_alloc, "Step {d} caller parse error.", .{step_num});
                break :run_result try abi.serializeJson(response, temp_alloc);
            }) else default_caller;

            const val = if (step.value) |v| makeU256(v) else default_val;

            const outcome = runWasmAction(
                temp_alloc,
                bin,
                selector,
                args_list.items,
                &storage,
                10_000_000,
                caller,
                val,
            ) catch |err| {
                response.error_message = try std.fmt.allocPrint(temp_alloc, "Step {d} ZVM Execution fault: {s}", .{ step_num, @errorName(err) });
                break :run_result try abi.serializeJson(response, temp_alloc);
            };

            const status_str = @tagName(outcome.status);

            const revert_str = if (outcome.revert_data.len > 0)
                try temp_alloc.dupe(u8, outcome.revert_data)
            else
                "";

            const return_val_hex = if (outcome.return_value) |rv| blk: {
                const enc_rv = try hexEncode(temp_alloc, rv);
                break :blk try std.fmt.allocPrint(temp_alloc, "0x{s}", .{enc_rv});
            } else null;

            try steps_out.append(temp_alloc, .{
                .step = step_num,
                .name = call_name,
                .status = status_str,
                .gas_used = outcome.gas_used,
                .events = outcome.events,
                .revert_data = revert_str,
                .fault_reason = outcome.fault_reason,
                .return_value = return_val_hex,
            });
        }

        // Get final storage state
        var final_stor = std.ArrayListUnmanaged(WasmStorageOutputEntry){};
        var iter = storage.map.iterator();
        while (iter.next()) |entry| {
            const key_encoded = try hexEncode(temp_alloc, entry.key_ptr);
            const val_encoded = try hexEncode(temp_alloc, entry.value_ptr);
            const key_hex = try std.fmt.allocPrint(temp_alloc, "0x{s}", .{key_encoded});
            const val_hex = try std.fmt.allocPrint(temp_alloc, "0x{s}", .{val_encoded});
            try final_stor.append(temp_alloc, .{
                .key = key_hex,
                .value = val_hex,
            });
        }

        response.success = true;
        response.steps = steps_out.items;
        response.storage = final_stor.items;

        break :run_result try abi.serializeJson(response, temp_alloc);
    };

    // Copy to persistent caller-owned memory
    const out_slice = try allocator.alloc(u8, run_result_json.len + 1);
    @memcpy(out_slice[0..run_result_json.len], run_result_json);
    out_slice[run_result_json.len] = 0; // null termination
    return out_slice;
}

/// SPEC: Part 14.5 — Main exported interface to execute test steps from JSON
export fn run_forge_tests_json(
    source_ptr: [*]const u8,
    source_len: usize,
    steps_json_ptr: [*]const u8,
    steps_json_len: usize,
) usize {
    if (last_result_ptr) |ptr| {
        wasm_allocator.free(ptr[0..last_result_len]);
        last_result_ptr = null;
        last_result_len = 0;
    }

    const source = source_ptr[0..source_len];
    const steps_json = steps_json_ptr[0..steps_json_len];

    if (run_forge_steps_json_internal(wasm_allocator, source, steps_json)) |res| {
        last_result_ptr = res.ptr;
        last_result_len = res.len;
        return @intFromPtr(res.ptr);
    } else |_| {
        const fallback = wasm_allocator.dupe(u8, "{\"success\":false,\"error_message\":\"Internal runner allocation failure.\"}\x00") catch return 0;
        last_result_ptr = fallback.ptr;
        last_result_len = fallback.len;
        return @intFromPtr(fallback.ptr);
    }
}

// ============================================================================
// Section ── Tests
// ============================================================================

test "wasm module setup" {
    // Tests cannot export Wasm if they aren't Wasm! We just test the internal compile function
    const alloc = std.testing.allocator;
    const src = "version 1\ncontract Test:\n  actions:\n    init() {}\n";

    const json_bytes = try compileInternal(alloc, src, false);
    defer alloc.free(json_bytes);

    try std.testing.expect(json_bytes.len > 0);
    try std.testing.expect(json_bytes[json_bytes.len - 1] == 0);

    // It should be a success
    try std.testing.expect(std.mem.indexOf(u8, json_bytes, "\"success\":true") != null);
}

test "run_forge_tests_json: setup and call actions" {
    const alloc = std.testing.allocator;
    const src =
        \\version 1
        \\
        \\contract CounterTest:
        \\    has:
        \\        total is u256
        \\
        \\    setup():
        \\        total = 10
        \\
        \\    action increment(amount is u256):
        \\        total = total + amount
        \\
        \\End;
    ;

    const steps =
        \\[
        \\  {"action": "setup", "args": []},
        \\  {"action": "increment", "args": [5]}
        \\]
    ;

    const result_json = try run_forge_steps_json_internal(alloc, src, steps);
    defer alloc.free(result_json);

    try std.testing.expect(result_json.len > 0);
    try std.testing.expect(result_json[result_json.len - 1] == 0); // null terminated

    // Verify it succeeded
    if (std.mem.indexOf(u8, result_json, "\"success\":true") == null) {
        std.debug.print("\nDEBUG: Wasm test result_json = {s}\n\n", .{result_json});
        try std.testing.expect(false);
    }
    try std.testing.expect(std.mem.indexOf(u8, result_json, "\"status\":\"returned\"") != null);
}
