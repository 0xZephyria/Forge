// ============================================================================
// Forge Compiler — WebAssembly Interface
// ============================================================================
//
// SPEC REFERENCE: Part 5 (Contract Anatomy), full pipeline in Wasm.
//
// Exports `compile_forge` function to be called from JavaScript.
// It returns a JSON string containing binary, abi, and errors.
//
// ALLOCATOR DISCIPLINE: Uses std.heap.wasm_allocator for allocations.

const std = @import("std");
const ast = @import("ast.zig");
const errors = @import("errors.zig");
const types = @import("types.zig");
const checker = @import("checker.zig");
const codegen = @import("codegen.zig");
const codegen_evm = @import("codegen_evm.zig");
const codegen_polkavm = @import("codegen_polkavm.zig");
const lexer = @import("lexer.zig");
const parser = @import("parser.zig");
const abi = @import("abi.zig");

// ── Allocator setup for Freestanding Wasm ────────────────────────────────────
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var wasm_allocator = if (@import("builtin").cpu.arch.isWasm()) std.heap.wasm_allocator else gpa.allocator();

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
                var cg = codegen_evm.EVMCodeGen.init(temp_alloc, &diagnostics, &resolver);
                binary = try cg.generate(contract, &checked);
            } else {
                var cg = codegen.CodeGen.init(temp_alloc, &diagnostics, &resolver);
                binary = try cg.generate(contract, &checked);
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
// Section: Tests
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
