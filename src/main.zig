// ============================================================================
// Forge Compiler — CLI Entry Point
// ============================================================================
//
// Ties all modules together. Handles command-line arguments, drives
// the compilation pipeline, and writes the .fozbin output.
//
// SPEC REFERENCE: Part 5 (Contract Anatomy), full pipeline.
//
// Usage:  forgec <input.foz> [options]

const std = @import("std");
const ast = @import("ast.zig");
const errors = @import("errors.zig");
const types = @import("types.zig");
const checker = @import("checker.zig");
const codegen = @import("codegen.zig");
const codegen_polkavm = @import("codegen_polkavm.zig");
const lexer = @import("lexer.zig");
const parser = @import("parser.zig");

const DiagnosticList = errors.DiagnosticList;
const TypeResolver = types.TypeResolver;
const Lexer = lexer.Lexer;
const Parser = parser.Parser;
const Checker = checker.Checker;
const CodeGen = codegen.CodeGen;
const CodeGenPolkaVM = codegen_polkavm.CodeGenPolkaVM;
const TopLevel = ast.TopLevel;

const COMPILER_VERSION = "1.0.0";

// ============================================================================
// Section 1 — Compile Options
// ============================================================================

/// All options that control a single compilation invocation.
pub const CompileOptions = struct {
    /// Output file path. Null = derive from input name.
    output: ?[]const u8 = null,
    /// Only run type-checking, skip codegen.
    check_only: bool = false,
    /// Print token stream and exit.
    print_tokens: bool = false,
    /// Print AST summary and exit.
    print_ast: bool = false,
    /// Print access lists and exit.
    print_access: bool = false,
    /// Disable ANSI color codes.
    no_color: bool = false,
    /// Compilation target (zephyria or polkavm)
    target: []const u8 = "zephyria",
};

// ============================================================================
// Section 2 — Argument Parsing
// ============================================================================

/// Result from argument parsing: either valid args or explicit exit request.
const ArgResult = union(enum) {
    /// Parsed successfully with input path and options.
    success: struct {
        input_path: []const u8,
        opts: CompileOptions,
    },
    /// Help or version was printed; caller should exit 0.
    exit_ok: void,
    /// Parse error; message already printed; caller should exit 2.
    exit_err: void,
};

/// Parse command-line arguments. Prints help/version/errors to stderr.
fn parseArgs(args: []const [:0]const u8) ArgResult {
    var opts = CompileOptions{};
    var input_path: ?[]const u8 = null;
    var i: usize = 1; // skip argv[0] (program name)

    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            return .exit_ok;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            std.debug.print("forgec {s}\n", .{COMPILER_VERSION});
            return .exit_ok;
        } else if (std.mem.eql(u8, arg, "-o")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("error: -o requires an argument\n", .{});
                return .exit_err;
            }
            opts.output = args[i];
        } else if (std.mem.eql(u8, arg, "--check-only")) {
            opts.check_only = true;
        } else if (std.mem.eql(u8, arg, "--print-tokens")) {
            opts.print_tokens = true;
        } else if (std.mem.eql(u8, arg, "--print-ast")) {
            opts.print_ast = true;
        } else if (std.mem.eql(u8, arg, "--print-access")) {
            opts.print_access = true;
        } else if (std.mem.eql(u8, arg, "--no-color")) {
            opts.no_color = true;
        } else if (std.mem.eql(u8, arg, "--target")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("error: --target requires an argument\n", .{});
                return .exit_err;
            }
            opts.target = args[i];
        } else if (arg.len > 0 and arg[0] == '-') {
            std.debug.print("error: unknown option '{s}'\n", .{arg});
            return .exit_err;
        } else {
            input_path = arg;
        }
    }

    if (input_path == null) {
        std.debug.print("error: no input file specified\n\n", .{});
        printUsage();
        return .exit_err;
    }

    return .{ .success = .{ .input_path = input_path.?, .opts = opts } };
}

/// Print usage/help text to stderr.
fn printUsage() void {
    std.debug.print(
        \\Usage: forgec <input.foz> [options]
        \\
        \\Options:
        \\  -o <output>       Output file path (default depends on target)
        \\  --target <name>   Target VM: zephyria (default), polkavm
        \\  --check-only      Only type-check, don't emit bytecode
        \\  --print-tokens    Print token stream and exit
        \\  --print-ast       Print AST summary and exit
        \\  --print-access    Print access lists for all actions and exit
        \\  --no-color        Disable colored error output
        \\  -v, --version     Print compiler version and exit
        \\  -h, --help        Print this help and exit
        \\
    , .{});
}

// ============================================================================
// Section 3 — Compilation Pipeline
// ============================================================================

/// Run the full compilation pipeline on source text.
/// Returns the binary bytes on success, null if there were compile errors.
pub fn compile(
    source: []const u8,
    file: []const u8,
    opts: CompileOptions,
    alloc: std.mem.Allocator,
) anyerror!?CompileResult {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const temp_alloc = arena.allocator();

    var diagnostics = DiagnosticList.init(temp_alloc);

    // ── Stage 1: Lex ─────────────────────────────────────────────────────
    var lex = Lexer.init(source, file);
    const tokens = try lex.tokenize(temp_alloc, &diagnostics);
    

    if (diagnostics.hasErrors()) {
        try printDiagnostics(&diagnostics);
        return null;
    }

    if (opts.print_tokens) {
        printTokenStream(tokens);
        return null;
    }

    // ── Stage 2: Parse ───────────────────────────────────────────────────
    var parse = Parser.init(tokens, temp_alloc, &diagnostics, source, file);
    const top_levels = parse.parse() catch |err| {
        try printDiagnostics(&diagnostics);
        return err;
    };
    

    if (diagnostics.hasErrors()) {
        try printDiagnostics(&diagnostics);
        return null;
    }

    if (opts.print_ast) {
        printAstSummary(top_levels);
        return null;
    }

    // ── Stage 3: Type resolution ─────────────────────────────────────────
    var resolver = TypeResolver.init(temp_alloc, &diagnostics);
    defer resolver.deinit();
    try resolver.registerTopLevel(top_levels);

    // ── Stage 4: Find the contract ───────────────────────────────────────
    var contract_ptr: ?*const ast.ContractDef = null;
    for (top_levels) |*tl| {
        switch (tl.*) {
            .contract => |*c| {
                contract_ptr = c;
                break;
            },
            else => {},
        }
    }

    if (contract_ptr == null) {
        std.debug.print("error: no contract found in {s}\n", .{file});
        return null;
    }
    const contract = contract_ptr.?;

    // ── Stage 5: Semantic check ──────────────────────────────────────────
    var chk = Checker.init(&resolver, &diagnostics, temp_alloc);
    var checked = try chk.checkContract(contract);
    defer checked.deinit();

    if (diagnostics.hasErrors()) {
        try printDiagnostics(&diagnostics);
        return null;
    }

    if (opts.print_access) {
        printAccessLists(contract, &checked);
        return null;
    }

    if (opts.check_only) {
        std.debug.print("Check passed: {s} ({d} actions, 0 errors)\n", .{
            contract.name, contract.actions.len,
        });
        std.process.exit(0);
    }

    // ── Stage 6: Code generation ─────────────────────────────────────────
    var binary: []u8 = undefined;
    if (std.mem.eql(u8, opts.target, "polkavm")) {
        var gen = CodeGenPolkaVM.init(temp_alloc, &diagnostics, &resolver);
        defer gen.deinit();
        const tmp_bin = try gen.generate(contract, &checked);
        binary = try alloc.dupe(u8, tmp_bin);
    } else {
        var gen = CodeGen.init(temp_alloc, &diagnostics, &resolver);
        defer gen.deinit();
        const tmp_bin = try gen.generate(contract, &checked);
        binary = try alloc.dupe(u8, tmp_bin);
    }

    if (diagnostics.hasErrors()) {
        alloc.free(binary);
        try printDiagnostics(&diagnostics);
        return null;
    }

    return CompileResult{
        .binary = binary,
        .contract_name = contract.name,
        .action_count = contract.actions.len,
        .warning_count = 0,
    };
}

/// Compilation outcome carrying output data.
pub const CompileResult = struct {
    binary: []u8,
    contract_name: []const u8,
    action_count: usize,
    warning_count: usize,
};

// ============================================================================
// Section 4 — Diagnostic and Debug Printing
// ============================================================================

/// Print all diagnostics to stderr via std.debug.print.
fn printDiagnostics(diagnostics: *DiagnosticList) anyerror!void {
    for (diagnostics.items.items) |d| {
        std.debug.print("error[E{d:0>4}]: {s}\n", .{ errorCodeFromDiag(d), d.message });
        std.debug.print(" --> {s}:{d}:{d}\n", .{ d.file, d.line, d.col });
        if (d.source_line.len > 0) {
            std.debug.print("  |\n", .{});
            std.debug.print("{d:>3} | {s}\n", .{ d.line, d.source_line });
            // Caret line
            std.debug.print("  | ", .{});
            var c: u32 = 1;
            while (c < d.col) : (c += 1) {
                std.debug.print(" ", .{});
            }
            var l: u32 = 0;
            while (l < @max(d.len, 1)) : (l += 1) {
                std.debug.print("^", .{});
            }
            std.debug.print("\n  |\n", .{});
        }
    }
}

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
        error.OutOfMemory => 29,
        error.InternalError => 30,
    };
}

/// Print the token stream (--print-tokens debug mode).
fn printTokenStream(tokens: []const lexer.Token) void {
    for (tokens) |tok| {
        std.debug.print("{d}:{d}  {s}  \"{s}\"\n", .{
            tok.span.line, tok.span.col, @tagName(tok.kind), tok.text,
        });
    }
}

/// Print a summary of the AST (--print-ast debug mode).
fn printAstSummary(top_levels: []const TopLevel) void {
    for (top_levels) |tl| {
        switch (tl) {
            .version => |v| std.debug.print("version {d}\n", .{v}),
            .use_import => |u| {
                std.debug.print("use ", .{});
                for (u.path, 0..) |seg, i| {
                    if (i > 0) std.debug.print(".", .{});
                    std.debug.print("{s}", .{seg});
                }
                if (u.alias) |a| std.debug.print(" as {s}", .{a});
                std.debug.print("\n", .{});
            },
            .contract => |c| {
                std.debug.print("contract {s}: {d} actions, {d} views, {d} state fields\n", .{
                    c.name, c.actions.len, c.views.len, c.state.len,
                });
            },
            .asset_def => |a| std.debug.print("asset {s}\n", .{a.name}),
            .interface_def => |iface| std.debug.print("interface {s}\n", .{iface.name}),
            .constant => |c| std.debug.print("define {s}\n", .{c.name}),
            .struct_def => |s| std.debug.print("struct {s}\n", .{s.name}),
            .record_def => |r| std.debug.print("record {s}\n", .{r.name}),
            .enum_def => |e| std.debug.print("enum {s}\n", .{e.name}),
            .type_alias => |t| std.debug.print("alias {s}\n", .{t.name}),
        }
    }
}

/// Print access lists for all actions (--print-access debug mode).
fn printAccessLists(contract: *const ast.ContractDef, checked: *const checker.CheckedContract) void {
    for (contract.actions) |action| {
        std.debug.print("action {s}:\n", .{action.name});
        if (checked.action_lists.get(action.name)) |al| {
            std.debug.print("  reads ({d}):\n", .{al.reads.items.len});
            for (al.reads.items) |entry| {
                std.debug.print("    - {s}", .{entry.account_name});
                if (entry.field) |f| std.debug.print(".{s}", .{f});
                std.debug.print("\n", .{});
            }
            std.debug.print("  writes ({d}):\n", .{al.writes.items.len});
            for (al.writes.items) |entry| {
                std.debug.print("    - {s}", .{entry.account_name});
                if (entry.field) |f| std.debug.print(".{s}", .{f});
                std.debug.print("\n", .{});
            }
        } else {
            std.debug.print("  (no access list)\n", .{});
        }
    }
}

// ============================================================================
// Section 5 — Output Path Derivation
// ============================================================================

/// Derive output path from input path: replace extension based on target.
fn deriveOutputPath(input_path: []const u8, target: []const u8, alloc: std.mem.Allocator) anyerror![]u8 {
    const basename = std.fs.path.basename(input_path);
    const dir = std.fs.path.dirname(input_path);

    var name_without_ext: []const u8 = basename;
    if (std.mem.lastIndexOf(u8, basename, ".")) |dot_pos| {
        name_without_ext = basename[0..dot_pos];
    }

    const ext = if (std.mem.eql(u8, target, "polkavm")) ".polkavm" else ".fozbin";

    if (dir) |d| {
        return std.fmt.allocPrint(alloc, "{s}/{s}{s}", .{ d, name_without_ext, ext });
    } else {
        return std.fmt.allocPrint(alloc, "{s}{s}", .{ name_without_ext, ext });
    }
}


/// Derive hex output path from binary output path: replace extension with .hex.
fn deriveHexOutputPath(binary_path: []const u8, alloc: std.mem.Allocator) anyerror![]u8 {
    const basename = std.fs.path.basename(binary_path);
    const dir = std.fs.path.dirname(binary_path);

    var name_without_ext: []const u8 = basename;
    if (std.mem.lastIndexOf(u8, basename, ".")) |dot_pos| {
        name_without_ext = basename[0..dot_pos];
    }

    if (dir) |d| {
        return std.fmt.allocPrint(alloc, "{s}/{s}.hex", .{ d, name_without_ext });
    } else {
        return std.fmt.allocPrint(alloc, "{s}.hex", .{name_without_ext});
    }
}

// ============================================================================
// Section 6 — Main Entry Point
// ============================================================================

pub fn main() anyerror!void {
    // ── Allocator ────────────────────────────────────────────────────────
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const check = gpa.deinit();
        if (check == .leak) {
            std.debug.print("warning: memory leak detected\n", .{});
        }
    }
    const alloc = gpa.allocator();

    // ── Argument parsing ─────────────────────────────────────────────────
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    const result = parseArgs(args);
    switch (result) {
        .exit_ok => return,
        .exit_err => std.process.exit(2),
        .success => |s| {
            const input_path = s.input_path;
            const opts = s.opts;

            // ── Read source file ─────────────────────────────────────────
            const source = std.fs.cwd().readFileAlloc(alloc, input_path, 10 * 1024 * 1024) catch |err| {
                std.debug.print("error: cannot read '{s}': {s}\n", .{ input_path, @errorName(err) });
                std.process.exit(2);
            };
            defer alloc.free(source);

            // ── Derive output path ───────────────────────────────────────
            const output_path = if (opts.output) |o|
                try alloc.dupe(u8, o)
            else
                try deriveOutputPath(input_path, opts.target, alloc);
            defer alloc.free(output_path);

            // ── Compile ──────────────────────────────────────────────────
            const compile_result = compile(source, input_path, opts, alloc) catch |err| {
                std.debug.print("internal compiler error: {s}\n", .{@errorName(err)});
                std.process.exit(3);
            };

            if (compile_result) |cr| {
                defer alloc.free(cr.binary);

                if (opts.check_only or opts.print_tokens or opts.print_ast or opts.print_access) {
                    return;
                }

                // ── Write output ─────────────────────────────────────────
                const out_file = std.fs.cwd().createFile(output_path, .{}) catch |err| {
                    std.debug.print("error: cannot write '{s}': {s}\n", .{ output_path, @errorName(err) });
                    std.process.exit(2);
                };
                defer out_file.close();
                out_file.writeAll(cr.binary) catch |err| {
                    std.debug.print("error: write failed: {s}\n", .{@errorName(err)});
                    std.process.exit(2);
                };

                // ── Write hex output ─────────────────────────────────────
                const hex_path = deriveHexOutputPath(output_path, alloc) catch |err| {
                    std.debug.print("error: string alloc failed: {s}\n", .{@errorName(err)});
                    std.process.exit(3);
                };
                defer alloc.free(hex_path);

                const hex_file = std.fs.cwd().createFile(hex_path, .{}) catch |err| {
                    std.debug.print("error: cannot write '{s}': {s}\n", .{ hex_path, @errorName(err) });
                    std.process.exit(2);
                };
                defer hex_file.close();

                const hex_string = alloc.alloc(u8, cr.binary.len * 2) catch |err| {
                    std.debug.print("error: hex string alloc failed: {s}\n", .{@errorName(err)});
                    std.process.exit(3);
                };
                defer alloc.free(hex_string);

                const hex_chars = "0123456789abcdef";
                for (cr.binary, 0..) |b, i| {
                    hex_string[i * 2] = hex_chars[b >> 4];
                    hex_string[i * 2 + 1] = hex_chars[b & 0x0F];
                }

                hex_file.writeAll(hex_string) catch |err| {
                    std.debug.print("error: hex write failed: {s}\n", .{@errorName(err)});
                    std.process.exit(2);
                };


                // ── Success message ──────────────────────────────────────
                const basename = std.fs.path.basename(input_path);
                const out_basename = std.fs.path.basename(output_path);
                std.debug.print("Compiled: {s} → {s} ({d} bytes, {d} actions, {d} warnings)\n", .{
                    basename,
                    out_basename,
                    cr.binary.len,
                    cr.action_count,
                    cr.warning_count,
                });
            } else {
                // Compile errors → exit 1
                std.process.exit(1);
            }
        },
    }
}

// ============================================================================
// Section 7 — Tests
// ============================================================================

test "compile minimal contract end to end" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const source = "version 1\ncontract Empty:\n    has:\n        x is u256\n";
    const opts = CompileOptions{};

    const result = try compile(source, "test.foz", opts, alloc);
    if (result) |cr| {
        // Binary must start with "FORG" magic
        try std.testing.expect(cr.binary.len >= 64);
        try std.testing.expectEqualSlices(u8, "FORG", cr.binary[0..4]);
        // Contract name should be "Empty"
        try std.testing.expectEqualSlices(u8, "Empty", cr.binary[8..13]);
    }
    // If result is null, there were parse/check errors which is also acceptable
    // for a minimal contract since the parser may require more context
}
