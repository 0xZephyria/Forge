// ============================================================================
// Forge Compiler — Error & Diagnostic System
// ============================================================================
//
// Defines every compile-time error the ZEPH compiler can produce, plus a
// rich diagnostic reporter that formats errors with file/line/column context,
// the offending source line, and a caret (^) underline.
//
// SPEC REFERENCE: Part 11 (Error Handling), Part 5.10 (Contract Errors)
//
// This is a library file. Do NOT add a main() function here.

const std = @import("std");

// ============================================================================
// Section 1 — CompileError (flat Zig error set)
// ============================================================================

/// All errors the ZEPH compiler can produce, as a flat Zig error set.
///
/// Errors are grouped by pipeline stage:
///   - Lexer errors: malformed tokens
///   - Parser errors: unexpected token structure
///   - Type errors: type system violations
///   - Semantic errors: higher-level contract-model violations
///   - Authority errors: authority-system misuse
///   - Access list errors: parallel-execution annotation violations
///   - Loop safety: unbounded loops missing required annotation
///   - Asset errors: linear-type system violations
///   - General: infrastructure errors
pub const CompileError = error{
    // ── Lexer errors ──────────────────────────────────────────────────────
    /// A character was encountered that does not begin any valid ZEPH token.
    UnexpectedCharacter,
    /// A string literal was opened but never closed before end-of-file.
    UnterminatedString,
    /// A numeric literal has an invalid form (e.g. `1__2`, trailing `_`).
    InvalidNumberLiteral,
    /// A hex literal has an invalid form (e.g. `0x`, `0xGG`).
    InvalidHexLiteral,

    // ── Parser errors ─────────────────────────────────────────────────────
    /// The parser encountered a token that does not fit the expected grammar
    /// position (e.g. a keyword where an expression was expected).
    UnexpectedToken,
    /// The parser expected a specific token kind but found something else.
    ExpectedToken,
    /// The source file ended while the parser was still inside a construct.
    UnexpectedEOF,
    /// A colon is required at this position but was absent.
    MissingColon,
    /// A `->` arrow is required at this position but was absent.
    MissingArrow,

    // ── Type errors ───────────────────────────────────────────────────────
    /// The inferred or declared type does not match the required type.
    TypeMismatch,
    /// An identifier was used before it was declared in any reachable scope.
    UndeclaredIdentifier,
    /// A type name was referenced that has not been declared in any scope.
    UndeclaredType,
    /// An account name was used in an expression but is not in the
    /// `accounts:` block of the current contract.
    UndeclaredAccount,
    /// An operator or built-in function was applied to a type it does not
    /// support (e.g. arithmetic on `bool`).
    InvalidTypeForOperation,
    /// An assignment was attempted to a `readonly` binding or constant.
    CannotAssignToReadonly,

    // ── Semantic errors ───────────────────────────────────────────────────
    /// A name was declared more than once in the same scope.
    DuplicateDeclaration,
    /// A struct or record has two fields with the same name.
    DuplicateField,
    /// A contract does not include a `setup` block, which is required.
    MissingSetupBlock,
    /// An account referenced in an action body was not declared in the
    /// `accounts:` block.
    AccountNotDeclared,
    /// A field was accessed via an account that is not listed in that
    /// account's capability set.
    FieldNotInCapabilityList,
    /// A write was attempted to an account declared as read-only in the
    /// access list.
    WriteToReadonlyAccount,
    /// An action read or wrote state from a different program's account
    /// namespace without a valid cross-program invocation declaration.
    CrossProgramStateAccess,

    // ── Authority errors ──────────────────────────────────────────────────
    /// An `only` guard referenced an authority name that is not declared in
    /// the contract's `authorities:` block.
    UnknownAuthority,
    /// The authority kind used in a guard does not match the declared kind
    /// (e.g. using a `Program` authority where a `Wallet` authority is
    /// required).
    AuthorityTypeMismatch,

    // ── Access list errors ────────────────────────────────────────────────
    /// An action wrote to an account field that was not listed in the
    /// `#[writes ...]` annotation.
    UndeclaredWrite,
    /// An action read from an account field that was not listed in the
    /// `#[reads ...]` annotation.
    UndeclaredRead,

    // ── Loop safety ───────────────────────────────────────────────────────
    /// A `repeat` or `while` loop whose iteration bound cannot be proven
    /// finite at compile time is missing the required `#[max_iterations N]`
    /// annotation.
    UnboundedLoopMissingAnnotation,

    // ── Asset (linear type) errors ────────────────────────────────────────
    /// A linear asset value went out of scope without being consumed
    /// (sent, stored, burned, or returned).
    LinearAssetDropped,
    /// A linear asset value was consumed more than once (move semantics
    /// violation).
    LinearAssetUsedTwice,
    /// A field marked as `immutable_fields` in an `upgrade:` block was modified.
    ImmutableFieldViolation,
    /// An annotation argument is malformed (e.g. invalid hex for sponsorship).
    InvalidAnnotationArgument,
    /// An asset transfer hook (`before_transfer`, etc.) has an invalid signature.
    InvalidHookSignature,

    // ── Novel feature errors ──────────────────────────────────────────────
    /// An action provably breaks a declared `conserves` equation.
    /// SPEC: Novel Idea 1 — Economic Conservation Proofs.
    ConservationViolated,
    /// An action body exceeds its declared gas complexity class.
    /// SPEC: Novel Idea 2 — Gas Complexity Class Annotations.
    ComplexityViolated,
    /// An adversary block achieved its expected bad outcome, indicating a bug.
    /// SPEC: Novel Idea 3 — Adversary Blocks.
    AttackSucceeded,
    /// An adversary attack was successfully prevented (informational).
    /// SPEC: Novel Idea 3 — Adversary Blocks.
    AttackBlocked,

    // ── General ───────────────────────────────────────────────────────────
    /// The allocator returned `error.OutOfMemory` during compilation.
    OutOfMemory,
    /// An unexpected internal compiler state was reached. File a bug report.
    InternalError,
};

// ============================================================================
// Section 2 — Diagnostic
// ============================================================================

/// A single compiler diagnostic: all information needed to print one error.
///
/// `source_line` is a slice into the original source buffer (no allocation).
/// `message` is heap-allocated via the `DiagnosticList` allocator and freed
/// by `DiagnosticList.deinit()`.
pub const Diagnostic = struct {
    /// Path of the source file (e.g. `"contracts/Token.foz"`).
    file: []const u8,
    /// 1-based line number of the error.
    line: u32,
    /// 1-based column number of the first offending character.
    col: u32,
    /// Number of characters the offending token spans (drives ^^^ width).
    len: u32,
    /// The specific compiler error kind.
    kind: CompileError,
    /// Human-readable description.  Heap-allocated; owned by DiagnosticList.
    message: []const u8,
    /// The complete text of the offending line (slice into source, not owned).
    source_line: []const u8,
};

// ============================================================================
// Section 3 — DiagnosticList
// ============================================================================

/// A growable list of `Diagnostic` values with a pretty-printer.
///
/// The list owns only the `message` strings inside each `Diagnostic`.
/// `source_line` slices and `file` slices are borrowed from the original
/// source buffer and must remain valid for the lifetime of this list.
///
/// In Zig 0.15 `std.ArrayListUnmanaged` is the canonical unmanaged list;
/// the allocator is stored separately and passed at each mutation call.
pub const DiagnosticList = struct {
    items: std.ArrayListUnmanaged(Diagnostic),
    allocator: std.mem.Allocator,

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /// Create an empty list backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) DiagnosticList {
        return .{
            .items    = .{},
            .allocator = allocator,
        };
    }

    /// Free all resources.  Frees every heap-allocated `message` string and
    /// the internal array storage.
    pub fn deinit(self: *DiagnosticList) void {
        for (self.items.items) |d| {
            self.allocator.free(d.message);
        }
        self.items.deinit(self.allocator);
    }

    // ── Mutation ──────────────────────────────────────────────────────────

    /// Append one diagnostic.  The caller must pass a `Diagnostic` whose
    /// `.message` field was allocated with `self.allocator`; ownership
    /// transfers to this list.
    pub fn add(self: *DiagnosticList, d: Diagnostic) anyerror!void {
        try self.items.append(self.allocator, d);
    }

    // ── Queries ───────────────────────────────────────────────────────────

    /// Returns `true` when the list contains at least one diagnostic.
    pub fn hasErrors(self: *const DiagnosticList) bool {
        return self.items.items.len > 0;
    }

    // ── Output ────────────────────────────────────────────────────────────

    /// Write every diagnostic in the list to `writer` in the canonical
    /// ZEPH compiler format:
    ///
    /// ```
    /// error[E0009]: type mismatch — expected u256, got bool
    ///  --> contracts/Token.foz:47:12
    ///   |
    /// 47 |     mine.balances[caller] = yes
    ///   |                            ^^^
    ///   |
    /// ```
    ///
    /// The error code is the index of the error tag in `CompileError`, zero-
    /// padded to four digits (e.g. `E0003`).
    pub fn print(self: *const DiagnosticList, writer: anytype) anyerror!void {
        for (self.items.items) |d| {
            try printDiagnostic(d, writer);
        }
    }
};

// ============================================================================
// Section 4 — Internal printing helpers
// ============================================================================

/// Compute the zero-padded error code number for a `CompileError`.
///
/// The code is derived from the declaration order of the error tags:
/// `UnexpectedCharacter` = 0, `UnterminatedString` = 1, etc.
fn errorCode(kind: CompileError) u16 {
    return switch (kind) {
        // Lexer
        error.UnexpectedCharacter            => 0,
        error.UnterminatedString             => 1,
        error.InvalidNumberLiteral           => 2,
        error.InvalidHexLiteral              => 3,
        // Parser
        error.UnexpectedToken                => 4,
        error.ExpectedToken                  => 5,
        error.UnexpectedEOF                  => 6,
        error.MissingColon                   => 7,
        error.MissingArrow                   => 8,
        // Type
        error.TypeMismatch                   => 9,
        error.UndeclaredIdentifier           => 10,
        error.UndeclaredType                 => 11,
        error.UndeclaredAccount              => 12,
        error.InvalidTypeForOperation        => 13,
        error.CannotAssignToReadonly         => 14,
        // Semantic
        error.DuplicateDeclaration           => 15,
        error.DuplicateField                 => 16,
        error.MissingSetupBlock              => 17,
        error.AccountNotDeclared             => 18,
        error.FieldNotInCapabilityList       => 19,
        error.WriteToReadonlyAccount         => 20,
        error.CrossProgramStateAccess        => 21,
        // Authority
        error.UnknownAuthority               => 22,
        error.AuthorityTypeMismatch          => 23,
        // Access list
        error.UndeclaredWrite                => 24,
        error.UndeclaredRead                 => 25,
        // Loop safety
        error.UnboundedLoopMissingAnnotation => 26,
        // Asset
        error.LinearAssetDropped             => 27,
        error.LinearAssetUsedTwice           => 28,
        error.ImmutableFieldViolation        => 29,
        error.InvalidAnnotationArgument      => 30,
        error.InvalidHookSignature           => 31,
        // Novel features
        error.ConservationViolated           => 32,
        error.ComplexityViolated             => 33,
        error.AttackSucceeded               => 34,
        error.AttackBlocked                 => 35,
        // General
        error.OutOfMemory                    => 36,
        error.InternalError                  => 37,
    };
}

/// The human-readable label shown after `error[Exxxx]:`.
fn errorLabel(kind: CompileError) []const u8 {
    return switch (kind) {
        error.UnexpectedCharacter            => "unexpected character",
        error.UnterminatedString             => "unterminated string literal",
        error.InvalidNumberLiteral           => "invalid number literal",
        error.InvalidHexLiteral              => "invalid hex literal",
        error.UnexpectedToken                => "unexpected token",
        error.ExpectedToken                  => "expected token",
        error.UnexpectedEOF                  => "unexpected end of file",
        error.MissingColon                   => "missing colon",
        error.MissingArrow                   => "missing arrow (->)",
        error.TypeMismatch                   => "type mismatch",
        error.UndeclaredIdentifier           => "undeclared identifier",
        error.UndeclaredType                 => "undeclared type",
        error.UndeclaredAccount              => "undeclared account",
        error.InvalidTypeForOperation        => "invalid type for operation",
        error.CannotAssignToReadonly         => "cannot assign to read-only binding",
        error.DuplicateDeclaration           => "duplicate declaration",
        error.DuplicateField                 => "duplicate field",
        error.MissingSetupBlock              => "missing setup block",
        error.AccountNotDeclared             => "account not declared in accounts: block",
        error.FieldNotInCapabilityList       => "field not in capability list",
        error.WriteToReadonlyAccount         => "write to read-only account",
        error.CrossProgramStateAccess        => "cross-program state access",
        error.UnknownAuthority               => "unknown authority",
        error.AuthorityTypeMismatch          => "authority type mismatch",
        error.UndeclaredWrite                => "undeclared write in access list",
        error.UndeclaredRead                 => "undeclared read in access list",
        error.UnboundedLoopMissingAnnotation => "unbounded loop missing #[max_iterations] annotation",
        error.LinearAssetDropped             => "linear asset dropped without consumption",
        error.LinearAssetUsedTwice           => "linear asset used more than once",
        error.ImmutableFieldViolation        => "immutable field modification violation",
        error.InvalidAnnotationArgument      => "invalid annotation argument",
        error.InvalidHookSignature           => "invalid asset transfer hook signature",
        // Novel features
        error.ConservationViolated           => "conservation proof violation",
        error.ComplexityViolated             => "gas complexity class exceeded",
        error.AttackSucceeded               => "adversary attack succeeded (potential vulnerability)",
        error.AttackBlocked                 => "adversary attack was blocked",
        // General
        error.OutOfMemory                    => "out of memory",
        error.InternalError                  => "internal compiler error",
    };
}

/// Render one `Diagnostic` to `writer`.
///
/// Output format (gutter width adapts to the line-number digit count):
///
/// ```
/// error[E0009]: type mismatch — expected u256, got bool
///  --> contracts/Token.foz:47:12
///   |
/// 47 |     mine.balances[caller] = yes
///   |                            ^^^
///   |
/// ```
///
/// The gutter (left of `|`) is `line_number_width + 1` characters wide so
/// that the `|` separator aligns between the location header and caret line.
fn printDiagnostic(d: Diagnostic, writer: anytype) anyerror!void {
    const code  = errorCode(d.kind);
    const label = errorLabel(d.kind);

    // ── Header line ───────────────────────────────────────────────────────
    // error[E0009]: type mismatch — expected u256, got bool
    try writer.print("error[E{d:0>4}]: {s} \u{2014} {s}\n", .{
        code,
        label,
        d.message,
    });

    // ── Gutter width ──────────────────────────────────────────────────────
    // Minimum 1 digit for the line number; the gutter is one wider.
    const line_num_width: usize = digitCount(d.line);
    const gutter_width: usize   = line_num_width + 1;

    // ── Location line ─────────────────────────────────────────────────────
    //  --> contracts/Token.foz:47:12
    try printSpaces(writer, gutter_width);
    try writer.print("--> {s}:{d}:{d}\n", .{ d.file, d.line, d.col });

    // ── Empty fence ───────────────────────────────────────────────────────
    //   |
    try printSpaces(writer, gutter_width);
    try writer.writeAll("|\n");

    // ── Source line ───────────────────────────────────────────────────────
    // Print the line number right-aligned in `line_num_width` columns,
    // then " | ", then the source text.
    //
    // We manually right-align because Zig 0.15 format width specifiers
    // via runtime values require the two-argument form:
    //   writer.print("{[v]d: >[w]}", .{ .v = d.line, .w = gutter_width })
    // which is only valid for comptime widths.  We emit the padding ourselves.
    const digits = digitCount(d.line);
    const padding = if (gutter_width > digits) gutter_width - digits else 0;
    try printSpaces(writer, padding);
    try writer.print("{d} | {s}\n", .{ d.line, d.source_line });

    // ── Caret line ────────────────────────────────────────────────────────
    //   |                            ^^^
    try printSpaces(writer, gutter_width);
    try writer.writeAll("| ");

    // col is 1-based; emit (col - 1) spaces before the carets.
    const caret_offset: usize = if (d.col > 0) @as(usize, d.col) - 1 else 0;
    try printSpaces(writer, caret_offset);

    const caret_len: usize = if (d.len > 0) @as(usize, d.len) else 1;
    try printChars(writer, '^', caret_len);
    try writer.writeByte('\n');

    // ── Trailing empty fence ──────────────────────────────────────────────
    //   |
    try printSpaces(writer, gutter_width);
    try writer.writeAll("|\n");

    // Blank separator between diagnostics
    try writer.writeByte('\n');
}

/// Return the count of decimal digits needed to represent `n` (minimum 1).
fn digitCount(n: u32) usize {
    if (n == 0) return 1;
    var count: usize = 0;
    var rem = n;
    while (rem > 0) : (rem /= 10) {
        count += 1;
    }
    return count;
}

/// Write `count` ASCII space characters to `writer`.
fn printSpaces(writer: anytype, count: usize) anyerror!void {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        try writer.writeByte(' ');
    }
}

/// Write `count` repetitions of byte `ch` to `writer`.
fn printChars(writer: anytype, ch: u8, count: usize) anyerror!void {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        try writer.writeByte(ch);
    }
}

// ============================================================================
// Section 5 — Public helper: create a Diagnostic with a formatted message
// ============================================================================

/// Allocate a `Diagnostic` with a heap-allocated `message` string.
///
/// The caller is responsible for eventually freeing `message` (normally by
/// passing the diagnostic to `DiagnosticList.add` and later calling
/// `DiagnosticList.deinit`).
///
/// Example:
/// ```zig
/// const d = try errors.makeDiagnostic(
///     allocator,
///     "contracts/Token.foz",
///     47, 12, 3,
///     CompileError.TypeMismatch,
///     "expected {s}, got {s}",
///     .{ "u256", "bool" },
///     source_line_slice,
/// );
/// try list.add(d);
/// ```
pub fn makeDiagnostic(
    allocator: std.mem.Allocator,
    file: []const u8,
    line: u32,
    col: u32,
    len: u32,
    kind: CompileError,
    comptime fmt: []const u8,
    args: anytype,
    source_line: []const u8,
) anyerror!Diagnostic {
    const message = try std.fmt.allocPrint(allocator, fmt, args);
    return Diagnostic{
        .file        = file,
        .line        = line,
        .col         = col,
        .len         = len,
        .kind        = kind,
        .message     = message,
        .source_line = source_line,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "diagnostic print format" {
    const allocator = std.testing.allocator;

    // Build a single diagnostic mimicking the spec's example:
    //   error[E0009]: type mismatch — expected u256, got bool
    //    --> contracts/Token.foz:47:12
    //     |
    //   47 |     mine.balances[caller] = yes
    //     |                            ^^^
    //     |
    const source_line: []const u8 = "    mine.balances[caller] = yes";
    const message = try std.fmt.allocPrint(allocator, "expected u256, got bool", .{});

    var list = DiagnosticList.init(allocator);
    defer list.deinit();

    try list.add(Diagnostic{
        .file        = "contracts/Token.foz",
        .line        = 47,
        .col         = 29,    // 1-based: 'y' in 'yes' (4 spaces + "mine.balances[caller] = " = 28 chars)
        .len         = 3,     // "yes"
        .kind        = CompileError.TypeMismatch,
        .message     = message,
        .source_line = source_line,
    });

    try std.testing.expect(list.hasErrors());

    // Capture output
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(allocator);
    try list.print(buf.writer(allocator));

    const output = buf.items;

    // Error code for TypeMismatch (index 9)
    try std.testing.expect(std.mem.indexOf(u8, output, "E0009") != null);

    // Human-readable label
    try std.testing.expect(std.mem.indexOf(u8, output, "type mismatch") != null);

    // User-supplied message
    try std.testing.expect(std.mem.indexOf(u8, output, "expected u256, got bool") != null);

    // file:line:col pattern
    try std.testing.expect(std.mem.indexOf(u8, output, "contracts/Token.foz:47:29") != null);

    // Source line verbatim
    try std.testing.expect(std.mem.indexOf(u8, output, source_line) != null);

    // Caret — exactly 3 '^' characters at the caret position
    try std.testing.expect(std.mem.indexOf(u8, output, "^^^") != null);
}

test "diagnostic hasErrors is false for empty list" {
    const allocator = std.testing.allocator;
    var list = DiagnosticList.init(allocator);
    defer list.deinit();
    try std.testing.expect(!list.hasErrors());
}

test "diagnostic multiple errors printed in order" {
    const allocator = std.testing.allocator;

    var list = DiagnosticList.init(allocator);
    defer list.deinit();

    const src_a: []const u8 = "let x is Foo = 42";
    const src_b: []const u8 = "loop repeat:";

    const msg_a = try std.fmt.allocPrint(allocator, "type 'Foo' is not declared", .{});
    const msg_b = try std.fmt.allocPrint(allocator, "loop has no #[max_iterations] annotation", .{});

    try list.add(Diagnostic{
        .file        = "contracts/A.foz",
        .line        = 3,
        .col         = 10,
        .len         = 3,
        .kind        = CompileError.UndeclaredType,
        .message     = msg_a,
        .source_line = src_a,
    });

    try list.add(Diagnostic{
        .file        = "contracts/B.foz",
        .line        = 99,
        .col         = 1,
        .len         = 4,
        .kind        = CompileError.UnboundedLoopMissingAnnotation,
        .message     = msg_b,
        .source_line = src_b,
    });

    try std.testing.expect(list.hasErrors());

    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(allocator);
    try list.print(buf.writer(allocator));

    const output = buf.items;

    // First error must appear before the second
    const pos_a = std.mem.indexOf(u8, output, "contracts/A.foz");
    const pos_b = std.mem.indexOf(u8, output, "contracts/B.foz");
    try std.testing.expect(pos_a != null);
    try std.testing.expect(pos_b != null);
    try std.testing.expect(pos_a.? < pos_b.?);

    // Caret for "loop" (len=4) — four carets
    try std.testing.expect(std.mem.indexOf(u8, output, "^^^^") != null);
}

test "makeDiagnostic helper allocates message correctly" {
    const allocator = std.testing.allocator;

    const source: []const u8 = "send asset to callar";

    var list = DiagnosticList.init(allocator);
    defer list.deinit();

    const d = try makeDiagnostic(
        allocator,
        "contracts/Vault.foz",
        12, 14, 6,
        CompileError.UndeclaredIdentifier,
        "identifier '{s}' is not declared in this scope",
        .{"callar"},
        source,
    );
    try list.add(d);

    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(allocator);
    try list.print(buf.writer(allocator));

    const output = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, output, "'callar' is not declared") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "contracts/Vault.foz:12:14") != null);
    // Six carets for len=6
    try std.testing.expect(std.mem.indexOf(u8, output, "^^^^^^") != null);
}

test "digitCount helper" {
    try std.testing.expectEqual(@as(usize, 1), digitCount(0));
    try std.testing.expectEqual(@as(usize, 1), digitCount(9));
    try std.testing.expectEqual(@as(usize, 2), digitCount(10));
    try std.testing.expectEqual(@as(usize, 2), digitCount(99));
    try std.testing.expectEqual(@as(usize, 3), digitCount(100));
    try std.testing.expectEqual(@as(usize, 5), digitCount(99999));
}
