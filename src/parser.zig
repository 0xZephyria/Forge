// ============================================================================
// Forge Compiler — Recursive Descent Parser  (Chunk 1/3)
// ============================================================================
// Consumes []Token from the lexer → produces []TopLevel AST nodes.
// ZEPH uses significant indentation; the parser tracks indent levels via
// token column numbers (col is 1-based, so indent = col - 1).
//
// This is a library file. No main() function.

const std    = @import("std");
const ast    = @import("ast.zig");
const lex    = @import("lexer.zig");
const errors = @import("errors.zig");

pub const Token          = lex.Token;
pub const TokenKind      = lex.TokenKind;
pub const Span           = ast.Span;
pub const CompileError   = errors.CompileError;
pub const DiagnosticList = errors.DiagnosticList;

// Re-export every AST type used in parse-rule return types.
pub const TopLevel       = ast.TopLevel;
pub const ContractDef    = ast.ContractDef;
pub const AssetDef       = ast.AssetDef;
pub const InterfaceDef   = ast.InterfaceDef;
pub const InterfaceMember= ast.InterfaceMember;
pub const InterfaceAction= ast.InterfaceAction;
pub const InterfaceView  = ast.InterfaceView;
pub const AccountDecl    = ast.AccountDecl;
pub const AccountKind    = ast.AccountKind;
pub const AccountOwnership = ast.AccountOwnership;
pub const CapabilityClause = ast.CapabilityClause;
pub const CapabilityAccess = ast.CapabilityAccess;
pub const SeedComponent  = ast.SeedComponent;
pub const AuthorityDecl  = ast.AuthorityDecl;
pub const AuthorityHolderKind = ast.AuthorityHolderKind;
pub const MultisigConfig = ast.MultisigConfig;
pub const DaoConfig      = ast.DaoConfig;
pub const StateField     = ast.StateField;
pub const ComputedField  = ast.ComputedField;
pub const ConfigField    = ast.ConfigField;
pub const ConstDecl      = ast.ConstDecl;
pub const SetupBlock     = ast.SetupBlock;
pub const GuardDecl      = ast.GuardDecl;
pub const ActionDecl     = ast.ActionDecl;
pub const ViewDecl       = ast.ViewDecl;
pub const PureDecl       = ast.PureDecl;
pub const HelperDecl     = ast.HelperDecl;
pub const EventDecl      = ast.EventDecl;
pub const EventField     = ast.EventField;
pub const ErrorDecl      = ast.ErrorDecl;
pub const ErrorField     = ast.ErrorField;
pub const UpgradeBlock   = ast.UpgradeBlock;
pub const InvariantDecl  = ast.InvariantDecl;
pub const Param          = ast.Param;
pub const TypeParam      = ast.TypeParam;
pub const TypeExpr       = ast.TypeExpr;
pub const Visibility     = ast.Visibility;
pub const Annotation     = ast.Annotation;
pub const AnnotationKind = ast.AnnotationKind;
pub const Stmt           = ast.Stmt;
pub const StmtKind       = ast.StmtKind;
pub const Expr           = ast.Expr;
pub const ExprKind       = ast.ExprKind;
pub const BinOp          = ast.BinOp;
pub const UnaryOp        = ast.UnaryOp;
pub const BuiltinExpr    = ast.BuiltinExpr;
pub const Argument       = ast.Argument;
pub const FieldInit      = ast.FieldInit;
pub const Pattern        = ast.Pattern;
pub const PatternFail    = ast.PatternFail;
pub const PackedEnumVariant = ast.PackedEnumVariant;
pub const FieldBinding   = ast.FieldBinding;
pub const MatchArm       = ast.MatchArm;
pub const UseImport      = ast.UseImport;
pub const StructDef      = ast.StructDef;
pub const RecordDef      = ast.RecordDef;
pub const RecordField    = ast.RecordField;
pub const EnumDef        = ast.EnumDef;
pub const EnumVariant    = ast.EnumVariant;
pub const TypeAliasDef   = ast.TypeAliasDef;
pub const SourceFile     = ast.SourceFile;

// Novel feature types
pub const ConservationExpr = ast.ConservationExpr;
pub const ConservationOp   = ast.ConservationOp;
pub const AggregatorKind   = ast.AggregatorKind;
pub const ComplexityClass  = ast.ComplexityClass;
pub const BoundExpr        = ast.BoundExpr;
pub const AdversaryBlock   = ast.AdversaryBlock;
pub const AttackSpec       = ast.AttackSpec;
pub const AttackCall       = ast.AttackCall;
pub const AttackOutcome    = ast.AttackOutcome;
pub const CapabilityDef    = ast.CapabilityDef;

// Statements
pub const LetBind        = ast.LetBind;
pub const Assign         = ast.Assign;
pub const AugAssign      = ast.AugAssign;
pub const AugOp          = ast.AugOp;
pub const WhenStmt       = ast.WhenStmt;
pub const ElseIf         = ast.ElseIf;
pub const MatchStmt      = ast.MatchStmt;
pub const EachLoop       = ast.EachLoop;
pub const EachBinding    = ast.EachBinding;
pub const RepeatLoop     = ast.RepeatLoop;
pub const WhileLoop      = ast.WhileLoop;
pub const NeedStmt       = ast.NeedStmt;
pub const NeedElse       = ast.NeedElse;
pub const TypedErrorCall = ast.TypedErrorCall;
pub const EnsureStmt     = ast.EnsureStmt;
pub const PanicStmt      = ast.PanicStmt;
pub const TellStmt       = ast.TellStmt;
pub const ThrowStmt      = ast.ThrowStmt;
pub const AttemptStmt    = ast.AttemptStmt;
pub const OnErrorClause  = ast.OnErrorClause;
pub const PayStmt        = ast.PayStmt;
pub const SendStmt       = ast.SendStmt;
pub const MoveStmt       = ast.MoveStmt;
pub const OnlyStmt       = ast.OnlyStmt;
pub const OnlyRequirement= ast.OnlyRequirement;
pub const TransferOwnershipStmt = ast.TransferOwnershipStmt;

// A synthetic EOF token returned when the parser is past the end.
const EOF_TOKEN: Token = .{
    .kind = .eof,
    .text = "",
    .span = .{ .line = 0, .col = 0, .len = 0 },
};

// ============================================================================
// Parser Struct
// ============================================================================

pub const Parser = struct {
    tokens:      []const Token,
    pos:         usize,
    allocator:   std.mem.Allocator,
    diagnostics: *DiagnosticList,
    source:      []const u8,
    file:        []const u8,

    // ── Lifecycle ─────────────────────────────────────────────────────────

    pub fn init(
        tokens:      []const Token,
        allocator:   std.mem.Allocator,
        diagnostics: *DiagnosticList,
        source:      []const u8,
        file:        []const u8,
    ) Parser {
        return .{
            .tokens      = tokens,
            .pos         = 0,
            .allocator   = allocator,
            .diagnostics = diagnostics,
            .source      = source,
            .file        = file,
        };
    }

    // ── Entry point ───────────────────────────────────────────────────────

    /// Parse all top-level declarations in the token stream.
    pub fn parse(self: *Parser) anyerror![]TopLevel {
        var list: std.ArrayListUnmanaged(TopLevel) = .{};
        errdefer list.deinit(self.allocator);

        while (self.peekKind() != .eof) {
            self.skipTrivia();
            const kind = self.peekKind();
            if (kind == .eof) break;

            // Handle optional "End;" terminator at top-level
            if (kind == .kw_end) {
                _ = self.advance();
                _ = try self.expect(.semicolon);
                continue;
            }

            if (try self.parseTopLevel()) |tl| {
                try list.append(self.allocator, tl);
            } else {
                // Unknown token at top level — emit error and skip.
                const tok = self.advance();
                try self.emitErr(tok.span, error.UnexpectedToken,
                    "unexpected token '{s}' at top level", .{tok.text});
                self.synchronize();
            }
        }

        return list.toOwnedSlice(self.allocator);
    }

    // ── Core helper methods ───────────────────────────────────────────────

    fn peek(self: *const Parser) Token {
        return if (self.pos < self.tokens.len) self.tokens[self.pos] else EOF_TOKEN;
    }

    fn peekKind(self: *const Parser) TokenKind {
        return self.peek().kind;
    }

    fn peekAt(self: *const Parser, offset: usize) Token {
        const i = self.pos + offset;
        return if (i < self.tokens.len) self.tokens[i] else EOF_TOKEN;
    }

    fn advance(self: *Parser) Token {
        const tok = self.peek();
        if (self.pos < self.tokens.len) self.pos += 1;
        return tok;
    }

    fn check(self: *const Parser, kind: TokenKind) bool {
        return self.peekKind() == kind;
    }

    /// Advance if the current token matches any of `kinds`; return true.
    fn matchAny(self: *Parser, kinds: []const TokenKind) bool {
        const k = self.peekKind();
        for (kinds) |want| {
            if (k == want) {
                _ = self.advance();
                return true;
            }
        }
        return false;
    }

    /// Consume the next token and assert it has the given kind.
    /// On failure: add a diagnostic, return error.ExpectedToken.
    fn expect(self: *Parser, kind: TokenKind) anyerror!Token {
        const tok = self.peek();
        if (tok.kind == kind) {
            return self.advance();
        }
        try self.emitErr(tok.span, error.ExpectedToken,
            "expected {s}, found '{s}'", .{ @tagName(kind), tok.text });
        return error.ExpectedToken;
    }

    /// Skip comment tokens (line_comment, doc_comment, block_comment).
    /// The parser calls this before each meaningful peek.
    fn skipTrivia(self: *Parser) void {
        while (self.pos < self.tokens.len) {
            switch (self.tokens[self.pos].kind) {
                .line_comment, .doc_comment, .block_comment => self.pos += 1,
                else => break,
            }
        }
    }

    /// Error recovery: advance past tokens until we find a safe restart point
    /// at the top-level (a keyword that begins a new declaration).
    fn synchronize(self: *Parser) void {
        while (self.peekKind() != .eof) {
            switch (self.peekKind()) {
                .kw_contract, .kw_action, .kw_view, .kw_event,
                .kw_error,    .kw_asset,  .kw_interface,
                .kw_version,  .kw_use,    .kw_define => return,
                else => _ = self.advance(),
            }
        }
    }

    // ── Indentation helpers ───────────────────────────────────────────────

    /// Return the 0-based indent of the current token (col - 1).
    fn currentIndent(self: *const Parser) u32 {
        const tok = self.peek();
        return if (tok.span.col > 0) tok.span.col - 1 else 0;
    }

    /// After seeing a colon, require the next non-trivia token to be on a
    /// new line with strictly greater indent than `parent_indent`.
    /// Returns the new block indent level.
    fn expectIndentIncrease(self: *Parser, parent_indent: u32) anyerror!u32 {
        self.skipTrivia();
        const new_indent = self.currentIndent();
        if (new_indent <= parent_indent) {
            const tok = self.peek();
            try self.emitErr(tok.span, error.ExpectedToken,
                "expected indented block (indent > {}), found indent {}", .{ parent_indent, new_indent });
            return error.ExpectedToken;
        }
        return new_indent;
    }

    /// True when the current token's indent is less than `block_indent`,
    /// or we've hit EOF.
    fn isBlockEnd(self: *const Parser, block_indent: u32) bool {
        if (self.peekKind() == .eof) return true;
        if (self.peekKind() == .kw_end) return true;
        const ind = self.currentIndent();
        return ind < block_indent;
    }

    // ── Diagnostic helper ─────────────────────────────────────────────────

    fn emitErr(
        self:        *Parser,
        span:        Span,
        kind:        CompileError,
        comptime fmt: []const u8,
        args:        anytype,
    ) anyerror!void {
        const msg = try std.fmt.allocPrint(self.allocator, fmt, args);
        // Derive source_line from the source buffer using span.line.
        const src_line = self.sourceLineAt(span.line);
        try self.diagnostics.add(.{
            .file        = self.file,
            .line        = span.line,
            .col         = span.col,
            .len         = span.len,
            .kind        = kind,
            .message     = msg,
            .source_line = src_line,
        });
    }

    fn sourceLineAt(self: *const Parser, line: u32) []const u8 {
        var cur_line: u32 = 1;
        var start:    usize = 0;
        var i:        usize = 0;
        while (i < self.source.len) : (i += 1) {
            if (cur_line == line) {
                start = i;
                while (i < self.source.len and self.source[i] != '\n') : (i += 1) {}
                return self.source[start..i];
            }
            if (self.source[i] == '\n') cur_line += 1;
        }
        return "";
    }

    // ── Allocation helpers ────────────────────────────────────────────────

    fn alloc(self: *Parser, val: anytype) anyerror!*@TypeOf(val) {
        const T = @TypeOf(val);
        const ptr = try self.allocator.create(T);
        ptr.* = val;
        return ptr;
    }

    // =====================================================================
    // TOP-LEVEL PARSE RULES
    // =====================================================================

    fn parseTopLevel(self: *Parser) anyerror!?TopLevel {
        self.skipTrivia();
        return switch (self.peekKind()) {
            .kw_version   => try self.parseVersion(),
            .kw_use       => try self.parseUse(),
            .kw_define    => try self.parseDefine(),
            .kw_asset     => .{ .asset_def    = try self.parseAsset()     },
            .kw_interface => .{ .interface_def = try self.parseInterface() },
            .kw_contract  => .{ .contract     = try self.parseContract()  },
            .kw_struct    => .{ .struct_def   = try self.parseStructDef() },
            .kw_record    => .{ .record_def   = try self.parseRecordDef() },
            .kw_enum      => .{ .enum_def     = try self.parseEnumDef()   },
            .kw_alias     => .{ .type_alias   = try self.parseTypeAlias() },
            .kw_global    => blk: {
                const start_col = self.peek().span.col;
                _ = self.advance();
                if (self.check(.kw_invariant)) {
                    break :blk .{ .global_invariant = try self.parseGlobalInvariant(start_col) };
                } else {
                    const tok = self.peek();
                    try self.emitErr(tok.span, error.ExpectedToken, "expected 'invariant' after 'global', found '{s}'", .{tok.text});
                    return error.ExpectedToken;
                }
            },
            .kw_global_invariant => .{ .global_invariant = try self.parseGlobalInvariant(self.peek().span.col) },
            else          => null,
        };
    }

    // ── version N ──────────────────────────────────────────────────────

    fn parseVersion(self: *Parser) anyerror!TopLevel {
        _ = try self.expect(.kw_version);
        const tok = try self.expect(.int_literal);
        const n = std.fmt.parseInt(u32, tok.text, 10) catch {
            try self.emitErr(tok.span, error.InvalidNumberLiteral,
                "invalid version number '{s}'", .{tok.text});
            return error.InvalidNumberLiteral;
        };
        return .{ .version = n };
    }

    // ── use module.path [as alias] ──────────────────────────────────────

    fn parseUse(self: *Parser) anyerror!TopLevel {
        const start_span = self.peek().span;
        _ = try self.expect(.kw_use);
        var path: std.ArrayListUnmanaged([]const u8) = .{};
        errdefer path.deinit(self.allocator);

        // Expect at least one identifier, then dot-separated names.
        const first = try self.expect(.identifier);
        try path.append(self.allocator, first.text);
        while (self.check(.dot)) {
            _ = self.advance();
            const seg = try self.expect(.identifier);
            try path.append(self.allocator, seg.text);
        }
        var alias: ?[]const u8 = null;
        if (self.check(.kw_as)) {
            _ = self.advance();
            const al = try self.expect(.identifier);
            alias = al.text;
        }
        return .{ .use_import = .{
            .path  = try path.toOwnedSlice(self.allocator),
            .alias = alias,
            .span  = start_span,
        }};
    }

    // ── define NAME as expr ─────────────────────────────────────────────

    fn parseDefine(self: *Parser) anyerror!TopLevel {
        const start_span = self.peek().span;
        _ = try self.expect(.kw_define);
        const name_tok = try self.expect(.identifier);
        _ = try self.expect(.kw_as);
        const val = try self.parseExpr();
        return .{ .constant = .{
            .name  = name_tok.text,
            .type_ = null,
            .value = val,
            .span  = start_span,
        }};
    }

    // ── struct Name { ... } ─────────────────────────────────────────────

    fn parseStructDef(self: *Parser) anyerror!StructDef {
        const start   = self.peek().span;
        _ = try self.expect(.kw_struct);
        const name    = (try self.expect(.identifier)).text;
        var type_params: std.ArrayListUnmanaged(TypeParam) = .{};
        if (self.check(.lbracket)) {
            type_params = try self.parseTypeParams();
        }
        _ = try self.expect(.colon);
        const parent_indent = start.col - 1;
        const block_indent  = try self.expectIndentIncrease(parent_indent);
        var fields: std.ArrayListUnmanaged(RecordField) = .{};
        errdefer fields.deinit(self.allocator);
        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            const f = try self.parseRecordField();
            try fields.append(self.allocator, f);
            _ = self.matchAny(&.{.comma});
        }
        return .{
            .name        = name,
            .type_params = try type_params.toOwnedSlice(self.allocator),
            .fields      = try fields.toOwnedSlice(self.allocator),
            .span        = start,
        };
    }

    // ── record Name { ... } ─────────────────────────────────────────────

    fn parseRecordDef(self: *Parser) anyerror!RecordDef {
        const start = self.peek().span;
        _ = try self.expect(.kw_record);
        const name  = (try self.expect(.identifier)).text;
        _ = try self.expect(.colon);
        const parent_indent = start.col - 1;
        const block_indent  = try self.expectIndentIncrease(parent_indent);
        var fields: std.ArrayListUnmanaged(RecordField) = .{};
        errdefer fields.deinit(self.allocator);
        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            const f = try self.parseRecordField();
            try fields.append(self.allocator, f);
            _ = self.matchAny(&.{.comma});
        }
        return .{
            .name   = name,
            .fields = try fields.toOwnedSlice(self.allocator),
            .span   = start,
        };
    }

    fn parseRecordField(self: *Parser) anyerror!RecordField {
        const span = self.peek().span;
        const name = (try self.expect(.identifier)).text;
        _ = try self.expect(.kw_is);
        const ty   = try self.parseType();
        var def: ?*Expr = null;
        if (self.check(.equals_sign)) {
            _ = self.advance();
            def = try self.parseExpr();
        }
        return .{ .name = name, .type_ = ty, .default = def, .span = span };
    }

    // ── enum Name { Variant, Variant { fields } } ───────────────────────

    fn parseEnumDef(self: *Parser) anyerror!EnumDef {
        const start = self.peek().span;
        _ = try self.expect(.kw_enum);
        const name  = (try self.expect(.identifier)).text;
        _ = try self.expect(.colon);
        const parent_indent = start.col - 1;
        const block_indent  = try self.expectIndentIncrease(parent_indent);
        var variants: std.ArrayListUnmanaged(EnumVariant) = .{};
        errdefer variants.deinit(self.allocator);
        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            const vspan  = self.peek().span;
            const vname  = (try self.expect(.identifier)).text;
            var fields: std.ArrayListUnmanaged(RecordField) = .{};
            if (self.check(.lbrace)) {
                _ = self.advance();
                while (!self.check(.rbrace) and self.peekKind() != .eof) {
                    const f = try self.parseRecordField();
                    try fields.append(self.allocator, f);
                    _ = self.matchAny(&.{.comma});
                }
                _ = try self.expect(.rbrace);
            }
            try variants.append(self.allocator, .{
                .name   = vname,
                .fields = try fields.toOwnedSlice(self.allocator),
                .span   = vspan,
            });
            _ = self.matchAny(&.{.comma});
        }
        return .{ .name = name, .variants = try variants.toOwnedSlice(self.allocator), .span = start };
    }

    // ── alias NewName = ExistingType ─────────────────────────────────────

    fn parseTypeAlias(self: *Parser) anyerror!TypeAliasDef {
        const start = self.peek().span;
        _ = try self.expect(.kw_alias);
        const name  = (try self.expect(.identifier)).text;
        _ = try self.expect(.equals_sign);
        const ty   = try self.parseType();
        return .{ .name = name, .type_ = ty, .span = start };
    }

    // ── asset Name { ... } ─────────────────────────────────────────────

    fn parseAsset(self: *Parser) anyerror!AssetDef {
        const start = self.peek().span;
        _ = try self.expect(.kw_asset);
        const name  = (try self.expect(.identifier)).text;
        _ = try self.expect(.colon);
        const parent_indent = start.col - 1;
        const block_indent  = try self.expectIndentIncrease(parent_indent);

        var display_name:      ?[]const u8 = null;
        var symbol:            ?[]const u8 = null;
        var decimals:          ?u8         = null;
        var max_supply:        ?*Expr      = null;
        var authorities:       std.ArrayListUnmanaged(AuthorityDecl) = .{};
        var before_transfer:   ?ast.AssetTransferHook = null;
        var after_transfer:    ?ast.AssetTransferHook  = null;
        var metadata_per_token = false;

        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            switch (self.peekKind()) {
                .kw_authorities => {
                    _ = self.advance();
                    _ = try self.expect(.colon);
                    const auth_indent = try self.expectIndentIncrease(block_indent);
                    while (!self.isBlockEnd(auth_indent)) {
                        self.skipTrivia();
                        if (self.isBlockEnd(auth_indent)) break;
                        const ad = try self.parseAuthorityDecl(auth_indent);
                        try authorities.append(self.allocator, ad);
                    }
                },
                .identifier => {
                    const key = (try self.expect(.identifier)).text;
                    _ = try self.expect(.colon);
                    if (std.mem.eql(u8, key, "name")) {
                        display_name = (try self.expect(.string_literal)).text;
                    } else if (std.mem.eql(u8, key, "symbol")) {
                        symbol = (try self.expect(.string_literal)).text;
                    } else if (std.mem.eql(u8, key, "decimals")) {
                        const n = try self.expect(.int_literal);
                        decimals = @intCast(std.fmt.parseInt(u8, n.text, 10) catch 18);
                    } else if (std.mem.eql(u8, key, "max_supply")) {
                        max_supply = try self.parseExpr();
                    } else if (std.mem.eql(u8, key, "metadata_per_token")) {
                        metadata_per_token = self.check(.kw_yes);
                        _ = self.advance();
                    } else if (std.mem.eql(u8, key, "before_transfer")) {
                        before_transfer = try self.parseTransferHook(.before_transfer, block_indent);
                    } else if (std.mem.eql(u8, key, "after_transfer")) {
                        after_transfer = try self.parseTransferHook(.after_transfer, block_indent);
                    } else {
                        const tok = self.peek();
                        try self.emitErr(tok.span, error.UnexpectedToken,
                            "unknown asset field '{s}'", .{key});
                        _ = self.advance();
                    }
                },
                else => _ = self.advance(),
            }
        }

        return .{
            .name               = name,
            .display_name       = display_name,
            .symbol             = symbol,
            .decimals           = decimals,
            .max_supply         = max_supply,
            .authorities        = try authorities.toOwnedSlice(self.allocator),
            .before_transfer    = before_transfer,
            .after_transfer     = after_transfer,
            .metadata_per_token = metadata_per_token,
            .span               = start,
        };
    }

    fn parseGlobalInvariant(self: *Parser, start_col: u32) anyerror!ast.GlobalInvariantDef {
        const start = self.peek().span;
        _ = try self.expect(.kw_invariant);
        const name = (try self.expect(.identifier)).text;
        _ = try self.expect(.colon);
        const parent_indent = start_col - 1;
        const block_indent = try self.expectIndentIncrease(parent_indent);

        var participants = std.ArrayListUnmanaged([]const u8){};
        var always_conditions = std.ArrayListUnmanaged(ast.InvariantDecl){};
        var on_violation: []ast.Stmt = &[_]ast.Stmt{};

        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            const key = (try self.expect(.identifier)).text;
            _ = try self.expect(.colon);
            if (std.mem.eql(u8, key, "on_violation")) {
                const inner_indent = try self.expectIndentIncrease(block_indent);
                on_violation = try self.parseBlock(inner_indent);
            } else if (std.mem.eql(u8, key, "participants")) {
                _ = try self.expect(.lbracket);
                while (!self.check(.rbracket) and self.peekKind() != .eof) {
                    try participants.append(self.allocator, (try self.expect(.identifier)).text);
                    _ = self.matchAny(&.{.comma});
                }
                _ = try self.expect(.rbracket);
            } else {
                const tok = self.peek();
                try self.emitErr(tok.span, error.UnexpectedToken, "unknown invariant field '{s}'", .{key});
                _ = self.advance();
            }
        }

        return .{
            .name = name,
            .participants = try participants.toOwnedSlice(self.allocator),
            .always_conditions = try always_conditions.toOwnedSlice(self.allocator),
            .on_violation = on_violation,
            .span = start,
        };
    }

    fn parseTransferHook(self: *Parser, when: ast.AssetHookWhen, parent_indent: u32) anyerror!ast.AssetTransferHook {
        const params = try self.parseParamList();
        _ = try self.expect(.colon);
        const hook_indent = try self.expectIndentIncrease(parent_indent);
        const body = try self.parseBlock(hook_indent);
        return .{ .when = when, .params = params, .body = body, .span = self.peek().span };
    }

    // ── interface Name { ... } ─────────────────────────────────────────

    fn parseInterface(self: *Parser) anyerror!InterfaceDef {
        const start = self.peek().span;
        _ = try self.expect(.kw_interface);
        const name  = (try self.expect(.identifier)).text;
        _ = try self.expect(.colon);
        const parent_indent = start.col - 1;
        const block_indent  = try self.expectIndentIncrease(parent_indent);

        var members: std.ArrayListUnmanaged(InterfaceMember) = .{};
        errdefer members.deinit(self.allocator);

        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            switch (self.peekKind()) {
                .kw_action => {
                    const ad = try self.parseInterfaceAction();
                    try members.append(self.allocator, .{ .action = ad });
                },
                .kw_view => {
                    const vd = try self.parseInterfaceView();
                    try members.append(self.allocator, .{ .view = vd });
                },
                .kw_event => {
                    const ed = try self.parseEvent();
                    try members.append(self.allocator, .{ .event = ed });
                },
                .kw_error => {
                    const er = try self.parseError_();
                    try members.append(self.allocator, .{ .error_ = er });
                },
                else => _ = self.advance(),
            }
        }

        return .{
            .name    = name,
            .members = try members.toOwnedSlice(self.allocator),
            .span    = start,
        };
    }

    fn parseInterfaceAction(self: *Parser) anyerror!InterfaceAction {
        const start = self.peek().span;
        _ = try self.expect(.kw_action);
        const name  = (try self.expect(.identifier)).text;
        const params = try self.parseParamList();
        var ret: ?TypeExpr = null;
        if (self.check(.kw_gives)) {
            _ = self.advance();
            ret = try self.parseType();
        }
        return .{ .name = name, .params = params, .return_type = ret, .span = start };
    }

    fn parseInterfaceView(self: *Parser) anyerror!InterfaceView {
        const start = self.peek().span;
        _ = try self.expect(.kw_view);
        const name  = (try self.expect(.identifier)).text;
        const params = try self.parseParamList();
        var ret: ?TypeExpr = null;
        if (self.check(.kw_gives)) {
            _ = self.advance();
            ret = try self.parseType();
        }
        return .{ .name = name, .params = params, .return_type = ret, .span = start };
    }

    // ── contract Name { ... } ─────────────────────────────────────────

    fn parseContract(self: *Parser) anyerror!ContractDef {
        const start = self.peek().span;
        _ = try self.expect(.kw_contract);
        const name  = (try self.expect(.identifier)).text;

        var inherits:   ?[]const u8 = null;
        var implements: std.ArrayListUnmanaged([]const u8) = .{};

        if (self.check(.kw_inherits)) {
            _ = self.advance();
            inherits = (try self.expect(.identifier)).text;
        }
        if (self.check(.kw_implements)) {
            _ = self.advance();
            const iname = (try self.expect(.identifier)).text;
            try implements.append(self.allocator, iname);
            while (self.check(.comma)) {
                _ = self.advance();
                const in2 = (try self.expect(.identifier)).text;
                try implements.append(self.allocator, in2);
            }
        }

        _ = try self.expect(.colon);
        const parent_indent = start.col - 1;
        const block_indent  = try self.expectIndentIncrease(parent_indent);

        var accounts:    std.ArrayListUnmanaged(AccountDecl)   = .{};
        var authorities: std.ArrayListUnmanaged(AuthorityDecl) = .{};
        var config:      std.ArrayListUnmanaged(ConfigField)   = .{};
        var always_:     std.ArrayListUnmanaged(ConstDecl)     = .{};
        var state:       std.ArrayListUnmanaged(StateField)    = .{};
        var computed:    std.ArrayListUnmanaged(ComputedField) = .{};
        var guards:      std.ArrayListUnmanaged(GuardDecl)     = .{};
        var actions:     std.ArrayListUnmanaged(ActionDecl)    = .{};
        var views:       std.ArrayListUnmanaged(ViewDecl)      = .{};
        var pures:       std.ArrayListUnmanaged(PureDecl)      = .{};
        var helpers:     std.ArrayListUnmanaged(HelperDecl)    = .{};
        var events:      std.ArrayListUnmanaged(EventDecl)     = .{};
        var errs:        std.ArrayListUnmanaged(ErrorDecl)     = .{};
        var namespaces:  std.ArrayListUnmanaged([]const u8)    = .{};
        var invariants:  std.ArrayListUnmanaged(InvariantDecl) = .{};
        var conserves:   std.ArrayListUnmanaged(ConservationExpr) = .{};
        var adversary_blocks: std.ArrayListUnmanaged(AdversaryBlock) = .{};
        var setup_block: ?SetupBlock     = null;
        var upgrade:     ?UpgradeBlock   = null;
        var fallback_h:  ?ActionDecl     = null;
        var receive_h:   ?ActionDecl     = null;

        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;

            switch (self.peekKind()) {
                .kw_accounts => {
                    const accs = try self.parseAccountsBlock(block_indent);
                    try accounts.appendSlice(self.allocator, accs);
                },
                .kw_authorities => {
                    const auths = try self.parseAuthoritiesBlock(block_indent);
                    try authorities.appendSlice(self.allocator, auths);
                },
                .kw_has => {
                    const sf = try self.parseHasBlock(block_indent);
                    try state.appendSlice(self.allocator, sf);
                },
                .kw_computed => {
                    const cf = try self.parseComputedBlock(block_indent);
                    try computed.appendSlice(self.allocator, cf);
                },
                .kw_config => {
                    const cfg = try self.parseConfigBlock(block_indent);
                    try config.appendSlice(self.allocator, cfg);
                },
                .kw_always => {
                    const al = try self.parseAlwaysBlock(block_indent);
                    try always_.appendSlice(self.allocator, al);
                },
                .kw_setup => {
                    setup_block = try self.parseSetup(block_indent);
                },
                .kw_guard => {
                    const gd = try self.parseGuard(block_indent);
                    try guards.append(self.allocator, gd);
                },
                .hash_sym, .kw_action => {
                    const ad = try self.parseAction(block_indent);
                    try actions.append(self.allocator, ad);
                },
                .kw_view => {
                    const vd = try self.parseView(block_indent);
                    try views.append(self.allocator, vd);
                },
                .kw_pure => {
                    const pd = try self.parsePure(block_indent);
                    try pures.append(self.allocator, pd);
                },
                .kw_helper => {
                    const hd = try self.parseHelper(block_indent);
                    try helpers.append(self.allocator, hd);
                },
                .kw_event => {
                    const ed = try self.parseEvent();
                    try events.append(self.allocator, ed);
                },
                .kw_error => {
                    const er = try self.parseError_();
                    try errs.append(self.allocator, er);
                },
                .kw_namespace => {
                    _ = self.advance();
                    const ns = (try self.expect(.identifier)).text;
                    try namespaces.append(self.allocator, ns);
                },
                .kw_invariant => {
                    const iv = try self.parseInvariant();
                    try invariants.append(self.allocator, iv);
                },
                .kw_upgrade => {
                    upgrade = try self.parseUpgrade(block_indent);
                },
                .kw_conserves => {
                    const cons = try self.parseConservesBlock(block_indent);
                    try conserves.appendSlice(self.allocator, cons);
                },
                .kw_adversary => {
                    const adv = try self.parseAdversaryBlock(block_indent);
                    try adversary_blocks.append(self.allocator, adv);
                },
                .kw_fallback => {
                    _ = self.advance(); // skip fallback
                    _ = try self.expect(.colon);
                    fallback_h = try self.parseAction(block_indent);
                },
                .kw_receive => {
                    _ = self.advance(); // skip receive
                    _ = try self.expect(.colon);
                    receive_h = try self.parseAction(block_indent);
                },
                else => _ = self.advance(),
            }
        }

        // Consume optional explicit `End;` contract terminator.
        if (self.peekKind() == .kw_end) {
            _ = self.advance();
            _ = self.matchAny(&.{.semicolon});
        }

        return .{
            .name        = name,
            .inherits    = inherits,
            .implements  = try implements.toOwnedSlice(self.allocator),
            .accounts    = try accounts.toOwnedSlice(self.allocator),
            .authorities = try authorities.toOwnedSlice(self.allocator),
            .config      = try config.toOwnedSlice(self.allocator),
            .always      = try always_.toOwnedSlice(self.allocator),
            .state       = try state.toOwnedSlice(self.allocator),
            .computed    = try computed.toOwnedSlice(self.allocator),
            .setup       = setup_block,
            .guards      = try guards.toOwnedSlice(self.allocator),
            .actions     = try actions.toOwnedSlice(self.allocator),
            .views       = try views.toOwnedSlice(self.allocator),
            .pures       = try pures.toOwnedSlice(self.allocator),
            .helpers     = try helpers.toOwnedSlice(self.allocator),
            .events      = try events.toOwnedSlice(self.allocator),
            .errors_     = try errs.toOwnedSlice(self.allocator),
            .upgrade     = upgrade,
            .namespaces  = try namespaces.toOwnedSlice(self.allocator),
            .invariants  = try invariants.toOwnedSlice(self.allocator),
            .conserves   = try conserves.toOwnedSlice(self.allocator),
            .adversary_blocks = try adversary_blocks.toOwnedSlice(self.allocator),
            .fallback    = fallback_h,
            .receive_    = receive_h,
            .span        = start,
        };
    }

    // ── Generic type param list: [T where T follows I, ...] ───────────────

    fn parseTypeParams(self: *Parser) anyerror!std.ArrayListUnmanaged(TypeParam) {
        var list: std.ArrayListUnmanaged(TypeParam) = .{};
        _ = try self.expect(.lbracket);
        while (!self.check(.rbracket) and self.peekKind() != .eof) {
            const n = (try self.expect(.identifier)).text;
            var constraint: ?[]const u8 = null;
            if (self.check(.kw_where)) {
                _ = self.advance();
                _ = try self.expect(.identifier); // the T again
                _ = try self.expect(.kw_follows);
                constraint = (try self.expect(.identifier)).text;
            }
            try list.append(self.allocator, .{ .name = n, .constraint = constraint });
            _ = self.matchAny(&.{.comma});
        }
        _ = try self.expect(.rbracket);
        return list;
    }

    // ── Param list: (name is Type, ...) ───────────────────────────────────

    fn parseParamList(self: *Parser) anyerror![]Param {
        var list: std.ArrayListUnmanaged(Param) = .{};
        errdefer list.deinit(self.allocator);
        if (!self.check(.lparen)) return list.toOwnedSlice(self.allocator);
        _ = self.advance();
        while (!self.check(.rparen) and self.peekKind() != .eof) {
            var is_private = false;
            while (self.check(.hash_sym)) {
                const ann = try self.parseAnnotation();
                if (ann.kind == .private) is_private = true;
            }
            const span  = self.peek().span;
            const pname = (try self.expect(.identifier)).text;
            _ = try self.expect(.kw_is);
            const ty    = try self.parseType();
            try list.append(self.allocator, .{
                .name          = pname,
                .declared_type = ty,
                .is_private    = is_private,
                .span          = span,
            });
            _ = self.matchAny(&.{.comma});
        }
        _ = try self.expect(.rparen);
        return list.toOwnedSlice(self.allocator);
    }

    // =========================================================
    // CONTRACT SECTION PARSE RULES
    // =========================================================

    // ── accounts: block ─────────────────────────────────────

    fn parseAccountsBlock(self: *Parser, parent_indent: u32) anyerror![]AccountDecl {
        _ = try self.expect(.kw_accounts);
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        var list: std.ArrayListUnmanaged(AccountDecl) = .{};
        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            const ad = try self.parseAccountDecl(block_indent);
            try list.append(self.allocator, ad);
        }
        return list.toOwnedSlice(self.allocator);
    }

    fn parseAccountDecl(self: *Parser, _: u32) anyerror!AccountDecl {
        const span  = self.peek().span;
        const name  = (try self.expect(.identifier)).text;
        _ = try self.expect(.kw_is);

        // Kind keyword: Data, Vault, Asset, Oracle, Wallet, Program
        const kind_tok = self.peek();
        const kind: AccountKind = switch (kind_tok.kind) {
            .identifier => blk: {
                const t = kind_tok.text;
                const k: AccountKind = if (std.mem.eql(u8, t, "Data"))    .data
                    else if (std.mem.eql(u8, t, "Vault"))   .vault
                    else if (std.mem.eql(u8, t, "Asset"))   .asset
                    else if (std.mem.eql(u8, t, "Oracle"))  .oracle
                    else if (std.mem.eql(u8, t, "Wallet"))  .wallet
                    else if (std.mem.eql(u8, t, "Program")) .program
                    else .data;
                _ = self.advance();
                break :blk k;
            },
            .kw_wallet_type  => blk: { _ = self.advance(); break :blk .wallet; },
            .kw_program_type => blk: { _ = self.advance(); break :blk .program; },
            else => blk: { _ = self.advance(); break :blk .data; },
        };

        // Optional generic type param: Vault[OurToken]
        var type_param: ?TypeExpr = null;
        if (self.check(.lbracket)) {
            _ = self.advance();
            type_param = try self.parseType();
            _ = try self.expect(.rbracket);
        }

        // Ownership: owned_by this / owned_by params.X / owned_by Name / global
        var ownership: AccountOwnership = .global;
        if (self.check(.kw_owned_by)) {
            _ = self.advance();
            if (self.check(.kw_this)) {
                _ = self.advance();
                ownership = .this;
            } else if (self.check(.kw_params)) {
                _ = self.advance();
                _ = try self.expect(.dot);
                const field = (try self.expect(.identifier)).text;
                ownership = .{ .param = field };
            } else {
                const n = (try self.expect(.identifier)).text;
                ownership = .{ .named = n };
            }
        } else if (self.check(.kw_global)) {
            _ = self.advance();
            ownership = .global;
        }

        // Seeds: seeded_by [...]
        var seeds: std.ArrayListUnmanaged(SeedComponent) = .{};
        if (self.check(.kw_seeded_by)) {
            _ = self.advance();
            _ = try self.expect(.lbracket);
            while (!self.check(.rbracket) and self.peekKind() != .eof) {
                if (self.check(.string_literal)) {
                    const s = self.advance().text;
                    try seeds.append(self.allocator, .{ .string_lit = s });
                } else {
                    const e = try self.parseExpr();
                    try seeds.append(self.allocator, .{ .expr = e });
                }
                _ = self.matchAny(&.{.comma});
            }
            _ = try self.expect(.rbracket);
        }

        var readonly           = false;
        var create_if_missing  = false;
        var initial_size: ?u64 = null;
        var known_address: ?[]const u8 = null;
        var child_of:      ?[]const u8 = null;
        var capabilities: std.ArrayListUnmanaged(CapabilityClause) = .{};

        // Attribute keywords on remainder of line
        var scanning = true;
        while (scanning) {
            switch (self.peekKind()) {
                .kw_readonly          => { readonly = true;            _ = self.advance(); },
                .kw_create_if_missing => { create_if_missing = true;   _ = self.advance(); },
                .kw_child_of          => {
                    _ = self.advance();
                    child_of = (try self.expect(.identifier)).text;
                },
                .kw_at => {
                    _ = self.advance();
                    // known.XYZ
                    if (self.check(.kw_known)) {
                        _ = self.advance(); _ = try self.expect(.dot);
                    }
                    known_address = (try self.expect(.identifier)).text;
                },
                .kw_can => {
                    _ = self.advance();
                    _ = try self.expect(.colon);
                    const cap_indent = self.currentIndent();
                    while (self.currentIndent() >= cap_indent and !self.isBlockEnd(cap_indent)) {
                        self.skipTrivia();
                        if (self.isBlockEnd(cap_indent)) break;
                        const acc: CapabilityAccess = switch (self.peekKind()) {
                            .kw_read   => blk: { _ = self.advance(); break :blk .read;   },
                            .kw_write  => blk: { _ = self.advance(); break :blk .write;  },
                            .kw_debit  => blk: { _ = self.advance(); break :blk .debit;  },
                            .kw_credit => blk: { _ = self.advance(); break :blk .credit; },
                            else       => break,
                        };
                        var fields: ?[][]const u8 = null;
                        // Collect optional field name list
                        if (self.check(.identifier)) {
                            var fs: std.ArrayListUnmanaged([]const u8) = .{};
                            while (self.check(.identifier) or self.check(.comma)) {
                                if (self.check(.comma)) { _ = self.advance(); continue; }
                                try fs.append(self.allocator, self.advance().text);
                            }
                            fields = try fs.toOwnedSlice(self.allocator);
                        }
                        try capabilities.append(self.allocator, .{ .access = acc, .fields = fields });
                    }
                },
                // `initial_size N bytes`
                .identifier => {
                    if (std.mem.eql(u8, self.peek().text, "initial_size")) {
                        _ = self.advance();
                        const n = try self.expect(.int_literal);
                        initial_size = std.fmt.parseInt(u64, n.text, 10) catch 0;
                        _ = self.matchAny(&.{.identifier}); // consume "bytes"
                    } else break;
                },
                else => scanning = false,
            }
        }

        return .{
            .name              = name,
            .kind              = kind,
            .type_param        = type_param,
            .ownership         = ownership,
            .seeds             = try seeds.toOwnedSlice(self.allocator),
            .readonly          = readonly,
            .capabilities      = try capabilities.toOwnedSlice(self.allocator),
            .create_if_missing = create_if_missing,
            .initial_size      = initial_size,
            .known_address     = known_address,
            .child_of          = child_of,
            .span              = span,
        };
    }

    // ── authorities: block ───────────────────────────────────

    fn parseAuthoritiesBlock(self: *Parser, parent_indent: u32) anyerror![]AuthorityDecl {
        _ = try self.expect(.kw_authorities);
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        var list: std.ArrayListUnmanaged(AuthorityDecl) = .{};
        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            const ad = try self.parseAuthorityDecl(block_indent);
            try list.append(self.allocator, ad);
        }
        return list.toOwnedSlice(self.allocator);
    }

    fn parseAuthorityDecl(self: *Parser, _: u32) anyerror!AuthorityDecl {
        const span = self.peek().span;
        const name = (try self.expect(.identifier)).text;
        _ = try self.expect(.kw_is);
        const kind = (try self.expect(.identifier)).text;
        _ = try self.expect(.kw_held_by);

        var holder_type    = AuthorityHolderKind.wallet;
        var multisig_cfg: ?MultisigConfig = null;
        var dao_cfg:      ?DaoConfig      = null;

        const holder_tok = self.peek();
        if (std.mem.eql(u8, holder_tok.text, "Multisig")) {
            _ = self.advance();
            holder_type = .multisig;
            if (self.check(.lbrace)) {
                _ = self.advance();
                var signers: std.ArrayListUnmanaged(*Expr) = .{};
                var required: u32 = 0;
                var time_window: ?*Expr = null;
                while (!self.check(.rbrace) and self.peekKind() != .eof) {
                    const key = (try self.expect(.identifier)).text;
                    _ = try self.expect(.colon);
                    if (std.mem.eql(u8, key, "signers")) {
                        _ = try self.expect(.lbracket);
                        while (!self.check(.rbracket) and self.peekKind() != .eof) {
                            try signers.append(self.allocator, try self.parseExpr());
                            _ = self.matchAny(&.{.comma});
                        }
                        _ = try self.expect(.rbracket);
                    } else if (std.mem.eql(u8, key, "required")) {
                        const n = try self.expect(.int_literal);
                        required = @intCast(std.fmt.parseInt(u32, n.text, 10) catch 0);
                    } else if (std.mem.eql(u8, key, "time_window")) {
                        time_window = try self.parseExpr();
                    }
                    _ = self.matchAny(&.{.comma});
                }
                _ = try self.expect(.rbrace);
                multisig_cfg = .{
                    .signers     = try signers.toOwnedSlice(self.allocator),
                    .required    = required,
                    .time_window = time_window,
                };
            }
        } else if (std.mem.eql(u8, holder_tok.text, "DAO")) {
            _ = self.advance(); holder_type = .dao;
            if (self.check(.lbrace)) {
                _ = self.advance();
                var gov_program: []const u8 = "";
                while (!self.check(.rbrace) and self.peekKind() != .eof) {
                    const key = (try self.expect(.identifier)).text;
                    _ = try self.expect(.colon);
                    if (std.mem.eql(u8, key, "governance_program")) {
                        gov_program = (try self.expect(.identifier)).text;
                    } else { _ = try self.parseExpr(); }
                    _ = self.matchAny(&.{.comma});
                }
                _ = try self.expect(.rbrace);
                dao_cfg = .{ .governance_program = gov_program,
                             .proposal_threshold = null, .quorum = null };
            }
        } else if (std.mem.eql(u8, holder_tok.text, "Program")) {
            _ = self.advance(); holder_type = .program;
        } else if (self.check(.kw_nobody)) {
            _ = self.advance(); holder_type = .nobody;
        } else {
            _ = self.advance(); holder_type = .wallet;
        }

        var initial_holder: ?*Expr = null;
        if (self.check(.kw_initially)) {
            _ = self.advance();
            initial_holder = try self.parseExpr();
        }
        var timelock: ?*Expr = null;
        if (self.check(.kw_with_timelock)) {
            _ = self.advance();
            timelock = try self.parseExpr();
        }
        var covers: std.ArrayListUnmanaged([]const u8) = .{};
        if (self.check(.kw_covers)) {
            _ = self.advance();
            _ = try self.expect(.lbracket);
            while (!self.check(.rbracket) and self.peekKind() != .eof) {
                try covers.append(self.allocator, (try self.expect(.identifier)).text);
                _ = self.matchAny(&.{.comma});
            }
            _ = try self.expect(.rbracket);
        }
        var inheritable    = false;
        var inherits_from: ?[]const u8 = null;
        if (self.check(.kw_inheritable))  { _ = self.advance(); inheritable = true; }
        if (self.check(.kw_inherits))     {
            _ = self.advance();
            inherits_from = (try self.expect(.identifier)).text;
        }

        return .{
            .name           = name, .kind = kind,
            .holder_type    = holder_type,
            .initial_holder = initial_holder,
            .timelock       = timelock,
            .multisig_cfg   = multisig_cfg,
            .dao_cfg        = dao_cfg,
            .covers         = try covers.toOwnedSlice(self.allocator),
            .inherits_from  = inherits_from,
            .inheritable    = inheritable,
            .span           = span,
        };
    }

    // ── has: / computed: / config: / always: blocks ─────────

    fn parseHasBlock(self: *Parser, parent_indent: u32) anyerror![]StateField {
        _ = try self.expect(.kw_has);
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        var list: std.ArrayListUnmanaged(StateField) = .{};
        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            var ns: ?[]const u8 = null;
            if (self.check(.kw_in)) {
                _ = self.advance();
                ns = (try self.expect(.identifier)).text;
                _ = try self.expect(.colon);
            }
            const span = self.peek().span;
            const name = (try self.expect(.identifier)).text;
            _ = try self.expect(.kw_is);
            const ty   = try self.parseType();
            try list.append(self.allocator, .{ .name = name, .type_ = ty, .namespace = ns, .span = span });
        }
        return list.toOwnedSlice(self.allocator);
    }

    fn parseComputedBlock(self: *Parser, parent_indent: u32) anyerror![]ComputedField {
        _ = try self.expect(.kw_computed);
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        var list: std.ArrayListUnmanaged(ComputedField) = .{};
        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            const span = self.peek().span;
            const name = (try self.expect(.identifier)).text;
            _ = try self.expect(.kw_is);
            const ty   = try self.parseType();
            _ = try self.expect(.equals_sign);
            const expr = try self.parseExpr();
            try list.append(self.allocator, .{ .name = name, .type_ = ty, .expr = expr, .span = span });
        }
        return list.toOwnedSlice(self.allocator);
    }

    fn parseConfigBlock(self: *Parser, parent_indent: u32) anyerror![]ConfigField {
        _ = try self.expect(.kw_config);
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        var list: std.ArrayListUnmanaged(ConfigField) = .{};
        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            const span = self.peek().span;
            const name = (try self.expect(.identifier)).text;
            _ = try self.expect(.kw_is);
            const ty   = try self.parseType();
            var def: ?*Expr = null;
            if (self.check(.equals_sign)) { _ = self.advance(); def = try self.parseExpr(); }
            try list.append(self.allocator, .{ .name = name, .type_ = ty, .default_val = def, .span = span });
        }
        return list.toOwnedSlice(self.allocator);
    }

    fn parseAlwaysBlock(self: *Parser, parent_indent: u32) anyerror![]ConstDecl {
        _ = try self.expect(.kw_always);
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        var list: std.ArrayListUnmanaged(ConstDecl) = .{};
        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            const span = self.peek().span;
            const name = (try self.expect(.identifier)).text;
            _ = try self.expect(.equals_sign);
            const val  = try self.parseExpr();
            try list.append(self.allocator, .{ .name = name, .type_ = null, .value = val, .span = span });
        }
        return list.toOwnedSlice(self.allocator);
    }

    // ── setup ─────────────────────────────────────────────────

    fn parseSetup(self: *Parser, parent_indent: u32) anyerror!SetupBlock {
        const span = self.peek().span;
        _ = try self.expect(.kw_setup);
        const params = try self.parseParamList();
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        const body = try self.parseBlock(block_indent);
        return .{ .params = params, .body = body, .span = span };
    }

    // ── guard ─────────────────────────────────────────────────

    fn parseGuard(self: *Parser, parent_indent: u32) anyerror!GuardDecl {
        const span = self.peek().span;
        _ = try self.expect(.kw_guard);
        const name   = (try self.expect(.identifier)).text;
        const params = try self.parseParamList();
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        const body = try self.parseBlock(block_indent);
        return .{ .name = name, .params = params, .body = body, .span = span };
    }

    // ── action / view / pure / helper ─────────────────────────

    fn parseFnHeader(self: *Parser, parent_indent: u32) anyerror!struct {
        span: Span, name: []const u8, vis: Visibility,
        tparams: []TypeParam, params: []Param, ret: ?TypeExpr,
        anns: []Annotation, accs: []AccountDecl, body: []Stmt,
    } {
        // Optional annotations before the keyword
        var anns: std.ArrayListUnmanaged(Annotation) = .{};
        while (self.check(.hash_sym)) {
            try anns.append(self.allocator, try self.parseAnnotation());
        }
        const span = self.peek().span;
        // Skip the keyword (action/view/pure/helper) — caller already consumed it
        var vis       = Visibility.shared;
        const vis_kinds = [_]TokenKind{ .kw_shared, .kw_within, .kw_hidden, .kw_outside, .kw_system };
        for (vis_kinds) |vk| {
            if (self.check(vk)) {
                _ = self.advance();
                vis = switch (vk) {
                    .kw_shared  => .shared,
                    .kw_within  => .within,
                    .kw_hidden  => .hidden,
                    .kw_outside => .outside,
                    .kw_system  => .system,
                    else        => .shared,
                };
                break;
            }
        }
        const name = (try self.expect(.identifier)).text;
        var tparams: std.ArrayListUnmanaged(TypeParam) = .{};
        if (self.check(.lbracket)) { tparams = try self.parseTypeParams(); }
        const params = try self.parseParamList();
        var ret: ?TypeExpr = null;
        if (self.check(.kw_gives)) { _ = self.advance(); ret = try self.parseType(); }
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        // Local accounts: block
        var accs: std.ArrayListUnmanaged(AccountDecl) = .{};
        if (!self.isBlockEnd(block_indent) and self.peekKind() == .kw_accounts) {
            accs = std.ArrayListUnmanaged(AccountDecl){
                .items = try self.parseAccountsBlock(block_indent),
                .capacity = 0,
            };
        }
        const body = try self.parseBlock(block_indent);
        return .{
            .span    = span, .name = name, .vis = vis,
            .tparams = try tparams.toOwnedSlice(self.allocator), .params = params,
            .ret     = ret, .anns = try anns.toOwnedSlice(self.allocator),
            .accs    = try accs.toOwnedSlice(self.allocator), .body = body,
        };
    }

    fn parseAction(self: *Parser, parent_indent: u32) anyerror!ActionDecl {
        var anns: std.ArrayListUnmanaged(Annotation) = .{};
        while (self.check(.hash_sym)) {
            try anns.append(self.allocator, try self.parseAnnotation());
        }
        const span = self.peek().span;
        _ = try self.expect(.kw_action);
        var vis = Visibility.shared;
        if (self.check(.kw_shared) or self.check(.kw_within) or self.check(.kw_hidden) or
            self.check(.kw_outside) or self.check(.kw_system)) {
            vis = self.parseVisibility();
        }
        const name   = (try self.expect(.identifier)).text;
        const params = try self.parseParamList();
        var ret: ?TypeExpr = null;
        if (self.check(.kw_gives)) { _ = self.advance(); ret = try self.parseType(); }
        var complexity_class: ?ComplexityClass = null;
        if (self.check(.kw_complexity)) {
            _ = self.advance();
            _ = try self.expect(.identifier); // 'O'
            _ = try self.expect(.lparen);
            if (self.check(.int_literal) and std.mem.eql(u8, self.peek().text, "1")) {
                _ = self.advance();
                complexity_class = .constant;
            } else if (self.check(.identifier) and std.mem.eql(u8, self.peek().text, "n")) {
                _ = self.advance();
                var bound: ?BoundExpr = null;
                if (self.check(.kw_where)) {
                    _ = self.advance();
                    _ = try self.expect(.identifier); // 'n'
                    _ = try self.expect(.lte);
                    const val = try self.expect(.int_literal);
                    bound = .{ .var_name = "n", .max_value = try std.fmt.parseInt(u64, val.text, 10) };
                }
                complexity_class = .{ .linear = bound };
            }
            _ = try self.expect(.rparen);
        }

        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        var accs: []AccountDecl = &.{};
        if (!self.isBlockEnd(block_indent) and self.peekKind() == .kw_accounts) {
            accs = try self.parseAccountsBlock(block_indent);
        }
        const body = try self.parseBlock(block_indent);
        return .{
            .name = name, .visibility = vis, .type_params = &.{},
            .params = params, .return_type = ret,
            .annotations = try anns.toOwnedSlice(self.allocator),
            .accounts = accs, .body = body,
            .complexity_class = complexity_class,
            .span = span,
        };
    }

    fn parseView(self: *Parser, parent_indent: u32) anyerror!ViewDecl {
        const span = self.peek().span;
        _ = try self.expect(.kw_view);
        var vis = Visibility.shared;
        if (self.check(.kw_shared) or self.check(.kw_within) or self.check(.kw_hidden)) {
            vis = self.parseVisibility();
        }
        const name   = (try self.expect(.identifier)).text;
        const params = try self.parseParamList();
        var ret: ?TypeExpr = null;
        if (self.check(.kw_gives)) { _ = self.advance(); ret = try self.parseType(); }
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        const body = try self.parseBlock(block_indent);
        return .{
            .name = name, .visibility = vis, .type_params = &.{},
            .params = params, .return_type = ret, .accounts = &.{},
            .body = body, .span = span,
        };
    }

    fn parsePure(self: *Parser, parent_indent: u32) anyerror!PureDecl {
        const span = self.peek().span;
        _ = try self.expect(.kw_pure);
        const name   = (try self.expect(.identifier)).text;
        const params = try self.parseParamList();
        var ret: ?TypeExpr = null;
        if (self.check(.kw_gives)) { _ = self.advance(); ret = try self.parseType(); }
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        const body = try self.parseBlock(block_indent);
        return .{ .name = name, .type_params = &.{}, .params = params, .return_type = ret, .body = body, .span = span };
    }

    fn parseHelper(self: *Parser, parent_indent: u32) anyerror!HelperDecl {
        const span = self.peek().span;
        _ = try self.expect(.kw_helper);
        const name   = (try self.expect(.identifier)).text;
        const params = try self.parseParamList();
        var ret: ?TypeExpr = null;
        if (self.check(.kw_gives)) { _ = self.advance(); ret = try self.parseType(); }
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        const body = try self.parseBlock(block_indent);
        return .{ .name = name, .params = params, .return_type = ret, .body = body, .span = span };
    }

    fn parseVisibility(self: *Parser) Visibility {
        return switch (self.advance().kind) {
            .kw_shared  => .shared,
            .kw_within  => .within,
            .kw_hidden  => .hidden,
            .kw_outside => .outside,
            .kw_system  => .system,
            else        => .shared,
        };
    }

    // ── event / error / invariant / upgrade ──────────────────

    fn parseEvent(self: *Parser) anyerror!EventDecl {
        const span = self.peek().span;
        _ = try self.expect(.kw_event);
        const name = (try self.expect(.identifier)).text;
        _ = try self.expect(.lparen);
        var fields: std.ArrayListUnmanaged(EventField) = .{};
        while (!self.check(.rparen) and self.peekKind() != .eof) {
            const fspan   = self.peek().span;
            const fname   = (try self.expect(.identifier)).text;
            _ = try self.expect(.kw_is);
            const ty      = try self.parseType();
            var indexed   = false;
            if (self.check(.kw_indexed)) { _ = self.advance(); indexed = true; }
            try fields.append(self.allocator, .{ .name = fname, .type_ = ty, .indexed = indexed, .span = fspan });
            _ = self.matchAny(&.{.comma});
        }
        _ = try self.expect(.rparen);
        return .{ .name = name, .fields = try fields.toOwnedSlice(self.allocator), .span = span };
    }

    fn parseError_(self: *Parser) anyerror!ErrorDecl {
        const span = self.peek().span;
        _ = try self.expect(.kw_error);
        const name = (try self.expect(.identifier)).text;
        var fields: std.ArrayListUnmanaged(ErrorField) = .{};
        // Parens are optional — `error Foo` is valid (no fields)
        if (self.check(.lparen)) {
            _ = self.advance();
            while (!self.check(.rparen) and self.peekKind() != .eof) {
                const fspan = self.peek().span;
                const fname = (try self.expect(.identifier)).text;
                _ = try self.expect(.kw_is);
                const ty    = try self.parseType();
                try fields.append(self.allocator, .{ .name = fname, .type_ = ty, .span = fspan });
                _ = self.matchAny(&.{.comma});
            }
            _ = try self.expect(.rparen);
        }
        return .{ .name = name, .fields = try fields.toOwnedSlice(self.allocator), .span = span };
    }

    fn parseInvariant(self: *Parser) anyerror!InvariantDecl {
        const span = self.peek().span;
        _ = try self.expect(.kw_invariant);
        const name = (try self.expect(.identifier)).text;
        _ = try self.expect(.colon);
        const cond = try self.parseExpr();
        return .{ .name = name, .cond = cond, .span = span };
    }

    /// SPEC: Novel Idea 1 — Economic Conservation Proofs.
    /// Parse a `conserves:` block containing one or more conservation equations.
    /// Syntax: `conserves:\n    [aggregator(]expr[)] op expr [at_all_times]`
    fn parseConservesBlock(self: *Parser, parent_indent: u32) anyerror![]ConservationExpr {
        _ = try self.expect(.kw_conserves);
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        var list: std.ArrayListUnmanaged(ConservationExpr) = .{};
        errdefer list.deinit(self.allocator);

        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;

            const span = self.peek().span;

            // Parse optional aggregator: sum(...), max_val(...), count(...)
            var aggregator: AggregatorKind = .identity;
            if (self.peekKind() == .kw_sum) {
                _ = self.advance();
                _ = try self.expect(.lparen);
                aggregator = .sum;
            } else if (self.peekKind() == .kw_max_val) {
                _ = self.advance();
                _ = try self.expect(.lparen);
                aggregator = .max_val;
            } else if (self.peekKind() == .kw_count_fn) {
                _ = self.advance();
                _ = try self.expect(.lparen);
                aggregator = .count;
            }

            // Parse LHS expression
            // Parse LHS expression — use parseAddSub to avoid consuming the comparison operator
            const lhs = try self.parseAddSub();

            // Close aggregator paren if present
            if (aggregator != .identity) {
                _ = try self.expect(.rparen);
            }

            // Parse comparison operator
            const op: ConservationOp = switch (self.peekKind()) {
                .kw_equals => blk: { _ = self.advance(); break :blk .equals; },
                .gte       => blk: { _ = self.advance(); break :blk .gte; },
                .lte       => blk: { _ = self.advance(); break :blk .lte; },
                .gt        => blk: { _ = self.advance(); break :blk .gt; },
                .lt        => blk: { _ = self.advance(); break :blk .lt; },
                else       => blk: {
                    const tok = self.peek();
                    try self.emitErr(tok.span, error.ExpectedToken,
                        "expected comparison operator in conserves equation, found '{s}'", .{tok.text});
                    break :blk .equals;
                },
            };

            // Parse RHS expression
            // Parse RHS expression — use parseAddSub to avoid consuming trailing modifiers
            const rhs = try self.parseAddSub();

            // Parse optional `at_all_times` modifier
            var at_all_times = false;
            if (self.peekKind() == .kw_at_all_times) {
                _ = self.advance();
                at_all_times = true;
            }

            try list.append(self.allocator, .{
                .aggregator = aggregator,
                .lhs = lhs,
                .op = op,
                .rhs = rhs,
                .at_all_times = at_all_times,
                .span = span,
            });
        }

        return list.toOwnedSlice(self.allocator);
    }

    fn parseUpgrade(self: *Parser, parent_indent: u32) anyerror!UpgradeBlock {
        const span = self.peek().span;
        _ = try self.expect(.kw_upgrade);
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        var authority:  []const u8 = "";
        var migrate_fn: ?[]const u8 = null;
        var version:    ?*Expr     = null;
        var imm_fields: std.ArrayListUnmanaged([]const u8) = .{};
        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            const key_tok = self.advance();
            const key = key_tok.text;
            _ = try self.expect(.colon);
            if (std.mem.eql(u8, key, "authority")) {
                authority  = (try self.expect(.identifier)).text;
            } else if (std.mem.eql(u8, key, "migrate")) {
                migrate_fn = (try self.expect(.identifier)).text;
            } else if (std.mem.eql(u8, key, "version")) {
                version    = try self.parseExpr();
            } else if (std.mem.eql(u8, key, "immutable_fields")) {
                // Parse comma-separated field names
                while (self.peekKind() == .identifier) {
                    try imm_fields.append(self.allocator, (try self.expect(.identifier)).text);
                    _ = self.matchAny(&.{.comma});
                }
            } else { _ = self.advance(); }
        }
        return .{
            .authority = authority,
            .migrate_fn = migrate_fn,
            .version = version,
            .immutable_fields = try imm_fields.toOwnedSlice(self.allocator),
            .span = span,
        };
    }

    fn parseAdversaryBlock(self: *Parser, parent_indent: u32) anyerror!AdversaryBlock {
        const span = self.peek().span;
        _ = try self.expect(.kw_adversary);
        _ = try self.expect(.kw_tries);
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        var attacks: std.ArrayListUnmanaged(AttackSpec) = .{};
        errdefer attacks.deinit(self.allocator);

        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            const attack = try self.parseAttackSpec(block_indent);
            try attacks.append(self.allocator, attack);
        }

        return .{
            .attacks = try attacks.toOwnedSlice(self.allocator),
            .span = span,
        };
    }

    fn parseAttackSpec(self: *Parser, parent_indent: u32) anyerror!AttackSpec {
        const span = self.peek().span;
        _ = try self.expect(.kw_attack);
        const name = (try self.expect(.identifier)).text;
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(parent_indent);
        var calls: std.ArrayListUnmanaged(AttackCall) = .{};
        errdefer calls.deinit(self.allocator);

        var outcome: AttackOutcome = .conservation_violated;

        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;

            if (self.check(.kw_expects)) {
                _ = self.advance();
                outcome = blk: switch (self.peekKind()) {
                    .kw_conservation_violated => { _ = self.advance(); break :blk .conservation_violated; },
                    .kw_action_blocked        => { _ = self.advance(); break :blk .action_blocked; },
                    .kw_invariant_broken      => { _ = self.advance(); break :blk .invariant_broken; },
                    else => {
                        const tok = self.peek();
                        try self.emitErr(tok.span, error.ExpectedToken, "expected attack outcome (conservation_violated, action_blocked, etc.), found '{s}'", .{tok.text});
                        break :blk .conservation_violated;
                    },
                };
            } else if (self.check(.kw_call)) {
                _ = self.advance();
                const call_name = (try self.expect(.identifier)).text;
                _ = try self.expect(.lparen);
                var args: std.ArrayListUnmanaged(Argument) = .{};
                while (!self.check(.rparen) and self.peekKind() != .eof) {
                    const a = try self.parseExpr();
                    try args.append(self.allocator, .{ .name = null, .value = a, .span = a.span });
                    _ = self.matchAny(&.{.comma});
                }
                _ = try self.expect(.rparen);
                try calls.append(self.allocator, .{
                    .action_name = call_name,
                    .args = try args.toOwnedSlice(self.allocator),
                    .span = span,
                });
            } else {
                _ = self.advance(); // skip unknown
            }
        }

        return .{
            .name = name,
            .calls = try calls.toOwnedSlice(self.allocator),
            .expected_outcome = outcome,
            .span = span,
        };
    }

    // ── Annotation: #[kind args...] ───────────────────────────

    fn parseAnnotation(self: *Parser) anyerror!Annotation {
        const span = self.peek().span;
        _ = try self.expect(.hash_sym);
        _ = try self.expect(.lbracket);
        const kind_tok = self.peek();
        const kind: AnnotationKind = if (kind_tok.kind == .kw_parallel) blk: {
            _ = self.advance(); break :blk .parallel;
        } else if (kind_tok.kind == .kw_zk_proof) blk: {
            _ = self.advance(); break :blk .zk_proof;
        } else if (kind_tok.kind == .kw_private) blk: {
            _ = self.advance(); break :blk .private;
        } else blk: {
            const text = (try self.expect(.identifier)).text;
            break :blk if (std.mem.eql(u8, text, "reads"))             .reads
              else if (std.mem.eql(u8, text, "writes"))                 .writes
              else if (std.mem.eql(u8, text, "max_iterations"))         .max_iterations
              else if (std.mem.eql(u8, text, "gas_check"))              .gas_check
              else if (std.mem.eql(u8, text, "gas_sponsored_for"))      .gas_sponsored_for
              else .parallel;
        };
        var args: std.ArrayListUnmanaged(*Expr) = .{};
        while (!self.check(.rbracket) and self.peekKind() != .eof) {
            try args.append(self.allocator, try self.parseExpr());
            _ = self.matchAny(&.{.comma});
        }
        _ = try self.expect(.rbracket);
        return .{ .kind = kind, .args = try args.toOwnedSlice(self.allocator), .span = span };
    }

    // =========================================================
    // TYPE PARSER
    // =========================================================

    fn parseType(self: *Parser) anyerror!TypeExpr {
        // maybe Type
        if (self.check(.kw_maybe)) {
            _ = self.advance();
            const inner = try self.parseType();
            const ptr   = try self.alloc(inner);
            return .{ .maybe = ptr };
        }
        // Result[T, E]
        if (self.check(.kw_result_type)) {
            _ = self.advance();
            _ = try self.expect(.lbracket);
            const ok_ty  = try self.parseType();
            _ = try self.expect(.comma);
            const err_ty = try self.parseType();
            _ = try self.expect(.rbracket);
            return .{ .result = .{
                .ok  = try self.alloc(ok_ty),
                .err = try self.alloc(err_ty),
            }};
        }
        // Collection types
        if (self.check(.kw_map) or self.check(.kw_enum_map)) {
            const is_enum = self.peekKind() == .kw_enum_map;
            _ = self.advance();
            _ = try self.expect(.lbracket);
            const k_ty = try self.parseType();
            _ = try self.expect(.arrow);
            const v_ty = try self.parseType();
            _ = try self.expect(.rbracket);
            if (is_enum) {
                return .{ .enum_map = .{ .key = try self.alloc(k_ty), .value = try self.alloc(v_ty) } };
            }
            return .{ .map = .{ .key = try self.alloc(k_ty), .value = try self.alloc(v_ty) } };
        }
        if (self.check(.kw_list)) {
            _ = self.advance();
            _ = try self.expect(.lbracket);
            const inner = try self.parseType();
            _ = try self.expect(.rbracket);
            return .{ .list = try self.alloc(inner) };
        }
        if (self.check(.kw_set)) {
            _ = self.advance();
            _ = try self.expect(.lbracket);
            const inner = try self.parseType();
            _ = try self.expect(.rbracket);
            return .{ .set = try self.alloc(inner) };
        }
        if (self.check(.kw_array)) {
            _ = self.advance();
            _ = try self.expect(.lbracket);
            const inner = try self.parseType();
            _ = try self.expect(.comma);
            const size_tok = try self.expect(.int_literal);
            const size = std.fmt.parseInt(u32, size_tok.text, 10) catch 0;
            _ = try self.expect(.rbracket);
            return .{ .array = .{ .elem = try self.alloc(inner), .size = size } };
        }
        // Fixed[N]
        if (self.check(.kw_fixed)) {
            _ = self.advance();
            _ = try self.expect(.lbracket);
            const n = try self.expect(.int_literal);
            _ = try self.expect(.rbracket);
            return .{ .fixed = .{ .decimals = @intCast(std.fmt.parseInt(u8, n.text, 10) catch 9) } };
        }
        return self.parsePrimitiveType();
    }

    fn parsePrimitiveType(self: *Parser) anyerror!TypeExpr {
        const tok = self.peek();
        const ty: TypeExpr = switch (tok.kind) {
            .kw_u8          => .u8,   .kw_u16   => .u16, .kw_u32  => .u32,
            .kw_u64         => .u64,  .kw_u128  => .u128,.kw_u256 => .u256,
            .kw_uint        => .uint,
            .kw_i8          => .i8,   .kw_i16   => .i16, .kw_i32  => .i32,
            .kw_i64         => .i64,  .kw_i128  => .i128,.kw_i256 => .i256,
            .kw_int         => .int,
            .kw_bool        => .bool,
            .kw_account_type => .account,.kw_wallet_type => .wallet,
            .kw_program_type => .program,.kw_system_acc  => .system_acc,
            .kw_hash_type   => .hash,  .kw_hash20 => .hash20,
            .kw_commitment  => .commitment,
            .kw_byte_type   => .byte,  .kw_bytes_type => .bytes,
            .kw_bytes32     => .bytes32,.kw_bytes64 => .bytes64,
            .kw_signature   => .signature,.kw_pubkey => .pubkey,
            .kw_string_type => .string,
            .kw_short_str   => .short_str,
            .kw_label       => .label,
            .kw_timestamp   => .timestamp,.kw_duration => .duration,
            .kw_block_number => .block_number,
            .kw_epoch       => .epoch,.kw_slot => .slot,
            .kw_price9      => .price9,.kw_price18 => .price18,
            .kw_percent     => .percent,
            // Named type (could be generic)
            .identifier => {
                const name = tok.text;
                _ = self.advance();
                if (self.check(.lbracket)) {
                    _ = self.advance();
                    var args: std.ArrayListUnmanaged(*TypeExpr) = .{};
                    while (!self.check(.rbracket) and self.peekKind() != .eof) {
                        const pt = try self.parseType();
                        const pp = try self.allocator.create(TypeExpr);
                        pp.* = pt;
                        try args.append(self.allocator, pp);
                        _ = self.matchAny(&.{.comma});
                    }
                    _ = try self.expect(.rbracket);
                    return .{ .generic = .{
                        .name   = name,
                        .params = try args.toOwnedSlice(self.allocator),
                    }};
                }
                return .{ .named = name };
            },
            else => {
                const t = self.advance();
                try self.emitErr(t.span, error.UnexpectedToken,
                    "expected type, found '{s}'", .{t.text});
                return .u64; // error recovery fallback
            },
        };
        _ = self.advance();
        return ty;
    }

    // =========================================================
    // STATEMENT PARSE RULES
    // =========================================================

    /// Parse an indented statement block. `block_indent` is the column of
    /// the first statement, established by `expectIndentIncrease`.
    fn parseBlock(self: *Parser, block_indent: u32) anyerror![]Stmt {
        var list: std.ArrayListUnmanaged(Stmt) = .{};
        errdefer list.deinit(self.allocator);
        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            // Enforce: statement must be precisely at block_indent.
            const ind = self.currentIndent();
            if (ind < block_indent) break;
            if (ind > block_indent) {
                const tok = self.peek();
                try self.emitErr(tok.span, error.UnexpectedToken,
                    "unexpected indent {} (expected {})", .{ ind, block_indent });
                _ = self.advance();
                continue;
            }
            if (try self.parseStmt()) |stmt| {
                try list.append(self.allocator, stmt);
            }
        }
        return list.toOwnedSlice(self.allocator);
    }

    fn parseStmt(self: *Parser) anyerror!?Stmt {
        self.skipTrivia();
        return switch (self.peekKind()) {
            .kw_let       => try self.parseLet(),
            .kw_when      => try self.parseWhen(),
            .kw_match     => try self.parseMatch(),
            .kw_each      => try self.parseEach(),
            .kw_repeat    => try self.parseRepeat(),
            .kw_while     => try self.parseWhile(),
            .kw_need      => try self.parseNeed(),
            .kw_ensure    => try self.parseEnsure(),
            .kw_tell      => try self.parseTell(),
            .kw_throw     => try self.parseThrow(),
            .kw_give      => try self.parseGiveBack(),
            .kw_stop      => blk: {
                const span = self.advance().span;
                break :blk .{ .kind = .stop, .span = span };
            },
            .kw_skip      => blk: {
                const span = self.advance().span;
                break :blk .{ .kind = .skip, .span = span };
            },
            .kw_panic     => blk: {
                const span = self.advance().span;
                const msg: []const u8 = if (self.check(.string_literal)) self.advance().text else "panic";
                break :blk .{ .kind = .{ .panic = .{ .message = msg } }, .span = span };
            },
            .kw_attempt   => try self.parseAttempt(),
            .kw_only      => try self.parseOnlyStmt(),
            .kw_remove    => try self.parseRemove(),
            .kw_close     => try self.parseClose(),
            .kw_freeze    => try self.parseFreeze(),
            .kw_unfreeze  => try self.parseUnfreeze(),
            .kw_expand    => try self.parseExpand(),
            .kw_pay       => try self.parsePay(),
            .kw_send      => try self.parseSend(),
            .kw_move      => try self.parseMoveAsset(),
            .kw_transfer_ownership => try self.parseTransferOwnership(),
            .kw_schedule  => try self.parseSchedule(),
            .kw_verify    => try self.parseVerify(),
            .eof          => null,
            else          => try self.parseAssignOrCall(),
        };
    }

    fn parseLet(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_let);
        const name  = (try self.expect(.identifier)).text;
        var declared_type: ?TypeExpr = null;
        if (self.check(.kw_is)) {
            _ = self.advance();
            declared_type = try self.parseType();
        }
        _ = try self.expect(.equals_sign);
        const val = try self.parseExpr();
        return .{ .kind = .{ .let_bind = .{
            .name = name, .declared_type = declared_type, .init = val, .mutable = true, .span = span,
        }}, .span = span };
    }

    fn parseWhen(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_when);
        const cond = try self.parseExpr();
        _ = try self.expect(.colon);
        const then_indent = try self.expectIndentIncrease(span.col - 1);
        const then_body   = try self.parseBlock(then_indent);

        var elseifs: std.ArrayListUnmanaged(ElseIf) = .{};
        var else_body: ?[]Stmt = null;

        while (self.peekKind() == .kw_otherwise or self.peekKind() == .kw_else) {
            const kw = self.advance();
            if (kw.kind == .kw_otherwise and self.check(.kw_when)) {
                _ = self.advance(); // consume `when`
                const ei_cond = try self.parseExpr();
                _ = try self.expect(.colon);
                const ei_indent = try self.expectIndentIncrease(kw.span.col - 1);
                const ei_body   = try self.parseBlock(ei_indent);
                try elseifs.append(self.allocator, .{ .cond = ei_cond, .body = ei_body, .span = kw.span });
            } else {
                _ = try self.expect(.colon);
                const el_indent = try self.expectIndentIncrease(kw.span.col - 1);
                else_body = try self.parseBlock(el_indent);
                break;
            }
        }

        return .{ .kind = .{ .when = .{
            .cond      = cond,
            .then_body = then_body,
            .else_ifs  = try elseifs.toOwnedSlice(self.allocator),
            .else_body = else_body,
        } }, .span = span };
    }

    fn parseMatch(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_match);
        const subject  = try self.parseExpr();
        _ = try self.expect(.colon);
        const block_indent = try self.expectIndentIncrease(span.col - 1);

        var arms: std.ArrayListUnmanaged(MatchArm) = .{};
        while (!self.isBlockEnd(block_indent)) {
            self.skipTrivia();
            if (self.isBlockEnd(block_indent)) break;
            const arm_span = self.peek().span;
            const pat      = try self.parsePattern();
            _ = try self.expect(.fat_arrow);
            var arm_body: []Stmt = &.{};
            if (self.check(.colon)) {
                _ = self.advance();
                const arm_indent = try self.expectIndentIncrease(arm_span.col - 1);
                arm_body = try self.parseBlock(arm_indent);
            } else {
                const e = try self.parseExpr();
                const es = Stmt{ .kind = .{ .call_stmt = e }, .span = e.span };
                const ptr = try self.allocator.alloc(Stmt, 1);
                ptr[0] = es;
                arm_body = ptr;
            }
            try arms.append(self.allocator, .{ .pattern = pat, .body = arm_body, .span = arm_span });
        }

        return .{ .kind = .{ .match = .{
            .subject = subject,
            .arms    = try arms.toOwnedSlice(self.allocator),
        }}, .span = span };
    }

    fn parseEach(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_each);
        const item  = (try self.expect(.identifier)).text;
        var key: ?[]const u8 = null;
        if (self.check(.comma)) {
            _ = self.advance();
            key = item;
            _ = (try self.expect(.identifier)).text;
        }
        _ = try self.expect(.kw_in);
        const iter = try self.parseExpr();
        _ = try self.expect(.colon);
        const bind: EachBinding = if (key) |k| .{ .pair = .{ .first = k, .second = item } } else .{ .single = item };
        const body_indent = try self.expectIndentIncrease(span.col - 1);
        const body = try self.parseBlock(body_indent);
        return .{ .kind = .{ .each = .{ .binding = bind, .collection = iter, .max_iters = null, .body = body } }, .span = span };
    }

    fn parseRepeat(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_repeat);
        const count = try self.parseExpr();
        _ = try self.expect(.kw_times);
        _ = try self.expect(.colon);
        const body_indent = try self.expectIndentIncrease(span.col - 1);
        const body = try self.parseBlock(body_indent);
        return .{ .kind = .{ .repeat = .{ .count = count, .max_iters = null, .body = body } }, .span = span };
    }

    fn parseWhile(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_while);
        const cond = try self.parseExpr();
        _ = try self.expect(.colon);
        const body_indent = try self.expectIndentIncrease(span.col - 1);
        const body = try self.parseBlock(body_indent);
        return .{ .kind = .{ .while_ = .{ .cond = cond, .max_iters = null, .body = body } }, .span = span };
    }

    fn parseNeed(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_need);
        const cond = try self.parseExpr();
        var else_clause: NeedElse = .{ .string_msg = "" };
        if (self.check(.kw_else)) {
            _ = self.advance();
            if (self.check(.string_literal)) {
                else_clause = .{ .string_msg = self.advance().text };
            } else {
                const ename = (try self.expect(.identifier)).text;
                else_clause = .{ .typed_error = .{ .error_type = ename, .args = &.{}, .span = span } };
            }
        }
        return .{ .kind = .{ .need = .{ .cond = cond, .else_ = else_clause, .span = span } }, .span = span };
    }

    fn parseEnsure(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_ensure);
        const cond = try self.parseExpr();
        var else_clause: NeedElse = .{ .string_msg = "" };
        if (self.check(.kw_else)) {
            _ = self.advance();
            if (self.check(.string_literal)) {
                else_clause = .{ .string_msg = self.advance().text };
            } else {
                const ename = (try self.expect(.identifier)).text;
                else_clause = .{ .typed_error = .{ .error_type = ename, .args = &.{}, .span = span } };
            }
        }
        return .{ .kind = .{ .ensure = .{ .cond = cond, .else_ = else_clause, .span = span } }, .span = span };
    }

    fn parseTell(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_tell);
        const name = (try self.expect(.identifier)).text;
        _ = try self.expect(.lparen);
        var args: std.ArrayListUnmanaged(Argument) = .{};
        while (!self.check(.rparen) and self.peekKind() != .eof) {
            const a = try self.parseExpr();
            try args.append(self.allocator, .{ .name = null, .value = a, .span = a.span });
            _ = self.matchAny(&.{.comma});
        }
        _ = try self.expect(.rparen);
        return .{ .kind = .{ .tell = .{ .event_name = name, .args = try args.toOwnedSlice(self.allocator), .span = span } }, .span = span };
    }

    fn parseThrow(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_throw);
        const name = (try self.expect(.identifier)).text;
        _ = try self.expect(.lparen);
        var args: std.ArrayListUnmanaged(Argument) = .{};
        while (!self.check(.rparen) and self.peekKind() != .eof) {
            { const a = try self.parseExpr(); try args.append(self.allocator, .{ .name = null, .value = a, .span = a.span }); }
            _ = self.matchAny(&.{.comma});
        }
        _ = try self.expect(.rparen);
        return .{ .kind = .{ .throw = .{ .error_call = .{ .error_type = name, .args = try args.toOwnedSlice(self.allocator), .span = span } } }, .span = span };
    }

    fn parseGiveBack(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_give);
        _ = try self.expect(.kw_back);
        var val: ?*Expr = null;
        if (self.peekKind() != .eof and !self.isBlockEnd(self.currentIndent())) {
            val = try self.parseExpr();
        }
        {
            const gv = val orelse try self.makeExprNode(.nothing, span);
            return .{ .kind = .{ .give_back = gv }, .span = span };
        }
    }

    fn parseAttempt(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_attempt);
        _ = try self.expect(.colon);
        const try_indent = try self.expectIndentIncrease(span.col - 1);
        const try_body   = try self.parseBlock(try_indent);
        var on_errors: std.ArrayListUnmanaged(OnErrorClause) = .{};
        while (self.peekKind() == .kw_on_error) {
            _ = self.advance();
            var etype: ?[]const u8 = null;
            if (self.check(.identifier)) etype = self.advance().text;
            _ = try self.expect(.colon);
            const err_indent = try self.expectIndentIncrease(span.col - 1);
            const err_body   = try self.parseBlock(err_indent);
            try on_errors.append(self.allocator, .{
                .error_type = etype, .bindings = &.{}, .body = err_body, .span = span,
            });
        }
        return .{ .kind = .{ .attempt = .{ .body = try_body, .on_error = try on_errors.toOwnedSlice(self.allocator), .always_body = null } }, .span = span };
    }

    fn parseOnlyStmt(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_only);
        // Parse the single requirement before the colon
        const req: OnlyRequirement = blk: {
            if (self.check(.lbracket)) {
                _ = self.advance();
                var addrs: std.ArrayListUnmanaged([]const u8) = .{};
                while (!self.check(.rbracket) and self.peekKind() != .eof) {
                    try addrs.append(self.allocator, (try self.expect(.identifier)).text);
                    _ = self.matchAny(&.{.comma});
                }
                _ = try self.expect(.rbracket);
                break :blk .{ .address_list = try addrs.toOwnedSlice(self.allocator) };
            }
            const name = (try self.expect(.identifier)).text;
            // authority or auth1 or auth2
            if (self.check(.kw_or)) {
                _ = self.advance();
                const name2 = (try self.expect(.identifier)).text;
                break :blk .{ .either = .{ .left = name, .right = name2 } };
            }
            break :blk .{ .authority = name };
        };
        _ = try self.expect(.colon);
        const body_indent = try self.expectIndentIncrease(span.col - 1);
        // OnlyStmt in ast.zig stores only requirement+span; the body is parsed
        // but used as guard context — discard via underscore assignment.
        const only_body = try self.parseBlock(body_indent);
        return .{ .kind = .{ .only = .{ .requirement = req, .body = only_body, .span = span } }, .span = span };
    }

    fn parseRemove(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_remove);
        const target = try self.parseExpr();
        return .{ .kind = .{ .remove = target }, .span = span };
    }
    fn parseClose(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_close);
        const account = try self.parseExpr();
        _ = try self.expect(.kw_to);
        const dest = try self.parseExpr();
        return .{ .kind = .{ .close = .{ .account = account, .refund_to = dest } }, .span = span };
    }
    fn parseFreeze(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_freeze);
        const account = try self.parseExpr();
        return .{ .kind = .{ .freeze = .{ .account = account } }, .span = span };
    }
    fn parseUnfreeze(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_unfreeze);
        const account = try self.parseExpr();
        return .{ .kind = .{ .unfreeze = .{ .account = account } }, .span = span };
    }
    fn parseExpand(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_expand);
        const account = try self.parseExpr();
        _ = try self.expect(.kw_by);
        const bytes   = try self.parseExpr();
        return .{ .kind = .{ .expand = .{ .account = account, .bytes = bytes } }, .span = span };
    }
    fn parsePay(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_pay);
        const amount = try self.parseExpr();
        _ = try self.expect(.kw_to);
        const dest   = try self.parseExpr();
        return .{ .kind = .{ .pay = .{ .recipient = dest, .amount = amount } }, .span = span };
    }
    fn parseSend(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_send);
        const amount = try self.parseExpr();
        _ = try self.expect(.kw_to);
        const dest   = try self.parseExpr();
        return .{ .kind = .{ .send = .{ .asset = amount, .recipient = dest } }, .span = span };
    }
    fn parseMoveAsset(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_move);
        const asset = try self.parseExpr();
        _ = try self.expect(.kw_to);
        const dest  = try self.parseExpr();
        return .{ .kind = .{ .move_asset = .{ .asset = asset, .dest = dest } }, .span = span };
    }
    fn parseTransferOwnership(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_transfer_ownership);
        _ = try self.expect(.kw_to);
        const new_owner = try self.parseExpr();
        return .{ .kind = .{ .transfer_ownership = .{ .account = new_owner, .new_owner = new_owner, .span = span } }, .span = span };
    }
    
    fn parseVerify(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_verify);
        const proof = try self.parseExpr();
        _ = try self.expect(.kw_against);
        const commitment = try self.parseExpr();
        return .{ .kind = .{ .verify = .{ .proof = proof, .commitment = commitment, .span = span } }, .span = span };
    }

    fn parseSchedule(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        _ = try self.expect(.kw_schedule);
        const program  = try self.parseExpr();
        _ = try self.expect(.dot);
        _ = (try self.expect(.identifier)).text; // action name
        const args = try self.parseCallArgs();
        _ = args;
        var delay: *Expr = program; // default: schedule immediately
        if (self.check(.kw_in)) {
            _ = self.advance();
            delay = try self.parseExpr();
        }
        return .{ .kind = .{ .schedule = .{ .call = program, .after = delay, .span = span } }, .span = span };
    }

    /// `mine.field = expr` | `mine.field += expr` | `foo(args)`
    fn parseAssignOrCall(self: *Parser) anyerror!Stmt {
        const span = self.peek().span;
        const lhs  = try self.parseExpr();
        // Augmented assignment: += -= *=
        const aug_ops = [_]TokenKind{ .plus_eq, .minus_eq, .times_eq };
        for (aug_ops) |op| {
            if (self.check(op)) {
                _ = self.advance();
                const rhs   = try self.parseExpr();
                const aug_op: AugOp = switch (op) {
                    .plus_eq  => .add,
                    .minus_eq => .sub,
                    .times_eq => .mul,
                    else      => .add,
                };
                return .{ .kind = .{ .aug_assign = .{ .target = lhs, .op = aug_op, .value = rhs } }, .span = span };
            }
        }
        // Plain assignment
        if (self.check(.equals_sign)) {
            _ = self.advance();
            const rhs = try self.parseExpr();
            return .{ .kind = .{ .assign = .{ .target = lhs, .value = rhs } }, .span = span };
        }
        // Expression statement (e.g. a bare function call)
        return .{ .kind = .{ .call_stmt = lhs }, .span = span };
    }

    fn parseCallArgs(self: *Parser) anyerror![]*Expr {
        var args: std.ArrayListUnmanaged(*Expr) = .{};
        if (!self.check(.lparen)) return args.toOwnedSlice(self.allocator);
        _ = self.advance();
        while (!self.check(.rparen) and self.peekKind() != .eof) {
            try args.append(self.allocator, try self.parseExpr());
            _ = self.matchAny(&.{.comma});
        }
        _ = try self.expect(.rparen);
        return args.toOwnedSlice(self.allocator);
    }

    // =========================================================
    // EXPRESSION PARSER  (Pratt / recursive descent chain)
    // =========================================================

    pub fn parseExpr(self: *Parser) anyerror!*Expr { return self.parseOr(); }

    fn parseOr(self: *Parser) anyerror!*Expr {
        var lhs = try self.parseAnd();
        while (self.check(.kw_or)) {
            const span = self.advance().span;
            const rhs  = try self.parseAnd();
            lhs = try self.makeExprNode(.{ .bin_op = .{ .op = .or_, .left = lhs, .right = rhs } }, span);
        }
        return lhs;
    }

    fn parseAnd(self: *Parser) anyerror!*Expr {
        var lhs = try self.parseComparison();
        while (self.check(.kw_and)) {
            const span = self.advance().span;
            const rhs  = try self.parseComparison();
            lhs = try self.makeExprNode(.{ .bin_op = .{ .op = .and_, .left = lhs, .right = rhs } }, span);
        }
        return lhs;
    }

    fn parseComparison(self: *Parser) anyerror!*Expr {
        var lhs = try self.parseAddSub();
        while (true) {
            const span = self.peek().span;
            const op: ?BinOp = switch (self.peekKind()) {
                .kw_equals => blk: { _ = self.advance(); break :blk .equals;  },
                .gt        => blk: { _ = self.advance(); break :blk .greater;  },
                .lt        => blk: { _ = self.advance(); break :blk .less;  },
                .gte       => blk: { _ = self.advance(); break :blk .greater_eq; },
                .lte       => blk: { _ = self.advance(); break :blk .less_eq; },
                .kw_is     => blk: {
                    _ = self.advance();
                    if (self.check(.kw_not)) { _ = self.advance(); break :blk .not_equals; }
                    break :blk .equals;
                },
                else => null,
            };
            if (op == null) break;
            const rhs = try self.parseAddSub();
            lhs = try self.makeExprNode(.{ .bin_op = .{ .op = op.?, .left = lhs, .right = rhs } }, span);
        }
        return lhs;
    }

    fn parseAddSub(self: *Parser) anyerror!*Expr {
        var lhs = try self.parseMulDiv();
        while (true) {
            const span = self.peek().span;
            const op: ?BinOp = switch (self.peekKind()) {
                .kw_plus  => blk: { _ = self.advance(); break :blk .plus; },
                .kw_minus => blk: { _ = self.advance(); break :blk .minus; },
                else      => null,
            };
            if (op == null) break;
            const rhs = try self.parseMulDiv();
            lhs = try self.makeExprNode(.{ .bin_op = .{ .op = op.?, .left = lhs, .right = rhs } }, span);
        }
        return lhs;
    }

    fn parseMulDiv(self: *Parser) anyerror!*Expr {
        var lhs = try self.parseUnary();
        while (true) {
            const span = self.peek().span;
            const op: ?BinOp = switch (self.peekKind()) {
                .kw_times_op => blk: { _ = self.advance(); break :blk .times;  },
                .slash       => blk: { _ = self.advance(); break :blk .divided_by;  },
                .kw_divided  => blk: {
                    _ = self.advance();
                    _ = self.matchAny(&.{.kw_by});
                    break :blk .divided_by;
                },
                .kw_mod      => blk: { _ = self.advance(); break :blk .mod; },
                else         => null,
            };
            if (op == null) break;
            const rhs = try self.parseUnary();
            lhs = try self.makeExprNode(.{ .bin_op = .{ .op = op.?, .left = lhs, .right = rhs } }, span);
        }
        return lhs;
    }

    fn parseUnary(self: *Parser) anyerror!*Expr {
        const span = self.peek().span;
        if (self.check(.kw_not)) {
            _ = self.advance();
            const operand = try self.parseUnary();
            return self.makeExprNode(.{ .unary_op = .{ .op = .not_, .operand = operand } }, span);
        }
        if (self.check(.kw_minus)) {
            _ = self.advance();
            const operand = try self.parseUnary();
            return self.makeExprNode(.{ .unary_op = .{ .op = .negate, .operand = operand } }, span);
        }
        return self.parsePostfix();
    }

    fn parsePostfix(self: *Parser) anyerror!*Expr {
        var base = try self.parsePrimary();
        while (true) {
            if (self.check(.dot)) {
                const span  = self.advance().span;
                const field = (try self.expect(.identifier)).text;
                base = try self.makeExprNode(.{ .field_access = .{ .object = base, .field = field } }, span);
            } else if (self.check(.double_colon)) {
                const span = self.advance().span;
                const name = (try self.expect(.identifier)).text;
                base = try self.makeExprNode(.{ .field_access = .{ .object = base, .field = name } }, span);
            } else if (self.check(.lbracket)) {
                const span = self.advance().span;
                const idx  = try self.parseExpr();
                _ = try self.expect(.rbracket);
                base = try self.makeExprNode(.{ .index_access = .{ .object = base, .index = idx } }, span);
            } else if (self.check(.lparen)) {
                const span = self.peek().span;
                _ = self.advance();
                var args: std.ArrayListUnmanaged(Argument) = .{};
                while (!self.check(.rparen) and self.peekKind() != .eof) {
                    var label: ?[]const u8 = null;
                    if (self.check(.identifier) and self.peekAt(1).kind == .colon) {
                        label = self.advance().text;
                        _ = self.advance();
                    }
                    const val = try self.parseExpr();
                    try args.append(self.allocator, .{ .name = label, .value = val, .span = span });
                    _ = self.matchAny(&.{.comma});
                }
                _ = try self.expect(.rparen);
                base = try self.makeExprNode(.{ .call = .{
                    .callee = base,
                    .args   = try args.toOwnedSlice(self.allocator),
                    }}, span);
            } else if (self.check(.question)) {
                const span = self.advance().span;
                base = try self.makeExprNode(.{ .try_propagate = base }, span);
            } else if (self.check(.kw_as)) {
                const span = self.advance().span;
                const ty   = try self.parseType();
                base = try self.makeExprNode(.{ .cast = .{ .expr = base, .to = ty } }, span);
            } else {
                break;
            }
        }
        return base;
    }

    fn parsePrimary(self: *Parser) anyerror!*Expr {
        const tok  = self.peek();
        const span = tok.span;
        switch (tok.kind) {
            .int_literal    => { _ = self.advance(); return self.makeExprNode(.{ .int_lit    = tok.text }, span); },
            .float_literal  => { _ = self.advance(); return self.makeExprNode(.{ .float_lit  = tok.text }, span); },
            .string_literal => { _ = self.advance(); return self.makeExprNode(.{ .string_lit = tok.text }, span); },
            .hex_literal    => { _ = self.advance(); return self.makeExprNode(.{ .int_lit = tok.text }, span); },
            .kw_yes         => { _ = self.advance(); return self.makeExprNode(.{ .bool_lit   = true    }, span); },
            .kw_no          => { _ = self.advance(); return self.makeExprNode(.{ .bool_lit   = false   }, span); },
            .kw_nothing     => { _ = self.advance(); return self.makeExprNode(.nothing,                   span); },
            .kw_caller        => { _ = self.advance(); return self.makeExprNode(.{ .builtin = .caller        }, span); },
            .kw_deployer      => { _ = self.advance(); return self.makeExprNode(.{ .builtin = .deployer      }, span); },
            .kw_value_kw      => { _ = self.advance(); return self.makeExprNode(.{ .builtin = .value         }, span); },
            .kw_now           => { _ = self.advance(); return self.makeExprNode(.{ .builtin = .now           }, span); },
            .kw_current_block => { _ = self.advance(); return self.makeExprNode(.{ .builtin = .current_block }, span); },
            .kw_gas_remaining => { _ = self.advance(); return self.makeExprNode(.{ .builtin = .gas_remaining }, span); },
            .kw_something => {
                _ = self.advance();
                _ = try self.expect(.lparen);
                const inner = try self.parseExpr();
                _ = try self.expect(.rparen);
                return self.makeExprNode(.{ .something = inner }, span);
            },
            .lparen => {
                _ = self.advance();
                const inner = try self.parseExpr();
                _ = try self.expect(.rparen);
                return inner;
            },
            .identifier, .kw_mine, .kw_this, .kw_oracle, .kw_vrf_random, .kw_zk_proof, .kw_private => {
                _ = self.advance();
                return self.makeExprNode(.{ .identifier = tok.text }, span);
            },
            .kw_ok => {
                _ = self.advance();
                _ = try self.expect(.lparen);
                const inner = try self.parseExpr();
                _ = try self.expect(.rparen);
                var ok_args = try self.allocator.alloc(Argument, 1);
                ok_args[0] = .{ .name = null, .value = inner, .span = inner.span };
                return self.makeExprNode(.{ .call = .{ .callee = try self.makeExprNode(.{ .identifier = "ok" }, span), .args = ok_args } }, span);
            },
            .kw_fail => {
                _ = self.advance();
                if (self.check(.lparen)) {
                    _ = self.advance();
                    const inner = try self.parseExpr();
                    _ = try self.expect(.rparen);
                    var fail_args = try self.allocator.alloc(Argument, 1);
                    fail_args[0] = .{ .name = null, .value = inner, .span = inner.span };
                    return self.makeExprNode(.{ .call = .{ .callee = try self.makeExprNode(.{ .identifier = "fail" }, span), .args = fail_args } }, span);
                }
                return self.makeExprNode(.{ .identifier = "fail" }, span);
            },
            else => {
                const t = self.advance();
                try self.emitErr(t.span, error.UnexpectedToken,
                    "unexpected token in expression", .{});
                return self.makeExprNode(.{ .identifier = t.text }, t.span);
            },
        }
    }

    fn makeExprNode(self: *Parser, kind: ExprKind, span: Span) anyerror!*Expr {
        const node = try self.allocator.create(Expr);
        node.* = .{ .kind = kind, .span = span };
        return node;
    }

    // =========================================================
    // PATTERN PARSER  (for match arms)
    // =========================================================

    pub fn parsePattern(self: *Parser) anyerror!Pattern {
        const _span = self.peek().span;
        _ = _span;
        switch (self.peekKind()) {
            .identifier => {
                const name = self.advance().text;
                if (std.mem.eql(u8, name, "_")) return .wildcard;
                if (self.check(.lparen)) {
                    _ = self.advance();
                    var bindings: std.ArrayListUnmanaged(FieldBinding) = .{};
                    while (!self.check(.rparen) and self.peekKind() != .eof) {
                        const fn_ = (try self.expect(.identifier)).text;
                        _ = try self.expect(.colon);
                        const binding = (try self.expect(.identifier)).text;
                        try bindings.append(self.allocator, .{ .field = fn_, .binding = binding });
                        _ = self.matchAny(&.{.comma});
                    }
                    _ = try self.expect(.rparen);
                    return Pattern{ .enum_variant = .{
                        .type_name      = "",
                        .variant_name   = name,
                        .field_bindings = try bindings.toOwnedSlice(self.allocator),
                    } };
                }
                return Pattern{ .binding = name };
            },
            .int_literal => {
                const t = self.advance();
                const e = try self.makeExprNode(.{ .int_lit = t.text }, t.span);
                return Pattern{ .literal = e };
            },
            .string_literal => {
                const t = self.advance();
                const e = try self.makeExprNode(.{ .string_lit = t.text }, t.span);
                return Pattern{ .literal = e };
            },
            .kw_nothing => {
                _ = self.advance();
                return .nothing;
            },
            .kw_something => {
                _ = self.advance();
                _ = try self.expect(.lparen);
                const binding = (try self.expect(.identifier)).text;
                _ = try self.expect(.rparen);
                return Pattern{ .something = binding };
            },
            .kw_ok => {
                _ = self.advance();
                _ = try self.expect(.lparen);
                const b = (try self.expect(.identifier)).text;
                _ = try self.expect(.rparen);
                return Pattern{ .ok = b };
            },
            .kw_fail => {
                _ = self.advance();
                _ = try self.expect(.lparen);
                const b = (try self.expect(.identifier)).text;
                _ = try self.expect(.rparen);
                return Pattern{ .fail = .{ .variant = b, .bindings = &.{} } };
            },
            else => {
                const t = self.advance();
                try self.emitErr(t.span, error.UnexpectedToken, "expected pattern", .{});
                return .wildcard;
            },
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

/// Helper: lex + parse `src` using an ArenaAllocator backed by the testing
/// allocator.  Returns the parsed TopLevel slice and the arena (caller must
/// call `arena.deinit()` to free all AST memory).
fn parseArena(
    src:   []const u8,
    arena: *std.heap.ArenaAllocator,
) ![]TopLevel {
    const alloc = arena.allocator();
    var diags   = DiagnosticList.init(alloc);
    // No defer deinit — arena owns it.
    var lexer   = lex.Lexer.init(src, "test.foz");
    const tokens = try lexer.tokenize(alloc, &diags);
    var parser   = Parser.init(tokens, alloc, &diags, src, "test.foz");
    return parser.parse();
}

test "parse minimal contract" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\version 1
        \\contract Foo:
        \\    has:
        \\        x is u256
    ;
    const tls = try parseArena(src, &arena);
    try std.testing.expect(tls.len >= 2);
    try std.testing.expectEqual(TopLevel.version, std.meta.activeTag(tls[0]));
    try std.testing.expect(std.meta.activeTag(tls[1]) == .contract);
    const con = tls[1].contract;
    try std.testing.expectEqualStrings("Foo", con.name);
    try std.testing.expect(con.state.len == 1);
    try std.testing.expectEqualStrings("x", con.state[0].name);
}

test "parse when/otherwise chain" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\version 1
        \\contract Bar:
        \\    action doIt():
        \\        when x equals 1:
        \\            stop
        \\        otherwise when x equals 2:
        \\            stop
        \\        otherwise:
        \\            stop
    ;
    const tls = try parseArena(src, &arena);
    const act = tls[1].contract.actions[0];
    try std.testing.expect(act.body.len == 1);
    const when_stmt = act.body[0].kind.when;
    try std.testing.expect(when_stmt.else_ifs.len == 1);
    try std.testing.expect(when_stmt.else_body != null);
}

test "parse match with enum" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\version 1
        \\contract Baz:
        \\    action check(s is Status):
        \\        match s:
        \\            Active(owner: o) => stop
        \\            _ => stop
    ;
    const tls = try parseArena(src, &arena);
    try std.testing.expect(tls.len >= 2);
    const act      = tls[1].contract.actions[0];
    const match_st = act.body[0].kind.match;
    try std.testing.expect(match_st.arms.len == 2);
    try std.testing.expect(match_st.arms[0].pattern == .enum_variant);
    try std.testing.expect(match_st.arms[1].pattern == .wildcard);
}

test "parse account declaration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\version 1
        \\contract Vault:
        \\    accounts:
        \\        data is Data owned_by this seeded_by ["vault", caller] create_if_missing
    ;
    const tls = try parseArena(src, &arena);
    const con = tls[1].contract;
    try std.testing.expect(con.accounts.len == 1);
    const acc = con.accounts[0];
    try std.testing.expectEqualStrings("data", acc.name);
    try std.testing.expect(acc.ownership == .this);
    try std.testing.expect(acc.create_if_missing == true);
    try std.testing.expect(acc.seeds.len == 2);
}

test "parse authority declaration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\version 1
        \\contract Gov:
        \\    authorities:
        \\        admin is Transfer held_by Multisig{signers: [caller], required: 2}
    ;
    const tls = try parseArena(src, &arena);
    const con  = tls[1].contract;
    try std.testing.expect(con.authorities.len == 1);
    const auth = con.authorities[0];
    try std.testing.expectEqualStrings("admin", auth.name);
    try std.testing.expect(auth.holder_type == .multisig);
    try std.testing.expect(auth.multisig_cfg != null);
    try std.testing.expect(auth.multisig_cfg.?.required == 2);
}

test "parse action with guard and need" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\version 1
        \\contract Token:
        \\    action transfer(amount is u64):
        \\        need amount > 0
        \\        give back
    ;
    const tls = try parseArena(src, &arena);
    const act = tls[1].contract.actions[0];
    try std.testing.expectEqualStrings("transfer", act.name);
    try std.testing.expect(act.body.len == 2);
    try std.testing.expect(std.meta.activeTag(act.body[0].kind) == .need);
    try std.testing.expect(std.meta.activeTag(act.body[1].kind) == .give_back);
}
