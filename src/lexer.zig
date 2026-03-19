// ============================================================================
// Forge Compiler — Lexer
// ============================================================================
//
// Converts raw .foz source text ([]const u8) into a flat []Token array.
// All string slices in tokens point into the original source buffer — zero copy.
// No heap allocation per token; the final slice is the only allocation.
//
// SPEC REFERENCE:
//   Part 2.1  — Literals
//   Part 2.2  — Duration literals
//   Part 2.3  — String types
//   The complete keyword list is encoded in the comptime map below.
//
// This is a library file. No main() function.

const std    = @import("std");
const ast    = @import("ast.zig");
const errors = @import("errors.zig");

pub const Span            = ast.Span;
pub const CompileError    = errors.CompileError;
pub const Diagnostic      = errors.Diagnostic;
pub const DiagnosticList  = errors.DiagnosticList;

// ============================================================================
// SECTION 1 — Token Kind Enum
// ============================================================================

/// Every distinct token the ZEPH lexer can produce.
pub const TokenKind = enum {

    // ── Literals ─────────────────────────────────────────────────────────
    /// Decimal integer, optionally with `_` separators: `1_000_000`
    /// Or binary literal:  `0b1010`
    int_literal,
    /// Decimal fixed-point / float literal: `1_234.567`
    float_literal,
    /// Double-quoted UTF-8 string: `"hello\nworld"`
    string_literal,
    /// Hex literal (any length): `0xABCD…`
    /// 32+ byte hex becomes an address; shorter is a number.
    hex_literal,

    // ── Keywords — Declaration structure ─────────────────────────────────
    kw_version,
    kw_contract,
    kw_asset,
    kw_interface,
    kw_struct,
    kw_record,
    kw_enum,
    kw_error,
    kw_event,
    kw_guard,
    kw_always,
    kw_has,
    kw_setup,
    kw_authorities,
    kw_accounts,
    kw_implements,
    kw_config,
    kw_computed,
    kw_upgrade,
    kw_namespace,
    kw_invariant,

    // ── Keywords — Function-like ──────────────────────────────────────────
    kw_action,
    kw_view,
    kw_pure,
    kw_hidden,
    kw_helper,

    // ── Keywords — Control flow ───────────────────────────────────────────
    kw_when,
    kw_otherwise,
    kw_then,
    kw_match,
    kw_each,
    kw_in,
    kw_repeat,
    kw_times,
    kw_while,
    kw_stop,
    kw_skip,
    kw_give,
    kw_back,
    kw_panic,
    kw_need,
    kw_else,
    kw_ensure,
    kw_attempt,
    kw_on_error,
    kw_always_after,

    // ── Keywords — Boolean ────────────────────────────────────────────────
    kw_yes,
    kw_no,
    kw_not,

    // ── Keywords — Logic operators ────────────────────────────────────────
    kw_and,
    kw_or,

    // ── Keywords — Arithmetic operators (English) ─────────────────────────
    kw_plus,
    kw_minus,
    kw_times_op,    // `times` used as multiplication (not loop-times)
    kw_divided,     // first word of `divided by`
    kw_by,          // second word of `divided by`; parser assembles the pair
    kw_mod,

    // ── Keywords — Comparison ─────────────────────────────────────────────
    kw_equals,
    kw_is,

    // ── Keywords — Optional ───────────────────────────────────────────────
    kw_nothing,
    kw_something,
    kw_maybe,
    kw_or_fallback,  // `or` when used as optional fallback (same token, parser decides)

    // ── Keywords — Access control ─────────────────────────────────────────
    kw_only,
    kw_shared,
    kw_within,
    kw_outside,
    kw_system,

    // ── Keywords — Account declarations ───────────────────────────────────
    kw_owned_by,
    kw_seeded_by,
    kw_readonly,
    kw_create_if_missing,
    kw_child_of,
    kw_can,
    kw_read,
    kw_write,
    kw_linked_to,
    kw_global,
    kw_mine,
    kw_this,
    kw_params,
    kw_known,
    kw_at,
    kw_exists,

    // ── Keywords — Authority declarations ─────────────────────────────────
    kw_held_by,
    kw_initially,
    kw_nobody,
    kw_with_timelock,
    kw_inheritable,
    kw_covers,
    kw_inherits,

    // ── Keywords — Type names (Part 2.1) ──────────────────────────────────
    kw_u8,           kw_u16,  kw_u32,   kw_u64,   kw_u128, kw_u256, kw_uint,
    kw_i8,           kw_i16,  kw_i32,   kw_i64,   kw_i128, kw_i256, kw_int,
    kw_bool,
    kw_account_type, kw_wallet_type, kw_program_type, kw_system_acc,
    kw_hash_type,    kw_hash20, kw_commitment,
    kw_byte_type,    kw_bytes_type, kw_bytes32, kw_bytes64,
    kw_signature,    kw_pubkey,
    kw_string_type,  kw_short_str, kw_label,
    kw_timestamp,    kw_duration, kw_block_number, kw_epoch, kw_slot,
    kw_price9,       kw_price18, kw_percent,
    kw_fixed,
    kw_result_type,  kw_map, kw_enum_map, kw_list, kw_set, kw_array,
    kw_tuple,

    // ── Keywords — Asset operations ───────────────────────────────────────
    kw_send,
    kw_to,
    kw_pay,
    kw_from,
    kw_move,
    kw_burn,
    kw_split,
    kw_wrap,
    kw_unwrap,
    kw_merge,
    kw_tell,
    kw_throw,
    kw_schedule,
    kw_give_back,    // two-word: parser assembles `give` + `back`
    kw_remove,
    kw_close,
    kw_freeze,
    kw_unfreeze,
    kw_expand,
    kw_transfer_ownership,

    // ── Keywords — Duration units (Part 2.2) ──────────────────────────────
    kw_millisecond,  kw_milliseconds,
    kw_second,       kw_seconds,
    kw_minute,       kw_minutes,
    kw_hour,         kw_hours,
    kw_day,          kw_days,
    kw_week,         kw_weeks,
    kw_month,        kw_months,
    kw_year,         kw_years,

    // ── Keywords — Misc / imports ─────────────────────────────────────────
    kw_use,
    kw_define,
    kw_as,
    kw_let,
    kw_alias,
    kw_gives,        // `gives ReturnType`
    kw_ok,
    kw_fail,
    kw_deployer,
    kw_caller,
    kw_value_kw,     // `value` (built-in)
    kw_now,
    kw_current_block,
    kw_gas_remaining,
    kw_indexed,
    kw_since_version,
    kw_parallel,
    kw_where,
    kw_follows,
    kw_debit,
    kw_credit,

    // ── Punctuation ───────────────────────────────────────────────────────
    colon,          // :
    double_colon,   // ::
    semicolon,      // ;
    comma,          // ,
    dot,            // .
    dot_dot,        // .. (range)
    lparen,         // (
    rparen,         // )
    lbracket,       // [
    rbracket,       // ]
    lbrace,         // {
    rbrace,         // }
    arrow,          // ->
    fat_arrow,      // =>
    question,       // ?
    at_sign,        // @
    hash_sym,       // #
    equals_sign,    // =
    plus_eq,        // +=
    minus_eq,       // -=
    times_eq,       // *=
    slash,          // /
    backslash,      // \
    pipe,           // |
    ampersand,      // &
    gt,             // >
    lt,             // <
    gte,            // >=
    lte,            // <=
    tilde,          // ~

    // ── Special ───────────────────────────────────────────────────────────
    identifier,
    doc_comment,    // /// documentation comment
    line_comment,   // // single-line comment
    block_comment,  // /* … */ multi-line comment

    /// A character sequence the lexer could not classify.
    /// Always accompanied by a Diagnostic in the DiagnosticList.
    error_token,

    eof,
};

// ============================================================================
// SECTION 2 — Token Struct
// ============================================================================

/// One token produced by the lexer.
/// `text` is a zero-copy slice into the original source buffer.
pub const Token = struct {
    kind: TokenKind,
    /// Slice into the source buffer — no allocation; always valid while the
    /// source buffer is alive.
    text: []const u8,
    /// Location of the first byte of this token in the source file.
    span: Span,
};

// ============================================================================
// SECTION 3 — Keyword Map (comptime, O(1) lookup)
// ============================================================================

/// Static comptime keyword map: source text → TokenKind.
/// All ZEPH reserved words are listed here.  The parser never looks up
/// keywords by string; it queries `tokenKindOf()`.
const keyword_map = std.StaticStringMap(TokenKind).initComptime(.{
    // Declaration structure
    .{ "version",               .kw_version            },
    .{ "contract",              .kw_contract            },
    .{ "asset",                 .kw_asset               },
    .{ "interface",             .kw_interface           },
    .{ "struct",                .kw_struct              },
    .{ "record",                .kw_record              },
    .{ "enum",                  .kw_enum                },
    .{ "error",                 .kw_error               },
    .{ "event",                 .kw_event               },
    .{ "guard",                 .kw_guard               },
    .{ "always",                .kw_always              },
    .{ "has",                   .kw_has                 },
    .{ "setup",                 .kw_setup               },
    .{ "authorities",           .kw_authorities         },
    .{ "accounts",              .kw_accounts            },
    .{ "implements",            .kw_implements          },
    .{ "config",                .kw_config              },
    .{ "computed",              .kw_computed            },
    .{ "upgrade",               .kw_upgrade             },
    .{ "namespace",             .kw_namespace           },
    .{ "invariant",             .kw_invariant           },
    // Function-like
    .{ "action",                .kw_action              },
    .{ "view",                  .kw_view                },
    .{ "pure",                  .kw_pure                },
    .{ "hidden",                .kw_hidden              },
    .{ "helper",                .kw_helper              },
    // Control flow
    .{ "when",                  .kw_when                },
    .{ "otherwise",             .kw_otherwise           },
    .{ "then",                  .kw_then                },
    .{ "match",                 .kw_match               },
    .{ "each",                  .kw_each                },
    .{ "in",                    .kw_in                  },
    .{ "repeat",                .kw_repeat              },
    .{ "times",                 .kw_times               },
    .{ "while",                 .kw_while               },
    .{ "stop",                  .kw_stop                },
    .{ "skip",                  .kw_skip                },
    .{ "give",                  .kw_give                },
    .{ "back",                  .kw_back                },
    .{ "panic",                 .kw_panic               },
    .{ "need",                  .kw_need                },
    .{ "else",                  .kw_else                },
    .{ "ensure",                .kw_ensure              },
    .{ "attempt",               .kw_attempt             },
    .{ "on_error",              .kw_on_error            },
    .{ "always_after",          .kw_always_after        },
    // Boolean
    .{ "yes",                   .kw_yes                 },
    .{ "no",                    .kw_no                  },
    .{ "not",                   .kw_not                 },
    // Logic
    .{ "and",                   .kw_and                 },
    .{ "or",                    .kw_or                  },
    // Arithmetic (English)
    .{ "plus",                  .kw_plus                },
    .{ "minus",                 .kw_minus               },
    .{ "divided",               .kw_divided             },
    .{ "by",                    .kw_by                  },
    .{ "mod",                   .kw_mod                 },
    // Comparison
    .{ "equals",                .kw_equals              },
    .{ "is",                    .kw_is                  },
    // Optional
    .{ "nothing",               .kw_nothing             },
    .{ "something",             .kw_something           },
    .{ "maybe",                 .kw_maybe               },
    // Access control
    .{ "only",                  .kw_only                },
    .{ "shared",                .kw_shared              },
    .{ "within",                .kw_within              },
    .{ "outside",               .kw_outside             },
    .{ "system",                .kw_system              },
    .{ "readonly",              .kw_readonly            },
    // Account keywords
    .{ "owned_by",              .kw_owned_by            },
    .{ "seeded_by",             .kw_seeded_by           },
    .{ "create_if_missing",     .kw_create_if_missing   },
    .{ "child_of",              .kw_child_of            },
    .{ "can",                   .kw_can                 },
    .{ "read",                  .kw_read                },
    .{ "write",                 .kw_write               },
    .{ "linked_to",             .kw_linked_to           },
    .{ "global",                .kw_global              },
    .{ "mine",                  .kw_mine                },
    .{ "this",                  .kw_this                },
    .{ "params",                .kw_params              },
    .{ "known",                 .kw_known               },
    .{ "at",                    .kw_at                  },
    .{ "exists",                .kw_exists              },
    // Authority keywords
    .{ "held_by",               .kw_held_by             },
    .{ "initially",             .kw_initially           },
    .{ "nobody",                .kw_nobody              },
    .{ "with_timelock",         .kw_with_timelock       },
    .{ "inheritable",           .kw_inheritable         },
    .{ "covers",                .kw_covers              },
    .{ "inherits",              .kw_inherits            },
    // Primitive type names (Part 2.1)
    .{ "u8",                    .kw_u8                  },
    .{ "u16",                   .kw_u16                 },
    .{ "u32",                   .kw_u32                 },
    .{ "u64",                   .kw_u64                 },
    .{ "u128",                  .kw_u128                },
    .{ "u256",                  .kw_u256                },
    .{ "uint",                  .kw_uint                },
    .{ "i8",                    .kw_i8                  },
    .{ "i16",                   .kw_i16                 },
    .{ "i32",                   .kw_i32                 },
    .{ "i64",                   .kw_i64                 },
    .{ "i128",                  .kw_i128                },
    .{ "i256",                  .kw_i256                },
    .{ "int",                   .kw_int                 },
    .{ "bool",                  .kw_bool                },
    .{ "Account",               .kw_account_type        },
    .{ "Wallet",                .kw_wallet_type         },
    .{ "Program",               .kw_program_type        },
    .{ "System",                .kw_system_acc          },
    .{ "Hash",                  .kw_hash_type           },
    .{ "Hash20",                .kw_hash20              },
    .{ "Commitment",            .kw_commitment          },
    .{ "byte",                  .kw_byte_type           },
    .{ "Bytes",                 .kw_bytes_type          },
    .{ "Bytes32",               .kw_bytes32             },
    .{ "Bytes64",               .kw_bytes64             },
    .{ "Signature",             .kw_signature           },
    .{ "PublicKey",             .kw_pubkey              },
    .{ "String",                .kw_string_type         },
    .{ "ShortStr",              .kw_short_str           },
    .{ "Label",                 .kw_label               },
    .{ "Timestamp",             .kw_timestamp           },
    .{ "Duration",              .kw_duration            },
    .{ "BlockNumber",           .kw_block_number        },
    .{ "Epoch",                 .kw_epoch               },
    .{ "Slot",                  .kw_slot                },
    .{ "price9",                .kw_price9              },
    .{ "price18",               .kw_price18             },
    .{ "percent",               .kw_percent             },
    .{ "Fixed",                 .kw_fixed               },
    .{ "Result",                .kw_result_type         },
    .{ "Map",                   .kw_map                 },
    .{ "EnumMap",               .kw_enum_map            },
    .{ "List",                  .kw_list                },
    .{ "Set",                   .kw_set                 },
    .{ "Array",                 .kw_array               },
    // Asset operations
    .{ "send",                  .kw_send                },
    .{ "to",                    .kw_to                  },
    .{ "pay",                   .kw_pay                 },
    .{ "from",                  .kw_from                },
    .{ "move",                  .kw_move                },
    .{ "burn",                  .kw_burn                },
    .{ "split",                 .kw_split               },
    .{ "wrap",                  .kw_wrap                },
    .{ "unwrap",                .kw_unwrap              },
    .{ "merge",                 .kw_merge               },
    .{ "tell",                  .kw_tell                },
    .{ "throw",                 .kw_throw               },
    .{ "schedule",              .kw_schedule            },
    .{ "remove",                .kw_remove              },
    .{ "close",                 .kw_close               },
    .{ "freeze",                .kw_freeze              },
    .{ "unfreeze",              .kw_unfreeze            },
    .{ "expand",                .kw_expand              },
    .{ "transfer_ownership",    .kw_transfer_ownership  },
    // Duration units
    .{ "millisecond",           .kw_millisecond         },
    .{ "milliseconds",          .kw_milliseconds        },
    .{ "second",                .kw_second              },
    .{ "seconds",               .kw_seconds             },
    .{ "minute",                .kw_minute              },
    .{ "minutes",               .kw_minutes             },
    .{ "hour",                  .kw_hour                },
    .{ "hours",                 .kw_hours               },
    .{ "day",                   .kw_day                 },
    .{ "days",                  .kw_days                },
    .{ "week",                  .kw_week                },
    .{ "weeks",                 .kw_weeks               },
    .{ "month",                 .kw_month               },
    .{ "months",                .kw_months              },
    .{ "year",                  .kw_year                },
    .{ "years",                 .kw_years               },
    // Misc
    .{ "use",                   .kw_use                 },
    .{ "define",                .kw_define              },
    .{ "as",                    .kw_as                  },
    .{ "let",                   .kw_let                 },
    .{ "alias",                 .kw_alias               },
    .{ "gives",                 .kw_gives               },
    .{ "ok",                    .kw_ok                  },
    .{ "fail",                  .kw_fail                },
    .{ "deployer",              .kw_deployer            },
    .{ "caller",                .kw_caller              },
    .{ "value",                 .kw_value_kw            },
    .{ "now",                   .kw_now                 },
    .{ "current_block",         .kw_current_block       },
    .{ "gas_remaining",         .kw_gas_remaining       },
    .{ "indexed",               .kw_indexed             },
    .{ "since_version",         .kw_since_version       },
    .{ "parallel",              .kw_parallel            },
    .{ "where",                 .kw_where               },
    .{ "follows",               .kw_follows             },
    .{ "debit",                 .kw_debit               },
    .{ "credit",                .kw_credit              },
});

/// Look up whether a source word is a reserved keyword.
/// Returns `null` for identifiers; otherwise returns the token kind.
pub fn tokenKindOf(word: []const u8) ?TokenKind {
    return keyword_map.get(word);
}

// ============================================================================
// SECTION 4 — Lexer
// ============================================================================

/// The ZEPH lexer.  Call `init` then `tokenize`.
pub const Lexer = struct {
    /// The complete source text.
    source:  []const u8,
    /// Current byte offset into `source`.
    pos:     usize,
    /// Current 1-based line number (updated on each `\n`).
    line:    u32,
    /// Current 1-based column number (byte offset within line).
    col:     u32,
    /// File path shown in diagnostics.
    file:    []const u8,

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /// Construct a fresh lexer for `source`.  `file` is used only in
    /// diagnostics and is not freed by the lexer.
    pub fn init(source: []const u8, file: []const u8) Lexer {
        return .{
            .source = source,
            .pos    = 0,
            .line   = 1,
            .col    = 1,
            .file   = file,
        };
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Lex the entire source and return a heap-allocated `[]Token`.
    ///
    /// Every token (including comments) is returned.  On lexical errors the
    /// lexer emits an `error_token`, records a `Diagnostic` in `diags`, and
    /// continues — so the caller always gets a complete token stream.
    ///
    /// The caller owns the returned slice; free with `allocator.free(tokens)`.
    pub fn tokenize(
        self:      *Lexer,
        allocator: std.mem.Allocator,
        diags:     *DiagnosticList,
    ) anyerror![]Token {
        var list: std.ArrayListUnmanaged(Token) = .{};
        errdefer list.deinit(allocator);

        while (true) {
            const tok = try self.nextToken(allocator, diags);
            try list.append(allocator, tok);
            if (tok.kind == .eof) break;
        }

        return list.toOwnedSlice(allocator);
    }

    // ── Internal: top-level token dispatcher ─────────────────────────────

    fn nextToken(
        self:      *Lexer,
        allocator: std.mem.Allocator,
        diags:     *DiagnosticList,
    ) anyerror!Token {
        // Skip whitespace (but track newlines for line/col).
        self.skipWhitespace();

        if (self.pos >= self.source.len) {
            return self.makeTokenAt(.eof, self.pos, self.line, self.col);
        }

        const start      = self.pos;
        const start_line = self.line;
        const start_col  = self.col;
        const ch         = self.source[self.pos];

        // ── Comments ───────────────────────────────────────────────────
        if (ch == '/' and self.pos + 1 < self.source.len) {
            const next = self.source[self.pos + 1];
            if (next == '/') {
                // `///` doc comment vs `//` line comment
                if (self.pos + 2 < self.source.len and self.source[self.pos + 2] == '/') {
                    return self.scanLineComment(start, start_line, start_col, .doc_comment);
                }
                return self.scanLineComment(start, start_line, start_col, .line_comment);
            }
            if (next == '*') {
                return try self.scanBlockComment(start, start_line, start_col, allocator, diags);
            }
            // Bare `/` — slash token.
            self.advance();
            return self.makeTokenAt(.slash, start, start_line, start_col);
        }

        // ── Number literals ────────────────────────────────────────────
        if (isDigit(ch)) {
            return self.scanNumber(start, start_line, start_col);
        }

        // ── String literals ────────────────────────────────────────────
        if (ch == '"') {
            return try self.scanString(start, start_line, start_col, allocator, diags);
        }

        // ── Identifiers & keywords ─────────────────────────────────────
        if (isIdentStart(ch)) {
            return self.scanIdentOrKeyword(start, start_line, start_col);
        }

        // ── Punctuation & operators ────────────────────────────────────
        return try self.scanPunct(start, start_line, start_col, allocator, diags);
    }

    // ── Whitespace ────────────────────────────────────────────────────────

    fn skipWhitespace(self: *Lexer) void {
        while (self.pos < self.source.len) {
            const c = self.source[self.pos];
            if (c == '\n') {
                self.line += 1;
                self.col   = 1;
                self.pos  += 1;
            } else if (c == ' ' or c == '\t' or c == '\r') {
                self.col  += 1;
                self.pos  += 1;
            } else {
                break;
            }
        }
    }

    // ── Comments ──────────────────────────────────────────────────────────

    fn scanLineComment(
        self:       *Lexer,
        start:      usize,
        start_line: u32,
        start_col:  u32,
        kind:       TokenKind,
    ) Token {
        // Consume to end of line (but not the newline itself).
        while (self.pos < self.source.len and self.source[self.pos] != '\n') {
            self.col += 1;
            self.pos += 1;
        }
        return self.makeTokenAt(kind, start, start_line, start_col);
    }

    fn scanBlockComment(
        self:       *Lexer,
        start:      usize,
        start_line: u32,
        start_col:  u32,
        allocator:  std.mem.Allocator,
        diags:      *DiagnosticList,
    ) anyerror!Token {
        // Consume `/*`.
        self.pos += 2;
        self.col += 2;
        var depth: u32 = 1; // Support nested /* /* */ */ comments.

        while (self.pos + 1 < self.source.len) {
            if (self.source[self.pos] == '/' and self.source[self.pos + 1] == '*') {
                depth    += 1;
                self.pos += 2;
                self.col += 2;
            } else if (self.source[self.pos] == '*' and self.source[self.pos + 1] == '/') {
                depth    -= 1;
                self.pos += 2;
                self.col += 2;
                if (depth == 0) break;
            } else if (self.source[self.pos] == '\n') {
                self.line += 1;
                self.col   = 1;
                self.pos  += 1;
            } else {
                self.col += 1;
                self.pos += 1;
            }
        }

        if (depth != 0) {
            try self.emitDiag(diags, allocator, error.UnterminatedString,
                start, start_line, start_col, 1, "unterminated block comment");
            return self.makeTokenAt(.error_token, start, start_line, start_col);
        }

        return self.makeTokenAt(.block_comment, start, start_line, start_col);
    }

    // ── Numbers ───────────────────────────────────────────────────────────

    fn scanNumber(
        self:       *Lexer,
        start:      usize,
        start_line: u32,
        start_col:  u32,
    ) Token {
        // Check for 0x (hex) or 0b (binary) prefix.
        if (self.source[self.pos] == '0' and self.pos + 1 < self.source.len) {
            const prefix = self.source[self.pos + 1];
            if (prefix == 'x' or prefix == 'X') {
                self.pos += 2;
                self.col += 2;
                while (self.pos < self.source.len and
                    isHexDigitOrUnderscore(self.source[self.pos]))
                {
                    self.col += 1;
                    self.pos += 1;
                }
                return self.makeTokenAt(.hex_literal, start, start_line, start_col);
            }
            if (prefix == 'b' or prefix == 'B') {
                self.pos += 2;
                self.col += 2;
                while (self.pos < self.source.len) {
                    const bc = self.source[self.pos];
                    if (bc == '0' or bc == '1' or bc == '_') {
                        self.col += 1;
                        self.pos += 1;
                    } else break;
                }
                return self.makeTokenAt(.int_literal, start, start_line, start_col);
            }
        }

        // Decimal integer (may have `_` separators).
        while (self.pos < self.source.len and isDigitOrUnderscore(self.source[self.pos])) {
            self.col += 1;
            self.pos += 1;
        }

        // Optional fractional part → float_literal.
        if (self.pos + 1 < self.source.len and
            self.source[self.pos] == '.' and
            isDigit(self.source[self.pos + 1]))
        {
            self.col += 1; // consume `.`
            self.pos += 1;
            while (self.pos < self.source.len and isDigitOrUnderscore(self.source[self.pos])) {
                self.col += 1;
                self.pos += 1;
            }
            return self.makeTokenAt(.float_literal, start, start_line, start_col);
        }

        return self.makeTokenAt(.int_literal, start, start_line, start_col);
    }

    // ── Strings ───────────────────────────────────────────────────────────

    fn scanString(
        self:       *Lexer,
        start:      usize,
        start_line: u32,
        start_col:  u32,
        allocator:  std.mem.Allocator,
        diags:      *DiagnosticList,
    ) anyerror!Token {
        self.advance(); // consume opening `"`.

        while (self.pos < self.source.len) {
            const c = self.source[self.pos];
            if (c == '"') {
                self.advance(); // consume closing `"`.
                return self.makeTokenAt(.string_literal, start, start_line, start_col);
            }
            if (c == '\n') {
                // Unterminated — do not consume the newline.
                try self.emitDiag(diags, allocator, error.UnterminatedString,
                    start, start_line, start_col, 1, "unterminated string literal");
                return self.makeTokenAt(.error_token, start, start_line, start_col);
            }
            if (c == '\\') {
                // Escape sequence: consume `\` and the escape character.
                self.advance();
                if (self.pos < self.source.len) self.advance();
            } else {
                self.advance();
            }
        }

        // Reached EOF inside a string.
        try self.emitDiag(diags, allocator, error.UnterminatedString,
            start, start_line, start_col, 1, "unterminated string literal (unexpected EOF)");
        return self.makeTokenAt(.error_token, start, start_line, start_col);
    }

    // ── Identifiers & keywords ────────────────────────────────────────────

    fn scanIdentOrKeyword(
        self:       *Lexer,
        start:      usize,
        start_line: u32,
        start_col:  u32,
    ) Token {
        while (self.pos < self.source.len and isIdentCont(self.source[self.pos])) {
            self.col += 1;
            self.pos += 1;
        }
        const word = self.source[start..self.pos];
        const kind  = tokenKindOf(word) orelse .identifier;
        return self.makeTokenAt(kind, start, start_line, start_col);
    }

    // ── Punctuation & operators ───────────────────────────────────────────

    fn scanPunct(
        self:       *Lexer,
        start:      usize,
        start_line: u32,
        start_col:  u32,
        allocator:  std.mem.Allocator,
        diags:      *DiagnosticList,
    ) anyerror!Token {
        const ch = self.source[self.pos];
        self.advance();

        switch (ch) {
            ':' => {
                if (self.pos < self.source.len and self.source[self.pos] == ':') {
                    self.advance();
                    return self.makeTokenAt(.double_colon, start, start_line, start_col);
                }
                return self.makeTokenAt(.colon, start, start_line, start_col);
            },
            ';' => return self.makeTokenAt(.semicolon,   start, start_line, start_col),
            ',' => return self.makeTokenAt(.comma,        start, start_line, start_col),
            '.' => {
                if (self.pos < self.source.len and self.source[self.pos] == '.') {
                    self.advance();
                    return self.makeTokenAt(.dot_dot, start, start_line, start_col);
                }
                return self.makeTokenAt(.dot, start, start_line, start_col);
            },
            '(' => return self.makeTokenAt(.lparen,       start, start_line, start_col),
            ')' => return self.makeTokenAt(.rparen,       start, start_line, start_col),
            '[' => return self.makeTokenAt(.lbracket,     start, start_line, start_col),
            ']' => return self.makeTokenAt(.rbracket,     start, start_line, start_col),
            '{' => return self.makeTokenAt(.lbrace,       start, start_line, start_col),
            '}' => return self.makeTokenAt(.rbrace,       start, start_line, start_col),
            '?' => return self.makeTokenAt(.question,     start, start_line, start_col),
            '@' => return self.makeTokenAt(.at_sign,      start, start_line, start_col),
            '#' => return self.makeTokenAt(.hash_sym,     start, start_line, start_col),
            '|' => return self.makeTokenAt(.pipe,         start, start_line, start_col),
            '&' => return self.makeTokenAt(.ampersand,    start, start_line, start_col),
            '~' => return self.makeTokenAt(.tilde,        start, start_line, start_col),
            '\\' => return self.makeTokenAt(.backslash,   start, start_line, start_col),
            '-' => {
                if (self.pos < self.source.len and self.source[self.pos] == '>') {
                    self.advance();
                    return self.makeTokenAt(.arrow, start, start_line, start_col);
                }
                if (self.pos < self.source.len and self.source[self.pos] == '=') {
                    self.advance();
                    return self.makeTokenAt(.minus_eq, start, start_line, start_col);
                }
                return self.makeTokenAt(.kw_minus, start, start_line, start_col);
            },
            '+' => {
                if (self.pos < self.source.len and self.source[self.pos] == '=') {
                    self.advance();
                    return self.makeTokenAt(.plus_eq, start, start_line, start_col);
                }
                return self.makeTokenAt(.kw_plus, start, start_line, start_col);
            },
            '*' => {
                if (self.pos < self.source.len and self.source[self.pos] == '=') {
                    self.advance();
                    return self.makeTokenAt(.times_eq, start, start_line, start_col);
                }
                return self.makeTokenAt(.kw_times_op, start, start_line, start_col);
            },
            '=' => {
                if (self.pos < self.source.len and self.source[self.pos] == '>') {
                    self.advance();
                    return self.makeTokenAt(.fat_arrow, start, start_line, start_col);
                }
                return self.makeTokenAt(.equals_sign, start, start_line, start_col);
            },
            '>' => {
                if (self.pos < self.source.len and self.source[self.pos] == '=') {
                    self.advance();
                    return self.makeTokenAt(.gte, start, start_line, start_col);
                }
                return self.makeTokenAt(.gt, start, start_line, start_col);
            },
            '<' => {
                if (self.pos < self.source.len and self.source[self.pos] == '=') {
                    self.advance();
                    return self.makeTokenAt(.lte, start, start_line, start_col);
                }
                return self.makeTokenAt(.lt, start, start_line, start_col);
            },
            else => {
                // Unknown character — error recovery.
                const byte_len: u32 = @intCast(self.pos - start);
                try self.emitDiag(diags, allocator, error.UnexpectedCharacter,
                    start, start_line, start_col, byte_len, "unexpected character");
                return self.makeTokenAt(.error_token, start, start_line, start_col);
            },
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    /// Advance one byte, updating `col`.
    inline fn advance(self: *Lexer) void {
        self.pos += 1;
        self.col += 1;
    }

    /// Build a Token starting at `start` (byte offset) and ending at
    /// `self.pos`, attributed to `start_line` / `start_col`.
    fn makeTokenAt(
        self:       *const Lexer,
        kind:       TokenKind,
        start:      usize,
        start_line: u32,
        start_col:  u32,
    ) Token {
        const end      = if (start > self.source.len) self.source.len else self.pos;
        const byte_len: u32 = @intCast(end - start);
        return .{
            .kind = kind,
            .text = self.source[start..end],
            .span = .{ .line = start_line, .col = start_col, .len = byte_len },
        };
    }

    /// Return the source line containing byte offset `pos`.
    fn lineAt(self: *const Lexer, pos: usize) []const u8 {
        var lo = if (pos > self.source.len) self.source.len else pos;
        while (lo > 0 and self.source[lo - 1] != '\n') : (lo -= 1) {}
        var hi = pos;
        while (hi < self.source.len and self.source[hi] != '\n') : (hi += 1) {}
        return self.source[lo..hi];
    }

    /// Emit one Diagnostic for a lexical error.
    fn emitDiag(
        self:       *Lexer,
        diags:      *DiagnosticList,
        allocator:  std.mem.Allocator,
        kind:       CompileError,
        start:      usize,
        start_line: u32,
        start_col:  u32,
        len:        u32,
        comptime msg: []const u8,
    ) anyerror!void {
        const message     = try std.fmt.allocPrint(allocator, msg, .{});
        const source_line = self.lineAt(start);
        try diags.add(.{
            .file        = self.file,
            .line        = start_line,
            .col         = start_col,
            .len         = len,
            .kind        = kind,
            .message     = message,
            .source_line = source_line,
        });
    }
};

// ── Character class helpers (file-scope, no allocation) ──────────────────────

inline fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

inline fn isDigitOrUnderscore(c: u8) bool {
    return isDigit(c) or c == '_';
}

inline fn isHexDigitOrUnderscore(c: u8) bool {
    return isDigit(c) or
        (c >= 'a' and c <= 'f') or
        (c >= 'A' and c <= 'F') or
        c == '_';
}

/// Valid first character of an identifier or keyword.
inline fn isIdentStart(c: u8) bool {
    return (c >= 'a' and c <= 'z') or
           (c >= 'A' and c <= 'Z') or
           c == '_';
}

/// Valid continuation character of an identifier or keyword.
inline fn isIdentCont(c: u8) bool {
    return isIdentStart(c) or isDigit(c);
}

// ============================================================================
// Tests
// ============================================================================

/// Convenience: lex `src` with no file name, returning the token slice.
/// The caller is responsible for freeing the returned slice.
fn lexAll(src: []const u8, allocator: std.mem.Allocator) ![]Token {
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var lexer = Lexer.init(src, "test.foz");
    return lexer.tokenize(allocator, &diags);
}

test "lex basic contract" {
    const allocator = std.testing.allocator;
    const tokens = try lexAll("contract Foo:", allocator);
    defer allocator.free(tokens);

    // Expected: kw_contract, identifier("Foo"), colon, eof
    try std.testing.expectEqual(@as(usize, 4), tokens.len);
    try std.testing.expectEqual(TokenKind.kw_contract, tokens[0].kind);
    try std.testing.expectEqual(TokenKind.identifier,  tokens[1].kind);
    try std.testing.expectEqualStrings("Foo",          tokens[1].text);
    try std.testing.expectEqual(TokenKind.colon,       tokens[2].kind);
    try std.testing.expectEqual(TokenKind.eof,         tokens[3].kind);
    // Verify spans are 1-based.
    try std.testing.expectEqual(@as(u32, 1), tokens[0].span.line);
    try std.testing.expectEqual(@as(u32, 1), tokens[0].span.col);
}

test "lex all keywords" {
    const allocator = std.testing.allocator;

    const Case = struct { src: []const u8, kind: TokenKind };
    const cases = [_]Case{
        .{ .src = "version",           .kind = .kw_version     },
        .{ .src = "action",            .kind = .kw_action       },
        .{ .src = "when",              .kind = .kw_when         },
        .{ .src = "yes",               .kind = .kw_yes          },
        .{ .src = "no",                .kind = .kw_no           },
        .{ .src = "not",               .kind = .kw_not          },
        .{ .src = "and",               .kind = .kw_and          },
        .{ .src = "or",                .kind = .kw_or           },
        .{ .src = "equals",            .kind = .kw_equals       },
        .{ .src = "nothing",           .kind = .kw_nothing      },
        .{ .src = "something",         .kind = .kw_something    },
        .{ .src = "owned_by",          .kind = .kw_owned_by     },
        .{ .src = "held_by",           .kind = .kw_held_by      },
        .{ .src = "u256",              .kind = .kw_u256         },
        .{ .src = "Account",           .kind = .kw_account_type },
        .{ .src = "send",              .kind = .kw_send         },
        .{ .src = "days",              .kind = .kw_days         },
        .{ .src = "gives",             .kind = .kw_gives        },
        .{ .src = "caller",            .kind = .kw_caller       },
        .{ .src = "deployer",          .kind = .kw_deployer     },
        .{ .src = "freeze",            .kind = .kw_freeze       },
        .{ .src = "parallel",          .kind = .kw_parallel     },
        .{ .src = "create_if_missing", .kind = .kw_create_if_missing },
        .{ .src = "transfer_ownership",.kind = .kw_transfer_ownership },
    };

    for (cases) |c| {
        const tokens = try lexAll(c.src, allocator);
        defer allocator.free(tokens);
        try std.testing.expect(tokens.len >= 2);
        try std.testing.expectEqual(c.kind, tokens[0].kind);
        try std.testing.expectEqualStrings(c.src, tokens[0].text);
    }
}

test "lex integer literals with underscores" {
    const allocator = std.testing.allocator;

    const tokens = try lexAll("1_000_000", allocator);
    defer allocator.free(tokens);

    try std.testing.expectEqual(@as(usize, 2), tokens.len); // literal + eof
    try std.testing.expectEqual(TokenKind.int_literal, tokens[0].kind);
    try std.testing.expectEqualStrings("1_000_000",    tokens[0].text);
}

test "lex hex address" {
    const allocator = std.testing.allocator;

    // 64 hex digits = 32 bytes (the length of a ZEPH address).
    const addr = "0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";
    const tokens = try lexAll(addr, allocator);
    defer allocator.free(tokens);

    try std.testing.expectEqual(@as(usize, 2), tokens.len);
    try std.testing.expectEqual(TokenKind.hex_literal, tokens[0].kind);
    try std.testing.expectEqualStrings(addr,           tokens[0].text);
}

test "lex string" {
    const allocator = std.testing.allocator;

    const tokens = try lexAll("\"hello world\"", allocator);
    defer allocator.free(tokens);

    try std.testing.expectEqual(@as(usize, 2), tokens.len);
    try std.testing.expectEqual(TokenKind.string_literal, tokens[0].kind);
    // text includes the surrounding double quotes.
    try std.testing.expectEqualStrings("\"hello world\"", tokens[0].text);
}

test "lex duration" {
    const allocator = std.testing.allocator;

    // `30 days` → int_literal("30") + kw_days + eof = 3 tokens.
    const tokens = try lexAll("30 days", allocator);
    defer allocator.free(tokens);

    try std.testing.expectEqual(@as(usize, 3), tokens.len);
    try std.testing.expectEqual(TokenKind.int_literal, tokens[0].kind);
    try std.testing.expectEqualStrings("30",           tokens[0].text);
    try std.testing.expectEqual(TokenKind.kw_days,     tokens[1].kind);
    try std.testing.expectEqual(TokenKind.eof,         tokens[2].kind);
}

test "lex annotation" {
    const allocator = std.testing.allocator;

    // `#[parallel]` → hash_sym + lbracket + kw_parallel + rbracket + eof
    const tokens = try lexAll("#[parallel]", allocator);
    defer allocator.free(tokens);

    try std.testing.expectEqual(@as(usize, 5), tokens.len);
    try std.testing.expectEqual(TokenKind.hash_sym,    tokens[0].kind);
    try std.testing.expectEqual(TokenKind.lbracket,    tokens[1].kind);
    try std.testing.expectEqual(TokenKind.kw_parallel, tokens[2].kind);
    try std.testing.expectEqualStrings("parallel",     tokens[2].text);
    try std.testing.expectEqual(TokenKind.rbracket,    tokens[3].kind);
    try std.testing.expectEqual(TokenKind.eof,         tokens[4].kind);
}


