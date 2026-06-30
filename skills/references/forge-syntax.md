# Forge Syntax Reference — Lexer, Parser & Grammar

## Complete Keyword Table (lexer.zig KEYWORDS)

```zig
// Every keyword must appear here AND in the parser's expect() sets.
// Sorted alphabetically for reference; order in StaticStringMap is irrelevant.

pub const KEYWORDS = std.StaticStringMap(TokenKind).initComptime(.{
    // File-level
    .{ "version",         .kw_version       },
    .{ "use",             .kw_use           },
    .{ "define",          .kw_define        },
    .{ "as",              .kw_as            },
    // Top-level declarations
    .{ "contract",        .kw_contract      },
    .{ "asset",           .kw_asset         },
    .{ "interface",       .kw_interface     },
    .{ "record",          .kw_record        },
    .{ "struct",          .kw_struct        },
    .{ "enum",            .kw_enum          },
    .{ "alias",           .kw_alias         },
    .{ "capability",      .kw_capability    },  // novel
    .{ "global",          .kw_global        },
    .{ "invariant",       .kw_invariant     },
    // Contract sections
    .{ "accounts",        .kw_accounts      },
    .{ "authorities",     .kw_authorities   },
    .{ "has",             .kw_has           },
    .{ "config",          .kw_config        },
    .{ "always",          .kw_always        },
    .{ "computed",        .kw_computed      },
    .{ "implements",      .kw_implements    },
    .{ "namespace",       .kw_namespace     },
    .{ "conserves",       .kw_conserves     },  // novel
    .{ "adversary",       .kw_adversary     },  // novel
    .{ "tries",           .kw_tries         },  // novel
    // Function kinds
    .{ "action",          .kw_action        },
    .{ "view",            .kw_view          },
    .{ "pure",            .kw_pure          },
    .{ "hidden",          .kw_hidden        },
    .{ "setup",           .kw_setup         },
    .{ "guard",           .kw_guard         },
    // Access modifiers
    .{ "only",            .kw_only          },
    .{ "shared",          .kw_shared        },
    .{ "sealed",          .kw_sealed        },
    .{ "accepts_value",   .kw_accepts_value },
    // State keywords
    .{ "mine",            .kw_mine          },
    .{ "params",          .kw_params        },
    .{ "known",           .kw_known         },
    // Control flow
    .{ "when",            .kw_when          },
    .{ "otherwise",       .kw_otherwise     },
    .{ "match",           .kw_match         },
    .{ "each",            .kw_each          },
    .{ "in",              .kw_in            },
    .{ "repeat",          .kw_repeat        },
    .{ "times",           .kw_times         },
    .{ "while",           .kw_while         },
    .{ "stop",            .kw_stop          },
    .{ "skip",            .kw_skip          },
    .{ "give",            .kw_give          },
    .{ "back",            .kw_back          },
    .{ "attempt",         .kw_attempt       },
    .{ "on_error",        .kw_on_error      },
    .{ "always_after",    .kw_always_after  },
    // Assertions
    .{ "need",            .kw_need          },
    .{ "ensure",          .kw_ensure        },
    .{ "panic",           .kw_panic         },
    .{ "throw",           .kw_throw         },
    .{ "else",            .kw_else          },
    // Variable binding
    .{ "let",             .kw_let           },
    .{ "is",              .kw_is            },
    .{ "then",            .kw_then          },
    // Operators (word form)
    .{ "plus",            .kw_plus          },
    .{ "minus",           .kw_minus         },
    .{ "times",           .kw_times         }, // overloaded: repeat N times / multiply
    .{ "divided",         .kw_divided       },
    .{ "by",              .kw_by            },
    .{ "mod",             .kw_mod           },
    .{ "equals",          .kw_equals        },
    .{ "and",             .kw_and           },
    .{ "or",              .kw_or            },
    .{ "not",             .kw_not           },
    // Optional / Result
    .{ "nothing",         .kw_nothing       },
    .{ "something",       .kw_something     },
    .{ "empty",           .kw_empty         },
    .{ "unwrap",          .kw_unwrap        },
    .{ "exists",          .kw_exists        },
    .{ "ok",              .kw_ok            },
    .{ "fail",            .kw_fail          },
    // Bool literals
    .{ "yes",             .kw_yes           },
    .{ "no",              .kw_no            },
    // Built-in refs
    .{ "caller",          .kw_caller        },
    .{ "value",           .kw_value         },
    .{ "deployer",        .kw_deployer      },
    .{ "this",            .kw_this          },
    .{ "zero_address",    .kw_zero_address  },
    .{ "now",             .kw_now           },
    .{ "current_block",   .kw_current_block },
    // Account ops
    .{ "owned_by",        .kw_owned_by      },
    .{ "seeded_by",       .kw_seeded_by     },
    .{ "child_of",        .kw_child_of      },
    .{ "readonly",        .kw_readonly      },
    .{ "global",          .kw_global        },  // overloaded with kw_global above
    .{ "linked_to",       .kw_linked_to     },
    .{ "create_if_missing",.kw_create_if_missing },
    .{ "can",             .kw_can           },
    // Authority
    .{ "held_by",         .kw_held_by       },
    .{ "initially",       .kw_initially     },
    .{ "nobody",          .kw_nobody        },
    .{ "with_timelock",   .kw_with_timelock },
    .{ "inheritable",     .kw_inheritable   },
    .{ "covers",          .kw_covers        },
    .{ "any_signer",      .kw_any_signer    },
    // Asset ops
    .{ "send",            .kw_send          },
    .{ "to",              .kw_to            },
    .{ "from",            .kw_from          },
    .{ "pay",             .kw_pay           },
    .{ "receive",         .kw_receive       },
    .{ "move",            .kw_move          },
    .{ "split",           .kw_split         },
    .{ "merge",           .kw_merge         },
    .{ "wrap",            .kw_wrap          },
    .{ "burn",            .kw_burn          },
    .{ "mint",            .kw_mint          },
    // Events / Errors
    .{ "tell",            .kw_tell          },
    .{ "event",           .kw_event         },
    .{ "error",           .kw_error         },
    .{ "indexed",         .kw_indexed       },
    // Lifecycle
    .{ "schedule",        .kw_schedule      },
    .{ "call",            .kw_call          },
    .{ "after",           .kw_after         },
    .{ "block",           .kw_block         },
    .{ "freeze",          .kw_freeze        },
    .{ "unfreeze",        .kw_unfreeze      },
    .{ "close",           .kw_close         },
    .{ "expand",          .kw_expand        },
    .{ "transfer_ownership",.kw_transfer_ownership },
    .{ "upgrade_program", .kw_upgrade_program },
    .{ "upgrade",         .kw_upgrade       },
    // Fallback / Receive
    .{ "fallback",        .kw_fallback      },
    // Complexity annotation
    .{ "complexity",      .kw_complexity    },  // novel
    // Types
    .{ "maybe",           .kw_maybe         },
    .{ "Result",          .kw_result        },
    .{ "Map",             .kw_map           },
    .{ "EnumMap",         .kw_enum_map      },
    .{ "List",            .kw_list          },
    .{ "Set",             .kw_set           },
    .{ "Array",           .kw_array         },
    .{ "Tuple",           .kw_tuple         },
    // Account kinds
    .{ "Wallet",          .kw_t_wallet      },
    .{ "Program",         .kw_t_program     },
    .{ "Data",            .kw_t_data        },
    .{ "Asset",           .kw_t_asset       },
    .{ "Vault",           .kw_t_vault       },
    .{ "Oracle",          .kw_t_oracle      },
    // Authority kinds
    .{ "MintAuthority",   .kw_t_mint_auth   },
    .{ "BurnAuthority",   .kw_t_burn_auth   },
    .{ "FreezeAuthority", .kw_t_freeze_auth },
    .{ "UpgradeAuthority",.kw_t_upgrade_auth },
    .{ "AdminAuthority",  .kw_t_admin_auth  },
    .{ "PauseAuthority",  .kw_t_pause_auth  },
    .{ "FeeAuthority",    .kw_t_fee_auth    },
    .{ "OracleAuthority", .kw_t_oracle_auth },
    .{ "TreasuryAuthority",.kw_t_treasury_auth },
    .{ "GovernanceAuthority",.kw_t_gov_auth },
    // Duration units
    .{ "millisecond",     .kw_ms            },
    .{ "milliseconds",    .kw_ms            },
    .{ "second",          .kw_sec           },
    .{ "seconds",         .kw_sec           },
    .{ "minute",          .kw_min           },
    .{ "minutes",         .kw_min           },
    .{ "hour",            .kw_hour          },
    .{ "hours",           .kw_hour          },
    .{ "day",             .kw_day           },
    .{ "days",            .kw_day           },
    .{ "week",            .kw_week          },
    .{ "weeks",           .kw_week          },
    .{ "month",           .kw_month         },
    .{ "months",          .kw_month         },
    .{ "year",            .kw_year          },
    .{ "years",           .kw_year          },
    // Multisig
    .{ "required",        .kw_required      },
    .{ "signers",         .kw_signers       },
    .{ "time_window",     .kw_time_window   },
    // DAO
    .{ "proposal_threshold",.kw_proposal_threshold },
    .{ "quorum",          .kw_quorum        },
    .{ "voting_period",   .kw_voting_period },
    .{ "execution_delay", .kw_execution_delay },
    // Collect ops
    .{ "sum",             .kw_sum           },  // novel: conservation aggregators
    .{ "count",           .kw_count         },
    .{ "max",             .kw_max           },
    .{ "at_all_times",    .kw_at_all_times  },
    // Adversary (novel)
    .{ "attack",          .kw_attack        },
    .{ "expects",         .kw_expects       },
    .{ "conservation_violated", .kw_conservation_violated },
    .{ "action_blocked",  .kw_action_blocked },
    .{ "invariant_broken",.kw_invariant_broken },
    .{ "during",          .kw_during        },
});
```

## Token Kinds (complete enum)

```zig
pub const TokenKind = enum {
    // Literals
    int_lit,          // 1234 or 1_000_000
    hex_lit,          // 0xDEADBEEF...
    float_lit,        // 1234.56789
    string_lit,       // "hello"
    // Identifiers
    ident,
    // Punctuation
    colon,            // :
    comma,            // ,
    dot,              // .
    dot_dot,          // ..
    arrow,            // →  (U+2192) or ->
    fat_arrow,        // =>
    lparen, rparen,   // ( )
    lbrace, rbrace,   // { }
    lbracket, rbracket, // [ ]
    question,         // ?
    bang,             // !
    at,               // @  (for annotations #[...])
    hash,             // #
    // Operators (symbol form)
    plus_op, minus_op, star_op, slash_op, percent_op,
    eq_eq,            // ==
    bang_eq,          // !=
    lt, gt, lt_eq, gt_eq,
    amp_amp,          // &&
    pipe_pipe,        // ||
    amp,              // &
    pipe,             // |
    caret,            // ^
    tilde,            // ~
    // Assignment
    eq,               // =
    plus_eq, minus_eq, star_eq, slash_eq,   // +=  -=  *=  /=
    // Special
    newline,
    eof,
    // ... all kw_* variants from KEYWORDS above
};
```

## Grammar Summary (EBNF-style)

```
program       = version_decl use_decl* define_decl* top_level_def*
version_decl  = "version" INT_LIT NEWLINE
use_decl      = "use" module_path NEWLINE
module_path   = IDENT ("." IDENT)*
define_decl   = "define" IDENT "as" expr NEWLINE

top_level_def = contract_def | asset_def | interface_def | capability_def | global_inv

contract_def  = "contract" IDENT ":" NEWLINE INDENT contract_body DEDENT
contract_body = accounts_block? authorities_block? implements_clause?
                config_block? always_block? has_block? namespace_decl*
                setup_block? guard_decl* fn_decl* event_decl* error_decl*
                upgrade_block? conserves_block? adversary_block?

has_block     = "has" ":" NEWLINE INDENT state_field+ DEDENT
state_field   = IDENT "is" type_expr ("=" expr)? NEWLINE
              | "in" IDENT ":" NEWLINE INDENT state_field+ DEDENT

accounts_block = "accounts" ":" NEWLINE INDENT account_decl+ DEDENT
account_decl   = IDENT "is" account_kind account_modifier* NEWLINE
account_kind   = "Data" | "Vault" ("[" type_expr "]")? | "Asset" ("[" type_expr "]")?
               | "Oracle" ("[" type_expr "]")? | "Wallet" | "Program"
account_modifier = "owned_by" owner_expr
                 | "seeded_by" "[" seed_elem ("," seed_elem)* "]"
                 | "child_of" IDENT
                 | "readonly" | "global" | "create_if_missing"
                 | "at" expr | "can" ":" can_spec
                 | "linked_to" expr | "size" INT_LIT "bytes"

action_decl   = "#[" annotation "]"* "action" IDENT param_list return_spec? ":"
                NEWLINE INDENT action_body DEDENT
param_list    = "(" (param ("," param)*)? ")"
param         = IDENT "is" type_expr
return_spec   = "gives" type_expr
action_body   = authority_stmt? guard_stmt* stmt+

authority_stmt = "only" authority_ref NEWLINE
authority_ref  = IDENT ("." IDENT)*
               | "[" expr ("," expr)* "]"
               | IDENT "or" IDENT

stmt          = let_stmt | assign_stmt | when_stmt | match_stmt | each_stmt
              | repeat_stmt | while_stmt | need_stmt | ensure_stmt | tell_stmt
              | throw_stmt | panic_stmt | stop_stmt | skip_stmt | give_back_stmt
              | attempt_stmt | call_stmt | send_stmt | pay_stmt | schedule_stmt
              | guard_apply | freeze_stmt | unfreeze_stmt | close_stmt
              | expand_stmt | transfer_own_stmt | upgrade_prog_stmt

let_stmt      = "let" IDENT ("is" type_expr)? "=" expr NEWLINE
assign_stmt   = lvalue ("=" | "+=" | "-=" | "*=" | "/=") expr NEWLINE
lvalue        = IDENT | IDENT "." IDENT | IDENT "[" expr "]" | ...

when_stmt     = "when" expr ":" NEWLINE INDENT stmt+ DEDENT
                ("otherwise" "when" expr ":" NEWLINE INDENT stmt+ DEDENT)*
                ("otherwise" ":" NEWLINE INDENT stmt+ DEDENT)?
match_stmt    = "match" expr ":" NEWLINE INDENT match_arm+ DEDENT
match_arm     = pattern "->" (stmt | NEWLINE INDENT stmt+ DEDENT)
pattern       = IDENT "." IDENT ("{" bind_list "}")? | IDENT | "_"

need_stmt     = "need" expr "else" (string_lit | error_construct) NEWLINE
              | "need" "not" expr "else" (string_lit | error_construct) NEWLINE
tell_stmt     = "tell" IDENT "(" (named_arg | expr) ("," ...)* ")" NEWLINE
named_arg     = IDENT "=" expr

give_back_stmt = "give" "back" expr NEWLINE

each_stmt     = "each" IDENT "in" expr ":" NEWLINE INDENT stmt+ DEDENT
repeat_stmt   = "repeat" expr "times" ":" NEWLINE INDENT stmt+ DEDENT

attempt_stmt  = "attempt" ":" NEWLINE INDENT stmt+ DEDENT
                ("on_error" error_pattern ":" NEWLINE INDENT stmt+ DEDENT)+
error_pattern = IDENT ("(" (IDENT ("," IDENT)*)? ")")? | "_"

send_stmt     = "send" expr "to" expr NEWLINE
pay_stmt      = "pay" expr expr ("from" expr)? NEWLINE

schedule_stmt = "schedule" "call" IDENT "(" args ")" "after" expr NEWLINE

type_expr     = primitive_type | compound_type | IDENT
primitive_type = "u8"|"u16"|"u32"|"u64"|"u128"|"u256"|"uint"
               | "i8"|"i16"|"i32"|"i64"|"i128"|"i256"|"int"
               | "bool"|"Hash"|"Commitment"|"Bytes"|"Bytes32"|"Bytes64"
               | "Signature"|"PublicKey"|"Timestamp"|"Duration"
               | "BlockNumber"|"Epoch"|"Slot"|"String"|"ShortStr"|"Label"
               | "Account"|"Wallet"|"Program"|"System"
               | "price9"|"price18"|"percent"|"Fixed" "[" INT_LIT "]"
compound_type  = "maybe" type_expr
               | "Result" "[" type_expr "," type_expr "]"
               | "Map" "[" type_expr "→" type_expr "]"
               | "List" "[" type_expr "]"
               | "Set" "[" type_expr "]"
               | "Array" "[" type_expr "," INT_LIT "]"
               | "Vault" "[" IDENT "]"
               | "Asset" "[" IDENT "]"
               | "Oracle" "[" type_expr "]"

annotation    = "parallel"
              | "reads" field_path ("," field_path)*
              | "writes" field_path ("," field_path)*
              | "max_iterations" INT_LIT
              | "gas_check"
              | "zk_proof"
              | "private"
              | "gas_sponsored_for" expr

conserves_block = "conserves" ":" NEWLINE INDENT conservation_expr+ DEDENT
conservation_expr = aggregator "(" field_path ")" ("equals"|">="|"<=") expr
                    ("at_all_times")? NEWLINE
aggregator    = "sum" | "count" | "max"

adversary_block = "adversary" "tries" ":" NEWLINE INDENT adversary_attack+ DEDENT
adversary_attack = "attack" IDENT ":" NEWLINE INDENT attack_stmt+ DEDENT
attack_stmt   = "call" IDENT "(" args ")" NEWLINE
              | "during" "action" IDENT ":" NEWLINE INDENT attack_stmt+ DEDENT
              | "expects" adversary_outcome NEWLINE
adversary_outcome = "conservation_violated" | "action_blocked" | "invariant_broken"
```

## Indentation Handling (Forge uses Python-style significant whitespace)

```zig
// In lexer.zig: emit INDENT/DEDENT tokens based on indentation stack
pub const IndentState = struct {
    stack: std.ArrayListUnmanaged(u32) = .{},
    
    pub fn processLine(self: *IndentState, indent: u32,
                       out: *std.ArrayListUnmanaged(Token), alloc: std.mem.Allocator) !void {
        const current = if (self.stack.items.len > 0) self.stack.items[self.stack.items.len - 1] else 0;
        if (indent > current) {
            try self.stack.append(alloc, indent);
            try out.append(alloc, .{ .kind = .indent, .span = .{ .start = 0, .end = 0 } });
        } else if (indent < current) {
            while (self.stack.items.len > 0 and
                   self.stack.items[self.stack.items.len - 1] > indent) {
                _ = self.stack.pop();
                try out.append(alloc, .{ .kind = .dedent, .span = .{ .start = 0, .end = 0 } });
            }
            if (self.stack.items.len > 0 and self.stack.items[self.stack.items.len - 1] != indent)
                return error.IndentationError;
        }
        // equal indent = same block, no token
    }
};
```
