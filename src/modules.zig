const std = @import("std");
const types = @import("types.zig");
const ResolvedType = types.ResolvedType;
const TypeResolver = types.TypeResolver;

/// Lightweight representation of a module function parameter's type.
/// Uses only non-pointer variants of ResolvedType (no maybe, list, map, etc.)
/// to allow compile-time construction without heap allocation.
pub const ModuleParamType = enum(u8) {
    u8,
    u16,
    u32,
    u64,
    u128,
    u256,
    i8,
    i16,
    i32,
    i64,
    i128,
    i256,
    bool,
    account,
    wallet,
    program,
    system_acc,
    hash,
    signature,
    pubkey,
    bytes,
    bytes32,
    commitment,
    timestamp,
    duration,
    block_number,
    string,
    short_str,
    void_,
    fixed4, // Fixed[4] — percent
    fixed18, // Fixed[18] — price18
};

/// Convert a ModuleParamType to a ResolvedType.
pub fn toResolvedType(mpt: ModuleParamType) ResolvedType {
    return switch (mpt) {
        .u8 => .u8,
        .u16 => .u16,
        .u32 => .u32,
        .u64 => .u64,
        .u128 => .u128,
        .u256 => .u256,
        .i8 => .i8,
        .i16 => .i16,
        .i32 => .i32,
        .i64 => .i64,
        .i128 => .i128,
        .i256 => .i256,
        .bool => .bool,
        .account => .account,
        .wallet => .wallet,
        .program => .program,
        .system_acc => .system_acc,
        .hash => .hash,
        .signature => .signature,
        .pubkey => .pubkey,
        .bytes => .bytes,
        .bytes32 => .{ .bytes_n = 32 },
        .commitment => .commitment,
        .timestamp => .timestamp,
        .duration => .duration,
        .block_number => .block_number,
        .string => .string,
        .short_str => .short_str,
        .void_ => .void_,
        .fixed4 => .{ .fixed_point = 4 },
        .fixed18 => .{ .fixed_point = 18 },
    };
}

/// Metadata for a single parameter in a module function.
pub const ModuleParam = struct {
    name: []const u8,
    type_: ModuleParamType,
};

/// Metadata for a function exported by a module.
pub const ModuleFn = struct {
    name: []const u8,
    params: []const ModuleParam,
    return_type: ModuleParamType,
};

/// An export from a module (function, constant, type, interface, event).
pub const ModuleExport = union(enum) {
    function: ModuleFn,
    interface: void,
    event: void,
};

/// Descriptor for a built-in standard library module.
pub const Module = struct {
    name: []const u8,
    exports: []const ModuleExport,
};

/// Resolve a module path like ["std", "math"] to a module descriptor.
/// Returns null if the path does not resolve to a known module.
pub fn resolveBuiltin(path: []const []const u8) ?Module {
    if (path.len < 2) return null;
    if (!std.mem.eql(u8, path[0], "std")) return null;
    const name = path[1];
    for (builtin_modules) |m| {
        if (std.mem.eql(u8, m.name, name)) return m;
    }
    return null;
}

/// All built-in standard library modules.
pub const builtin_modules: []const Module = &.{
    std_math,
    std_access,
    std_crypto,
    std_tokens,
    std_governance,
    std_oracle,
    std_strings,
    std_arrays,
};

// ============================================================================
// std.math — SafeMath, fixed-point math, compound interest, sqrt
// ============================================================================

const std_math = Module{
    .name = "math",
    .exports = &.{
        .{ .function = .{
            .name = "sqrt",
            .params = &.{ .{ .name = "value", .type_ = .u256 } },
            .return_type = .u256,
        } },
        .{ .function = .{
            .name = "compound",
            .params = &.{
                .{ .name = "principal", .type_ = .u256 },
                .{ .name = "rate", .type_ = .fixed4 },
                .{ .name = "periods", .type_ = .u64 },
            },
            .return_type = .u256,
        } },
        .{ .function = .{
            .name = "pow",
            .params = &.{ .{ .name = "base", .type_ = .u256 }, .{ .name = "exponent", .type_ = .u256 } },
            .return_type = .u256,
        } },
        .{ .function = .{
            .name = "min",
            .params = &.{ .{ .name = "a", .type_ = .u256 }, .{ .name = "b", .type_ = .u256 } },
            .return_type = .u256,
        } },
        .{ .function = .{
            .name = "max",
            .params = &.{ .{ .name = "a", .type_ = .u256 }, .{ .name = "b", .type_ = .u256 } },
            .return_type = .u256,
        } },
        .{ .function = .{
            .name = "abs",
            .params = &.{ .{ .name = "value", .type_ = .i256 } },
            .return_type = .i256,
        } },
    },
};

// ============================================================================
// std.access — RBAC (Role-Based Access Control) helpers
// ============================================================================

const std_access = Module{
    .name = "access",
    .exports = &.{
        .{ .interface = {} },
        .{ .event = {} },
        .{ .function = .{
            .name = "grant",
            .params = &.{ .{ .name = "role", .type_ = .short_str }, .{ .name = "account", .type_ = .account } },
            .return_type = .void_,
        } },
        .{ .function = .{
            .name = "revoke",
            .params = &.{ .{ .name = "role", .type_ = .short_str }, .{ .name = "account", .type_ = .account } },
            .return_type = .void_,
        } },
        .{ .function = .{
            .name = "has_role",
            .params = &.{ .{ .name = "role", .type_ = .short_str }, .{ .name = "account", .type_ = .account } },
            .return_type = .bool,
        } },
    },
};

// ============================================================================
// std.crypto — Hash, sign, verify (keccak, BLS, Merkle)
// ============================================================================

const std_crypto = Module{
    .name = "crypto",
    .exports = &.{
        .{ .function = .{
            .name = "keccak",
            .params = &.{ .{ .name = "a", .type_ = .hash }, .{ .name = "b", .type_ = .hash } },
            .return_type = .hash,
        } },
        .{ .function = .{
            .name = "bls_verify",
            .params = &.{ .{ .name = "message", .type_ = .hash }, .{ .name = "signature", .type_ = .signature }, .{ .name = "pubkey", .type_ = .pubkey } },
            .return_type = .bool,
        } },
        .{ .function = .{
            .name = "merkle_verify",
            .params = &.{ .{ .name = "leaf", .type_ = .hash }, .{ .name = "proof", .type_ = .hash }, .{ .name = "root", .type_ = .hash } },
            .return_type = .bool,
        } },
        .{ .function = .{
            .name = "sha256",
            .params = &.{ .{ .name = "data", .type_ = .bytes } },
            .return_type = .bytes32,
        } },
    },
};

// ============================================================================
// std.tokens — Token helpers (ERC20-equivalent)
// ============================================================================

const std_tokens = Module{
    .name = "tokens",
    .exports = &.{
        .{ .function = .{
            .name = "transfer",
            .params = &.{ .{ .name = "from", .type_ = .account }, .{ .name = "to", .type_ = .account }, .{ .name = "amount", .type_ = .u256 } },
            .return_type = .void_,
        } },
        .{ .function = .{
            .name = "transfer_from",
            .params = &.{ .{ .name = "sender", .type_ = .account }, .{ .name = "from", .type_ = .account }, .{ .name = "to", .type_ = .account }, .{ .name = "amount", .type_ = .u256 } },
            .return_type = .void_,
        } },
        .{ .function = .{
            .name = "approve",
            .params = &.{ .{ .name = "spender", .type_ = .account }, .{ .name = "amount", .type_ = .u256 } },
            .return_type = .void_,
        } },
        .{ .function = .{
            .name = "balance_of",
            .params = &.{ .{ .name = "account", .type_ = .account } },
            .return_type = .u256,
        } },
        .{ .function = .{
            .name = "allowance",
            .params = &.{ .{ .name = "owner", .type_ = .account }, .{ .name = "spender", .type_ = .account } },
            .return_type = .u256,
        } },
    },
};

// ============================================================================
// std.governance — Voting and governance primitives
// ============================================================================

const std_governance = Module{
    .name = "governance",
    .exports = &.{
        .{ .function = .{
            .name = "create_proposal",
            .params = &.{ .{ .name = "target", .type_ = .program }, .{ .name = "calldata", .type_ = .bytes }, .{ .name = "description", .type_ = .string } },
            .return_type = .u64,
        } },
        .{ .function = .{
            .name = "cast_vote",
            .params = &.{ .{ .name = "proposal_id", .type_ = .u64 }, .{ .name = "in_favor", .type_ = .bool }, .{ .name = "votes", .type_ = .u256 } },
            .return_type = .void_,
        } },
        .{ .function = .{
            .name = "execute_proposal",
            .params = &.{ .{ .name = "proposal_id", .type_ = .u64 } },
            .return_type = .void_,
        } },
        .{ .function = .{
            .name = "get_vote_count",
            .params = &.{ .{ .name = "proposal_id", .type_ = .u64 } },
            .return_type = .u256,
        } },
    },
};

// ============================================================================
// std.oracle — Price feed helpers
// ============================================================================

const std_oracle = Module{
    .name = "oracle",
    .exports = &.{
        .{ .function = .{
            .name = "get_price",
            .params = &.{ .{ .name = "feed", .type_ = .account } },
            .return_type = .fixed18,
        } },
        .{ .function = .{
            .name = "get_price_at",
            .params = &.{ .{ .name = "feed", .type_ = .account }, .{ .name = "timestamp", .type_ = .timestamp } },
            .return_type = .fixed18,
        } },
        .{ .function = .{
            .name = "is_stale",
            .params = &.{ .{ .name = "feed", .type_ = .account } },
            .return_type = .bool,
        } },
    },
};

// ============================================================================
// std.strings — String manipulation utilities
// ============================================================================

const std_strings = Module{
    .name = "strings",
    .exports = &.{
        .{ .function = .{
            .name = "concat",
            .params = &.{ .{ .name = "a", .type_ = .string }, .{ .name = "b", .type_ = .string } },
            .return_type = .string,
        } },
        .{ .function = .{
            .name = "substring",
            .params = &.{ .{ .name = "s", .type_ = .string }, .{ .name = "start", .type_ = .u64 }, .{ .name = "end", .type_ = .u64 } },
            .return_type = .string,
        } },
        .{ .function = .{
            .name = "contains",
            .params = &.{ .{ .name = "s", .type_ = .string }, .{ .name = "substr", .type_ = .string } },
            .return_type = .bool,
        } },
        .{ .function = .{
            .name = "to_upper",
            .params = &.{ .{ .name = "s", .type_ = .string } },
            .return_type = .string,
        } },
        .{ .function = .{
            .name = "to_lower",
            .params = &.{ .{ .name = "s", .type_ = .string } },
            .return_type = .string,
        } },
    },
};

// ============================================================================
// std.arrays — Collection utilities
// ============================================================================

const std_arrays = Module{
    .name = "arrays",
    .exports = &.{
        .{ .function = .{
            .name = "sort",
            .params = &.{ .{ .name = "arr", .type_ = .hash } },
            .return_type = .void_,
        } },
        .{ .function = .{
            .name = "reverse",
            .params = &.{ .{ .name = "arr", .type_ = .hash } },
            .return_type = .void_,
        } },
    },
};

test "resolve builtin modules" {
    try std.testing.expect(resolveBuiltin(&.{ "std", "math" }) != null);
    try std.testing.expect(resolveBuiltin(&.{ "std", "crypto" }) != null);
    try std.testing.expect(resolveBuiltin(&.{ "std", "access" }) != null);
    try std.testing.expect(resolveBuiltin(&.{ "std", "unknown" }) == null);
}

test "math module exports" {
    const math = resolveBuiltin(&.{ "std", "math" }) orelse unreachable;
    var found_sqrt = false;
    var found_compound = false;
    for (math.exports) |exp| {
        if (exp == .function) {
            if (std.mem.eql(u8, exp.function.name, "sqrt")) {
                try std.testing.expectEqual(.u256, exp.function.params[0].type_);
                try std.testing.expectEqual(.u256, exp.function.return_type);
                found_sqrt = true;
            }
            if (std.mem.eql(u8, exp.function.name, "compound")) {
                try std.testing.expectEqual(.u256, exp.function.params[0].type_);
                try std.testing.expectEqual(.fixed4, exp.function.params[1].type_);
                try std.testing.expectEqual(.u64, exp.function.params[2].type_);
                try std.testing.expectEqual(.u256, exp.function.return_type);
                found_compound = true;
            }
        }
    }
    try std.testing.expect(found_sqrt);
    try std.testing.expect(found_compound);
}

test "toResolvedType roundtrip" {
    try std.testing.expectEqual(ResolvedType.u256, toResolvedType(.u256));
    try std.testing.expectEqual(ResolvedType.bool, toResolvedType(.bool));
    try std.testing.expectEqual(ResolvedType.hash, toResolvedType(.hash));
    try std.testing.expectEqual(@as(ResolvedType, .{ .fixed_point = 4 }), toResolvedType(.fixed4));
    try std.testing.expectEqual(@as(ResolvedType, .{ .fixed_point = 18 }), toResolvedType(.fixed18));
    try std.testing.expectEqual(@as(ResolvedType, .{ .bytes_n = 32 }), toResolvedType(.bytes32));
}
