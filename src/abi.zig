// ============================================================================
// Forge Compiler — Dual ABI Generator
// ============================================================================
//
// Produces two ABI representations from the checked AST:
//
//   1. Zephyria Native ABI (.fozabi) — the canonical on-chain format.
//      Carries all ZVM-specific metadata: selectors, access lists,
//      parallel flags, authority declarations, state layout with
//      field IDs, and ZVM-native type names.
//
//   2. EVM Standard ABI (.json) — Ethereum ABI-compatible JSON.
//      Enables existing Ethereum tooling (ethers.js, viem, Foundry)
//      to encode/decode calls to Forge contracts bridged to EVM chains.
//
// SPEC REFERENCE:
//   Part 5  — Contract Anatomy (actions, views, events, errors, setup)
//   Part 9  — Parallel Execution (access lists, parallel flag)
//   Part 4  — Authority System
//   Part 14 — Cross-Chain Interoperability & ABI

const std    = @import("std");
const ast    = @import("ast.zig");
const types  = @import("types.zig");
const errors = @import("errors.zig");
const checker_mod = @import("checker.zig");

const ContractDef     = ast.ContractDef;
const TypeResolver    = types.TypeResolver;
const CheckedContract = checker_mod.CheckedContract;

// ============================================================================
// Section 1 — EVM ABI Structures
// ============================================================================

pub const EVMParam = struct {
    name: []const u8,
    type: []const u8,
};

pub const EVMEntry = struct {
    type:            []const u8,
    name:            []const u8,
    inputs:          []const EVMParam,
    outputs:         []const EVMParam,
    stateMutability: []const u8,
    anonymous:       bool,
};

// ============================================================================
// Section 2 — Zephyria Native ABI Structures
// ============================================================================

pub const ZephParam = struct {
    name:     []const u8,
    type:     []const u8,
    zvm_size: u32,
};

pub const ZephAccessEntry = struct {
    account: []const u8,
    field:   ?[]const u8,
};

pub const ZephAction = struct {
    name:        []const u8,
    selector:    u32,
    visibility:  []const u8,
    is_parallel: bool,
    params:      []const ZephParam,
    returns:     ?ZephParam,
    reads:       []const ZephAccessEntry,
    writes:      []const ZephAccessEntry,
};

pub const ZephView = struct {
    name:       []const u8,
    selector:   u32,
    visibility: []const u8,
    params:     []const ZephParam,
    returns:    ?ZephParam,
};

pub const ZephEventField = struct {
    name:    []const u8,
    type:    []const u8,
    indexed: bool,
};

pub const ZephEvent = struct {
    name:     []const u8,
    selector: u32,
    fields:   []const ZephEventField,
};

pub const ZephErrorField = struct {
    name: []const u8,
    type: []const u8,
};

pub const ZephError = struct {
    name:   []const u8,
    fields: []const ZephErrorField,
};

pub const ZephConstructor = struct {
    params: []const ZephParam,
};

pub const ZephStateField = struct {
    name:      []const u8,
    type:      []const u8,
    field_id:  u32,
    slot_size: u32,
};

pub const ZephAuthority = struct {
    name:   []const u8,
    kind:   []const u8,
    covers: []const []const u8,
};

pub const ZephABI = struct {
    forge_abi_version: []const u8,
    contract:          []const u8,
    spec_version:      u32,
    constructor:       ?ZephConstructor,
    actions:           []const ZephAction,
    views:             []const ZephView,
    events:            []const ZephEvent,
    errors:            []const ZephError,
    state_layout:      []const ZephStateField,
    authorities:       []const ZephAuthority,
    encoding:          []const u8,
};

// ============================================================================
// Section 3 — ABI Generator
// ============================================================================

pub const AbiGenerator = struct {
    allocator: std.mem.Allocator,
    resolver:  *TypeResolver,

    pub fn init(allocator: std.mem.Allocator, resolver: *TypeResolver) AbiGenerator {
        return .{ .allocator = allocator, .resolver = resolver };
    }

    pub fn deinit(_: *AbiGenerator) void {}

    pub fn generateZephAbi(
        self: *AbiGenerator,
        contract: *const ContractDef,
        checked: *const CheckedContract,
    ) anyerror![]u8 {
        var field_ids = std.StringHashMap(u32).init(self.allocator);
        defer field_ids.deinit();
        var next_id: u32 = 0;
        for (contract.state) |sf| {
            const res = try field_ids.getOrPut(sf.name);
            if (!res.found_existing) {
                res.value_ptr.* = next_id;
                next_id += 1;
            }
        }

        // Actions
        var actions_list = std.ArrayListUnmanaged(ZephAction){};
        defer {
            for (actions_list.items) |a| {
                self.allocator.free(a.params);
                self.allocator.free(a.reads);
                self.allocator.free(a.writes);
            }
            actions_list.deinit(self.allocator);
        }

        for (contract.actions) |act| {
            var params = std.ArrayListUnmanaged(ZephParam){};
            errdefer params.deinit(self.allocator);
            for (act.params) |p| {
                const rt = try self.resolver.resolve(p.declared_type);
                try params.append(self.allocator, .{
                    .name     = p.name,
                    .type     = mapZephType(rt),
                    .zvm_size = zvmSize(rt),
                });
            }
            const returns: ?ZephParam = if (act.return_type) |ret| blk: {
                const rt = try self.resolver.resolve(ret);
                if (std.meta.activeTag(rt) == .void_) break :blk null;
                break :blk ZephParam{ .name = "", .type = mapZephType(rt), .zvm_size = zvmSize(rt) };
            } else null;

            var reads  = std.ArrayListUnmanaged(ZephAccessEntry){};
            var writes = std.ArrayListUnmanaged(ZephAccessEntry){};
            errdefer reads.deinit(self.allocator);
            errdefer writes.deinit(self.allocator);

            if (checked.action_lists.get(act.name)) |al| {
                for (al.reads.items)  |e| try reads.append(self.allocator, .{ .account = e.account_name, .field = e.field });
                for (al.writes.items) |e| try writes.append(self.allocator, .{ .account = e.account_name, .field = e.field });
            }

            var is_parallel = false;
            for (act.annotations) |ann| {
                if (ann.kind == .parallel) is_parallel = true;
            }

            try actions_list.append(self.allocator, .{
                .name        = act.name,
                .selector    = actionSelector(act.name),
                .visibility  = visibilityStr(act.visibility),
                .is_parallel = is_parallel,
                .params      = try params.toOwnedSlice(self.allocator),
                .returns     = returns,
                .reads       = try reads.toOwnedSlice(self.allocator),
                .writes      = try writes.toOwnedSlice(self.allocator),
            });
        }

        // Views
        var views_list = std.ArrayListUnmanaged(ZephView){};
        defer { for (views_list.items) |v| self.allocator.free(v.params); views_list.deinit(self.allocator); }

        for (contract.views) |view| {
            var params = std.ArrayListUnmanaged(ZephParam){};
            errdefer params.deinit(self.allocator);
            for (view.params) |p| {
                const rt = try self.resolver.resolve(p.declared_type);
                try params.append(self.allocator, .{ .name = p.name, .type = mapZephType(rt), .zvm_size = zvmSize(rt) });
            }
            const returns: ?ZephParam = if (view.return_type) |ret| blk: {
                const rt = try self.resolver.resolve(ret);
                if (std.meta.activeTag(rt) == .void_) break :blk null;
                break :blk ZephParam{ .name = "", .type = mapZephType(rt), .zvm_size = zvmSize(rt) };
            } else null;
            try views_list.append(self.allocator, .{
                .name       = view.name,
                .selector   = actionSelector(view.name),
                .visibility = visibilityStr(view.visibility),
                .params     = try params.toOwnedSlice(self.allocator),
                .returns    = returns,
            });
        }

        // Events
        var evts = std.ArrayListUnmanaged(ZephEvent){};
        defer { for (evts.items) |e| self.allocator.free(e.fields); evts.deinit(self.allocator); }
        for (contract.events) |ev| {
            var fields = std.ArrayListUnmanaged(ZephEventField){};
            errdefer fields.deinit(self.allocator);
            for (ev.fields) |f| {
                const rt = try self.resolver.resolve(f.type_);
                try fields.append(self.allocator, .{ .name = f.name, .type = mapZephType(rt), .indexed = f.indexed });
            }
            try evts.append(self.allocator, .{ .name = ev.name, .selector = actionSelector(ev.name), .fields = try fields.toOwnedSlice(self.allocator) });
        }

        // Errors
        var errs = std.ArrayListUnmanaged(ZephError){};
        defer { for (errs.items) |e| self.allocator.free(e.fields); errs.deinit(self.allocator); }
        for (contract.errors_) |er| {
            var fields = std.ArrayListUnmanaged(ZephErrorField){};
            errdefer fields.deinit(self.allocator);
            for (er.fields) |f| {
                const rt = try self.resolver.resolve(f.type_);
                try fields.append(self.allocator, .{ .name = f.name, .type = mapZephType(rt) });
            }
            try errs.append(self.allocator, .{ .name = er.name, .fields = try fields.toOwnedSlice(self.allocator) });
        }

        // State layout
        var state_layout = std.ArrayListUnmanaged(ZephStateField){};
        defer state_layout.deinit(self.allocator);
        for (contract.state) |sf| {
            const rt  = try self.resolver.resolve(sf.type_);
            const fid = field_ids.get(sf.name) orelse 0;
            try state_layout.append(self.allocator, .{ .name = sf.name, .type = mapZephType(rt), .field_id = fid, .slot_size = zvmSize(rt) });
        }

        // Authorities
        var auths = std.ArrayListUnmanaged(ZephAuthority){};
        defer auths.deinit(self.allocator);
        for (contract.authorities) |au| {
            try auths.append(self.allocator, .{ .name = au.name, .kind = au.kind, .covers = au.covers });
        }

        // Constructor
        var ctor_params = std.ArrayListUnmanaged(ZephParam){};
        defer ctor_params.deinit(self.allocator);
        const constructor: ?ZephConstructor = if (contract.setup) |setup| blk: {
            for (setup.params) |p| {
                const rt = try self.resolver.resolve(p.declared_type);
                try ctor_params.append(self.allocator, .{ .name = p.name, .type = mapZephType(rt), .zvm_size = zvmSize(rt) });
            }
            break :blk ZephConstructor{ .params = ctor_params.items };
        } else null;

        const abi_doc = ZephABI{
            .forge_abi_version = "1.0",
            .contract          = contract.name,
            .spec_version      = 1,
            .constructor       = constructor,
            .actions           = actions_list.items,
            .views             = views_list.items,
            .events            = evts.items,
            .errors            = errs.items,
            .state_layout      = state_layout.items,
            .authorities       = auths.items,
            .encoding          = "zvm_native_le",
        };

        return try serializeJson(abi_doc, self.allocator);
    }

    pub fn generateEVMAbi(
        self: *AbiGenerator,
        contract: *const ContractDef,
    ) anyerror![]u8 {
        var entries = std.ArrayListUnmanaged(EVMEntry){};
        defer {
            for (entries.items) |e| {
                self.allocator.free(e.inputs);
                self.allocator.free(e.outputs);
            }
            entries.deinit(self.allocator);
        }

        // Constructor
        if (contract.setup) |setup| {
            var inputs = std.ArrayListUnmanaged(EVMParam){};
            errdefer inputs.deinit(self.allocator);
            for (setup.params) |p| {
                const rt = try self.resolver.resolve(p.declared_type);
                try inputs.append(self.allocator, .{ .name = p.name, .type = mapEVMType(rt) });
            }
            try entries.append(self.allocator, .{
                .type = "constructor", .name = "",
                .inputs = try inputs.toOwnedSlice(self.allocator), .outputs = &[_]EVMParam{},
                .stateMutability = "nonpayable", .anonymous = false,
            });
        }

        // Actions
        for (contract.actions) |act| {
            var inputs = std.ArrayListUnmanaged(EVMParam){};
            errdefer inputs.deinit(self.allocator);
            for (act.params) |p| {
                const rt = try self.resolver.resolve(p.declared_type);
                try inputs.append(self.allocator, .{ .name = p.name, .type = mapEVMType(rt) });
            }
            var outputs = std.ArrayListUnmanaged(EVMParam){};
            errdefer outputs.deinit(self.allocator);
            if (act.return_type) |ret| {
                const rt = try self.resolver.resolve(ret);
                if (std.meta.activeTag(rt) != .void_)
                    try outputs.append(self.allocator, .{ .name = "", .type = mapEVMType(rt) });
            }
            try entries.append(self.allocator, .{
                .type = "function", .name = act.name,
                .inputs = try inputs.toOwnedSlice(self.allocator), .outputs = try outputs.toOwnedSlice(self.allocator),
                .stateMutability = "nonpayable", .anonymous = false,
            });
        }

        // Views
        for (contract.views) |view| {
            var inputs = std.ArrayListUnmanaged(EVMParam){};
            errdefer inputs.deinit(self.allocator);
            for (view.params) |p| {
                const rt = try self.resolver.resolve(p.declared_type);
                try inputs.append(self.allocator, .{ .name = p.name, .type = mapEVMType(rt) });
            }
            var outputs = std.ArrayListUnmanaged(EVMParam){};
            errdefer outputs.deinit(self.allocator);
            if (view.return_type) |ret| {
                const rt = try self.resolver.resolve(ret);
                if (std.meta.activeTag(rt) != .void_)
                    try outputs.append(self.allocator, .{ .name = "", .type = mapEVMType(rt) });
            }
            try entries.append(self.allocator, .{
                .type = "function", .name = view.name,
                .inputs = try inputs.toOwnedSlice(self.allocator), .outputs = try outputs.toOwnedSlice(self.allocator),
                .stateMutability = "view", .anonymous = false,
            });
        }

        // Events
        for (contract.events) |ev| {
            var inputs = std.ArrayListUnmanaged(EVMParam){};
            errdefer inputs.deinit(self.allocator);
            for (ev.fields) |f| {
                const rt = try self.resolver.resolve(f.type_);
                try inputs.append(self.allocator, .{ .name = f.name, .type = mapEVMType(rt) });
            }
            try entries.append(self.allocator, .{
                .type = "event", .name = ev.name,
                .inputs = try inputs.toOwnedSlice(self.allocator), .outputs = &[_]EVMParam{},
                .stateMutability = "", .anonymous = false,
            });
        }

        // Errors
        for (contract.errors_) |er| {
            var inputs = std.ArrayListUnmanaged(EVMParam){};
            errdefer inputs.deinit(self.allocator);
            for (er.fields) |f| {
                const rt = try self.resolver.resolve(f.type_);
                try inputs.append(self.allocator, .{ .name = f.name, .type = mapEVMType(rt) });
            }
            try entries.append(self.allocator, .{
                .type = "error", .name = er.name,
                .inputs = try inputs.toOwnedSlice(self.allocator), .outputs = &[_]EVMParam{},
                .stateMutability = "", .anonymous = false,
            });
        }

        return try serializeJson(entries.items, self.allocator);
    }
};

// ============================================================================
// Section 4 — JSON Serialisation (Zig 0.15 correct pattern)
// ============================================================================

// ============================================================================
// Section 4 — JSON Serialisation (manual; no std.json dependency)
// ============================================================================
// std.json.stringify / stringifyAlloc do not exist in Zig 0.15.2.
// We own all the ABI structs, so a comptime-recursive append-based writer
// is simpler, faster, and dependency-free.

/// Serialize `value` to a heap-allocated, caller-owned JSON string.
fn serializeJson(value: anytype, allocator: std.mem.Allocator) anyerror![]u8 {
    var buf = std.ArrayListUnmanaged(u8){};
    errdefer buf.deinit(allocator);
    try jsonAppend(&buf, allocator, value);
    return buf.toOwnedSlice(allocator);
}

/// Recursively append the JSON representation of `value` into `buf`.
fn jsonAppend(buf: *std.ArrayListUnmanaged(u8), alloc: std.mem.Allocator, value: anytype) anyerror!void {
    const T = @TypeOf(value);
    const info = @typeInfo(T);

    switch (info) {
        // ── Boolean ───────────────────────────────────────────────────────
        .bool => {
            try buf.appendSlice(alloc, if (value) "true" else "false");
        },
        // ── Integer (u8, u16, u32, u64, …) ───────────────────────────────
        .int, .comptime_int => {
            const s = try std.fmt.allocPrint(alloc, "{d}", .{value});
            defer alloc.free(s);
            try buf.appendSlice(alloc, s);
        },
        // ── Optional ─────────────────────────────────────────────────────
        .optional => {
            if (value) |inner| {
                try jsonAppend(buf, alloc, inner);
            } else {
                try buf.appendSlice(alloc, "null");
            }
        },
        // ── Pointer ──────────────────────────────────────────────────────
        .pointer => |ptr| {
            if (ptr.size == .slice) {
                if (ptr.child == u8) {
                    // []const u8 → JSON string with basic escaping
                    try buf.append(alloc, '"');
                    for (value) |c| {
                        switch (c) {
                            '"'  => try buf.appendSlice(alloc, "\\\""),
                            '\\' => try buf.appendSlice(alloc, "\\\\"),
                            '\n' => try buf.appendSlice(alloc, "\\n"),
                            '\r' => try buf.appendSlice(alloc, "\\r"),
                            '\t' => try buf.appendSlice(alloc, "\\t"),
                            else => try buf.append(alloc, c),
                        }
                    }
                    try buf.append(alloc, '"');
                } else {
                    // []const T → JSON array
                    try buf.append(alloc, '[');
                    for (value, 0..) |item, i| {
                        if (i > 0) try buf.append(alloc, ',');
                        try buf.appendSlice(alloc, "\n  ");
                        try jsonAppend(buf, alloc, item);
                    }
                    if (value.len > 0) try buf.append(alloc, '\n');
                    try buf.append(alloc, ']');
                }
            } else {
                // Single pointer → dereference
                try jsonAppend(buf, alloc, value.*);
            }
        },
        // ── Struct ───────────────────────────────────────────────────────
        .@"struct" => |s| {
            try buf.append(alloc, '{');
            var first = true;
            inline for (s.fields) |field| {
                if (!first) try buf.append(alloc, ',');
                first = false;
                try buf.append(alloc, '"');
                try buf.appendSlice(alloc, field.name);
                try buf.appendSlice(alloc, "\":");
                try jsonAppend(buf, alloc, @field(value, field.name));
            }
            try buf.append(alloc, '}');
        },
        // ── Anything else → null ─────────────────────────────────────────
        else => {
            try buf.appendSlice(alloc, "null");
        },
    }
}

// ============================================================================
// Section 5 — EVM Type Mapping
// ============================================================================

fn mapEVMType(ty: types.ResolvedType) []const u8 {
    return switch (ty) {
        .u8       => "uint8",
        .u16      => "uint16",
        .u32      => "uint32",
        .u64      => "uint64",
        .u128     => "uint128",
        .u256     => "uint256",
        .i8       => "int8",
        .i16      => "int16",
        .i32      => "int32",
        .i64      => "int64",
        .i128     => "int128",
        .i256     => "int256",
        .fixed_point => "uint256",
        .bool     => "bool",
        .account, .wallet, .program, .system_acc => "address",
        .hash, .commitment => "bytes32",
        .bytes    => "bytes",
        .bytes_n  => "bytes32",
        .signature => "bytes",
        .pubkey   => "bytes",
        .string, .short_str => "string",
        .timestamp, .duration => "uint64",
        .block_number => "uint64",
        .asset    => "address",
        .maybe    => "bytes",
        .list     => "bytes",
        .set      => "bytes",
        .map, .enum_map => "bytes",
        .array    => "bytes",
        .tuple    => "bytes",
        .struct_  => "bytes",
        .enum_    => "uint8",
        .result   => "bytes",
        .linear   => "bytes",
        .void_    => "void",
    };
}

// ============================================================================
// Section 6 — Zephyria Native Type Mapping
// ============================================================================

fn mapZephType(ty: types.ResolvedType) []const u8 {
    return switch (ty) {
        .u8       => "u8",
        .u16      => "u16",
        .u32      => "u32",
        .u64      => "u64",
        .u128     => "u128",
        .u256     => "u256",
        .i8       => "i8",
        .i16      => "i16",
        .i32      => "i32",
        .i64      => "i64",
        .i128     => "i128",
        .i256     => "i256",
        .fixed_point => |d| switch (d) { 4 => "percent", 9 => "price9", 18 => "price18", else => "fixed" },
        .bool       => "bool",
        .account    => "account",
        .wallet     => "wallet",
        .program    => "program",
        .system_acc => "system_acc",
        .hash       => "hash",
        .commitment => "commitment",
        .bytes      => "bytes",
        .bytes_n    => "bytesN",
        .signature  => "signature",
        .pubkey     => "pubkey",
        .string     => "string",
        .short_str  => "short_str",
        .timestamp  => "timestamp",
        .duration   => "duration",
        .block_number => "block_number",
        .asset      => "asset",
        .maybe      => "maybe",
        .map        => "map",
        .enum_map   => "enum_map",
        .list       => "list",
        .set        => "set",
        .array      => "array",
        .tuple      => "tuple",
        .struct_    => |info| info.name,
        .enum_      => |info| info.name,
        .result     => "result",
        .linear     => "linear",
        .void_      => "void",
    };
}

// ============================================================================
// Section 7 — ZVM Encoding Sizes
// ============================================================================

fn zvmSize(ty: types.ResolvedType) u32 {
    return switch (ty) {
        .bool       => 1,
        .u8, .i8   => 1,
        .u16, .i16 => 2,
        .u32, .i32 => 4,
        .u64, .i64 => 8,
        .u128, .i128 => 16,
        .u256, .i256 => 32,
        .fixed_point  => 16,
        .account, .wallet, .program, .system_acc => 32,
        .hash, .commitment => 32,
        .bytes_n    => |n| n,
        .signature  => 96,
        .pubkey     => 48,
        .timestamp, .duration, .block_number => 8,
        .asset      => 32,
        else        => 0,
    };
}

// ============================================================================
// Section 8 — Helpers
// ============================================================================

fn actionSelector(name: []const u8) u32 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(name);
    const digest = hasher.finalResult();
    return std.mem.readInt(u32, digest[0..4], .little);
}

fn visibilityStr(v: ast.Visibility) []const u8 {
    return switch (v) {
        .shared  => "shared",
        .within  => "within",
        .hidden  => "hidden",
        .outside => "outside",
        .system  => "system",
    };
}

// ============================================================================
// Section 9 — Tests
// ============================================================================

test "mapEVMType covers all numeric and address primitives" {
    try std.testing.expectEqualStrings("uint256", mapEVMType(.u256));
    try std.testing.expectEqualStrings("uint8",   mapEVMType(.u8));
    try std.testing.expectEqualStrings("int256",  mapEVMType(.i256));
    try std.testing.expectEqualStrings("bool",    mapEVMType(.bool));
    try std.testing.expectEqualStrings("address", mapEVMType(.wallet));
    try std.testing.expectEqualStrings("address", mapEVMType(.account));
    try std.testing.expectEqualStrings("bytes32", mapEVMType(.hash));
    try std.testing.expectEqualStrings("bytes",   mapEVMType(.bytes));
    try std.testing.expectEqualStrings("string",  mapEVMType(.string));
    try std.testing.expectEqualStrings("uint64",  mapEVMType(.timestamp));
    try std.testing.expectEqualStrings("uint64",  mapEVMType(.duration));
    try std.testing.expectEqualStrings("uint8",   mapEVMType(.{ .enum_ = @constCast(&types.EnumInfo{ .name = "S", .variants = &.{} }) }));
}

test "mapZephType covers all variants including composites" {
    try std.testing.expectEqualStrings("u256",      mapZephType(.u256));
    try std.testing.expectEqualStrings("wallet",    mapZephType(.wallet));
    try std.testing.expectEqualStrings("duration",  mapZephType(.duration));
    try std.testing.expectEqualStrings("signature", mapZephType(.signature));
    try std.testing.expectEqualStrings("pubkey",    mapZephType(.pubkey));
    try std.testing.expectEqualStrings("price9",    mapZephType(.{ .fixed_point = 9 }));
    try std.testing.expectEqualStrings("price18",   mapZephType(.{ .fixed_point = 18 }));
    try std.testing.expectEqualStrings("percent",   mapZephType(.{ .fixed_point = 4 }));
    try std.testing.expectEqualStrings("map",       mapZephType(.{ .map = undefined }));
    try std.testing.expectEqualStrings("list",      mapZephType(.{ .list = undefined }));
    try std.testing.expectEqualStrings("maybe",     mapZephType(.{ .maybe = undefined }));
    try std.testing.expectEqualStrings("linear",    mapZephType(.{ .linear = undefined }));
    try std.testing.expectEqualStrings("void",      mapZephType(.void_));
}

test "zvmSize is correct for all typed primitives" {
    try std.testing.expectEqual(@as(u32, 1),  zvmSize(.u8));
    try std.testing.expectEqual(@as(u32, 8),  zvmSize(.u64));
    try std.testing.expectEqual(@as(u32, 32), zvmSize(.u256));
    try std.testing.expectEqual(@as(u32, 32), zvmSize(.account));
    try std.testing.expectEqual(@as(u32, 96), zvmSize(.signature));
    try std.testing.expectEqual(@as(u32, 48), zvmSize(.pubkey));
    try std.testing.expectEqual(@as(u32, 8),  zvmSize(.timestamp));
    try std.testing.expectEqual(@as(u32, 8),  zvmSize(.duration));
    try std.testing.expectEqual(@as(u32, 0),  zvmSize(.string));
    try std.testing.expectEqual(@as(u32, 0),  zvmSize(.bytes));
    try std.testing.expectEqual(@as(u32, 0),  zvmSize(.{ .list = undefined }));
    try std.testing.expectEqual(@as(u32, 0),  zvmSize(.void_));
}

test "actionSelector is deterministic and non-zero" {
    const s1 = actionSelector("transfer");
    const s2 = actionSelector("transfer");
    const s3 = actionSelector("withdraw");
    try std.testing.expectEqual(s1, s2);
    try std.testing.expect(s1 != s3);
    try std.testing.expect(s1 != 0);
    for ([_][]const u8{ "transfer", "mint", "burn", "setup", "init" }) |n|
        try std.testing.expect(actionSelector(n) != 0);
}

test "visibilityStr covers all variants" {
    try std.testing.expectEqualStrings("shared",  visibilityStr(.shared));
    try std.testing.expectEqualStrings("within",  visibilityStr(.within));
    try std.testing.expectEqualStrings("hidden",  visibilityStr(.hidden));
    try std.testing.expectEqualStrings("outside", visibilityStr(.outside));
    try std.testing.expectEqualStrings("system",  visibilityStr(.system));
}

test "serializeJson produces valid JSON" {
    const allocator = std.testing.allocator;
    const obj = struct { name: []const u8, value: u32 }{ .name = "test", .value = 42 };
    const json = try serializeJson(obj, allocator);
    defer allocator.free(json);
    try std.testing.expect(json.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "42") != null);
}

test "generateZephAbi and generateEVMAbi minimal contract" {
    const allocator = std.testing.allocator;
    var diag = errors.DiagnosticList.init(allocator);
    defer diag.deinit();
    var resolver = types.TypeResolver.init(allocator, &diag);
    defer resolver.deinit();
    var gen = AbiGenerator.init(allocator, &resolver);
    defer gen.deinit();

    const contract = ContractDef{
        .name = "Minimal", .inherits = null, .implements = &.{},
        .accounts = &.{}, .authorities = &.{}, .config = &.{}, .always = &.{},
        .state = &.{}, .computed = &.{}, .setup = null, .guards = &.{},
        .actions = &.{}, .views = &.{}, .pures = &.{}, .helpers = &.{},
        .events = &.{}, .errors_ = &.{}, .upgrade = null, .namespaces = &.{},
        .invariants = &.{}, .span = .{ .line = 1, .col = 1, .len = 0 },
    };
    var checked = checker_mod.CheckedContract{
        .name = "Minimal",
        .action_lists = std.StringHashMap(checker_mod.AccessList).init(allocator),
        .type_map = std.StringHashMap(types.ResolvedType).init(allocator),
        .scope = types.SymbolTable.init(allocator, null),
        .allocator = allocator,
    };
    defer checked.deinit();

    const zeph = try gen.generateZephAbi(&contract, &checked);
    defer allocator.free(zeph);
    try std.testing.expect(zeph.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, zeph, "Minimal") != null);
    try std.testing.expect(std.mem.indexOf(u8, zeph, "forge_abi_version") != null);
    try std.testing.expect(std.mem.indexOf(u8, zeph, "zvm_native_le") != null);

    const evm = try gen.generateEVMAbi(&contract);
    defer allocator.free(evm);
    try std.testing.expect(evm.len > 0);
    try std.testing.expect(evm[0] == '[');
}
