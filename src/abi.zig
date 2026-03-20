// ============================================================================
// Forge Compiler — Dual-Chain ABI Generator
// ============================================================================
//
// Extracts both Zephyria Native ABI (.fozabi) and EVM Standard ABI (.json)
// from the checked AST, enabling cross-chain interaction with Ethereum standard
// tools and retaining Zephyria-specific optimization metadata.
//
// SPEC: Part 14 — Cross-Chain Interoperability & ABI
//

const std = @import("std");
const ast = @import("ast.zig");
const types = @import("types.zig");

const ContractDef = ast.ContractDef;

// ── JSON Formats ────────────────────────────────────────────────────────────

pub const EVMParam = struct {
    name: []const u8,
    type: []const u8,
};

pub const EVMMethod = struct {
    type: []const u8,
    name: []const u8,
    inputs: []const EVMParam,
    outputs: []const EVMParam,
    stateMutability: []const u8,
};

pub const ZephParam = struct {
    name: []const u8,
    type: []const u8,
};

pub const ZephMethod = struct {
    type: []const u8,
    name: []const u8,
    selector: u32,
    inputs: []const ZephParam,
    outputs: []const ZephParam,
    is_parallel: bool,
};

pub const ZephABI = struct {
    name: []const u8,
    methods: []const ZephMethod,
};

// ── ABI Generator ───────────────────────────────────────────────────────────

pub const AbiGenerator = struct {
    allocator: std.mem.Allocator,
    resolver: *types.TypeResolver,

    pub fn init(allocator: std.mem.Allocator, resolver: *types.TypeResolver) AbiGenerator {
        return .{
            .allocator = allocator,
            .resolver = resolver,
        };
    }

    pub fn deinit(self: *AbiGenerator) void {
        _ = self;
    }

    /// Generates the standard EVM JSON representation.
    pub fn generateEVMAbi(self: *AbiGenerator, contract: *const ContractDef) anyerror![]u8 {
        var methods: std.ArrayList(EVMMethod) = .empty;
        defer {
            for (methods.items) |m| {
                self.allocator.free(m.inputs);
                self.allocator.free(m.outputs);
            }
            methods.deinit(self.allocator);
        }

        for (contract.actions) |act| {
            var inputs: std.ArrayList(EVMParam) = .empty;
            errdefer inputs.deinit(self.allocator);
            
            for (act.params) |p| {
                const rt = try self.resolver.resolve(p.declared_type);
                try inputs.append(self.allocator, .{
                    .name = p.name,
                    .type = mapEVMType(rt),
                });
            }

            var outputs: std.ArrayList(EVMParam) = .empty;
            errdefer outputs.deinit(self.allocator);
            if (act.return_type) |ret| {
                const rt = try self.resolver.resolve(ret);
                if (std.meta.activeTag(rt) != .void_) {
                    try outputs.append(self.allocator, .{
                        .name = "",
                        .type = mapEVMType(rt),
                    });
                }
            }

            try methods.append(self.allocator, .{
                .type = "function",
                .name = act.name,
                .inputs = try inputs.toOwnedSlice(self.allocator),
                .outputs = try outputs.toOwnedSlice(self.allocator),
                .stateMutability = "nonpayable",
            });
        }

        for (contract.views) |view| {
            var inputs: std.ArrayList(EVMParam) = .empty;
            errdefer inputs.deinit(self.allocator);
            
            for (view.params) |p| {
                const rt = try self.resolver.resolve(p.declared_type);
                try inputs.append(self.allocator, .{
                    .name = p.name,
                    .type = mapEVMType(rt),
                });
            }

            var outputs: std.ArrayList(EVMParam) = .empty;
            errdefer outputs.deinit(self.allocator);
            if (view.return_type) |ret| {
                const rt = try self.resolver.resolve(ret);
                if (std.meta.activeTag(rt) != .void_) {
                    try outputs.append(self.allocator, .{
                        .name = "",
                        .type = mapEVMType(rt),
                    });
                }
            }

            try methods.append(self.allocator, .{
                .type = "function",
                .name = view.name,
                .inputs = try inputs.toOwnedSlice(self.allocator),
                .outputs = try outputs.toOwnedSlice(self.allocator),
                .stateMutability = "view",
            });
        }

        var out = std.io.Writer.Allocating.init(self.allocator);
        defer out.deinit();
        try std.json.Stringify.value(methods.items, .{ .whitespace = .indent_2 }, &out.writer);

        return try self.allocator.dupe(u8, out.written());
    }

    /// Generates the zephyria custom JSON ABI representation.
    pub fn generateZephAbi(self: *AbiGenerator, contract: *const ContractDef) anyerror![]u8 {
        var methods: std.ArrayList(ZephMethod) = .empty;
        defer {
            for (methods.items) |m| {
                self.allocator.free(m.inputs);
                self.allocator.free(m.outputs);
            }
            methods.deinit(self.allocator);
        }

        for (contract.actions) |act| {
            var inputs: std.ArrayList(ZephParam) = .empty;
            errdefer inputs.deinit(self.allocator);
            
            for (act.params) |p| {
                const rt = try self.resolver.resolve(p.declared_type);
                try inputs.append(self.allocator, .{
                    .name = p.name,
                    .type = mapZephTypeString(rt),
                });
            }

            var outputs: std.ArrayList(ZephParam) = .empty;
            errdefer outputs.deinit(self.allocator);
            if (act.return_type) |ret| {
                const rt = try self.resolver.resolve(ret);
                if (std.meta.activeTag(rt) != .void_) {
                    try outputs.append(self.allocator, .{
                        .name = "",
                        .type = mapZephTypeString(rt),
                    });
                }
            }

            var is_parallel = false;
            for (act.annotations) |ann| {
                if (ann.kind == .parallel) is_parallel = true;
            }

            try methods.append(self.allocator, .{
                .type = "action",
                .name = act.name,
                .selector = actionSelector(act.name),
                .inputs = try inputs.toOwnedSlice(self.allocator),
                .outputs = try outputs.toOwnedSlice(self.allocator),
                .is_parallel = is_parallel,
            });
        }

        for (contract.views) |view| {
            var inputs: std.ArrayList(ZephParam) = .empty;
            errdefer inputs.deinit(self.allocator);
            
            for (view.params) |p| {
                const rt = try self.resolver.resolve(p.declared_type);
                try inputs.append(self.allocator, .{
                    .name = p.name,
                    .type = mapZephTypeString(rt),
                });
            }

            var outputs: std.ArrayList(ZephParam) = .empty;
            errdefer outputs.deinit(self.allocator);
            if (view.return_type) |ret| {
                const rt = try self.resolver.resolve(ret);
                if (std.meta.activeTag(rt) != .void_) {
                    try outputs.append(self.allocator, .{
                        .name = "",
                        .type = mapZephTypeString(rt),
                    });
                }
            }

            try methods.append(self.allocator, .{
                .type = "view",
                .name = view.name,
                .selector = actionSelector(view.name),
                .inputs = try inputs.toOwnedSlice(self.allocator),
                .outputs = try outputs.toOwnedSlice(self.allocator),
                .is_parallel = true,
            });
        }

        const abi_data = ZephABI{
            .name = contract.name,
            .methods = try methods.toOwnedSlice(self.allocator),
        };
        defer self.allocator.free(abi_data.methods);

        var out = std.io.Writer.Allocating.init(self.allocator);
        defer out.deinit();
        try std.json.Stringify.value(abi_data, .{ .whitespace = .indent_2 }, &out.writer);

        return try self.allocator.dupe(u8, out.written());
    }
};

// ── Type Mapping Helpers ────────────────────────────────────────────────────

fn mapEVMType(ty: types.ResolvedType) []const u8 {
    return switch (ty) {
        .u8 => "uint8",
        .u16 => "uint16",
        .u32 => "uint32",
        .u64 => "uint64",
        .u128 => "uint128",
        .u256 => "uint256",
        .i8 => "int8",
        .i16 => "int16",
        .i32 => "int32",
        .i64 => "int64",
        .i128 => "int128",
        .i256 => "int256",
        .bool => "bool",
        .account, .wallet, .program, .system_acc => "address",
        .hash, .commitment => "bytes32",
        .bytes => "bytes",
        .bytes_n => "bytes32",
        .string, .short_str => "string",
        .timestamp => "uint64",
        .block_number => "uint32",
        .asset => "address",
        .fixed_point => "uint256",
        else => "bytes",
    };
}

fn mapZephTypeString(ty: types.ResolvedType) []const u8 {
    return switch (ty) {
        .u8 => "u8",
        .u16 => "u16",
        .u32 => "u32",
        .u64 => "u64",
        .u128 => "u128",
        .u256 => "u256",
        .i8 => "i8",
        .i16 => "i16",
        .i32 => "i32",
        .i64 => "i64",
        .i128 => "i128",
        .i256 => "i256",
        .bool => "bool",
        .account => "account",
        .wallet => "wallet",
        .program => "program",
        .system_acc => "system_acc",
        .hash => "hash",
        .commitment => "commitment",
        .bytes => "bytes",
        .bytes_n => "bytesN",
        .string => "string",
        .short_str => "short_str",
        .timestamp => "timestamp",
        .block_number => "block_number",
        .asset => "asset",
        .fixed_point => "fixed",
        .void_ => "void",
        else => "complex",
    };
}

fn actionSelector(name: []const u8) u32 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(name);
    const digest = hasher.finalResult();
    return std.mem.readInt(u32, digest[0..4], .little);
}

// ── Tests ───────────────────────────────────────────────────────────────────

test "ABI mappings and basic structure" {
    const allocator = std.testing.allocator;

    try std.testing.expectEqualStrings("uint256", mapEVMType(.u256));
    try std.testing.expectEqualStrings("address", mapEVMType(.wallet));
    try std.testing.expectEqualStrings("bytes32", mapEVMType(.hash));

    try std.testing.expectEqualStrings("u256", mapZephTypeString(.u256));
    try std.testing.expectEqualStrings("wallet", mapZephTypeString(.wallet));

    const selector = actionSelector("transfer");
    try std.testing.expect(selector != 0);

    const errors_mod = @import("errors.zig");
    var diagnostics = errors_mod.DiagnosticList.init(allocator);
    defer diagnostics.deinit();

    var resolver = types.TypeResolver.init(allocator, &diagnostics);
    defer resolver.deinit();

    var generator = AbiGenerator.init(allocator, &resolver);
    defer generator.deinit();
}
