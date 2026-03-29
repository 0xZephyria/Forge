// ============================================================================
// Forge Compiler — Type System Engine
// ============================================================================
//
// Resolves TypeExpr nodes to concrete types, performs type inference,
// type compatibility checking, and builds the symbol table.
//
// SPEC REFERENCE: Part 2 (All Types), Part 2.9 (Generics), Part 2.12 (Aliases)
//
// This is a library file. No main() function is present.

const std = @import("std");
const ast = @import("ast.zig");
const errors = @import("errors.zig");

const TypeExpr = ast.TypeExpr;
const Span = ast.Span;
const TopLevel = ast.TopLevel;
const Expr = ast.Expr;
const ExprKind = ast.ExprKind;
const BinOp = ast.BinOp;
const UnaryOp = ast.UnaryOp;
const DiagnosticList = errors.DiagnosticList;
const CompileError = errors.CompileError;

// ============================================================================
// Section 1 — Resolved Type
// ============================================================================

/// A concrete, fully-resolved type produced after resolving a `TypeExpr`.
/// All named references (aliases, generics) have been expanded.
pub const ResolvedType = union(enum) {
    // ── Unsigned integers ─────────────────────────────────────────────────
    u8,
    u16,
    u32,
    u64,
    u128,
    u256,
    // ── Signed integers ───────────────────────────────────────────────────
    i8,
    i16,
    i32,
    i64,
    i128,
    i256,
    // ── Fixed-point ───────────────────────────────────────────────────────
    /// Fixed-point with N decimal places.
    fixed_point: u8,
    // ── Boolean ───────────────────────────────────────────────────────────
    bool,
    // ── Address types ─────────────────────────────────────────────────────
    account,
    wallet,
    program,
    system_acc,
    // ── Hash / byte types ─────────────────────────────────────────────────
    hash,
    commitment,
    bytes,
    bytes_n: u32,
    signature,
    pubkey,
    // ── Time types ────────────────────────────────────────────────────────
    timestamp,
    duration,
    block_number,
    // ── Text types ────────────────────────────────────────────────────────
    string,
    short_str,
    // ── Composite types ───────────────────────────────────────────────────
    /// `maybe T` — optional value.
    maybe: *ResolvedType,
    /// `Result[T, E]` — success or typed failure.
    result: struct { ok: *ResolvedType, err: *ResolvedType },
    /// `Map[K → V]`.
    map: struct { key: *ResolvedType, value: *ResolvedType },
    /// `EnumMap[K → V]` — iterable map.
    enum_map: struct { key: *ResolvedType, value: *ResolvedType },
    /// `List[T]`.
    list: *ResolvedType,
    /// `Set[T]`.
    set: *ResolvedType,
    /// `Array[T, N]` — fixed-length array.
    array: struct { elem: *ResolvedType, size: u64 },
    /// Unnamed tuple `(T1, T2, ...)`.
    tuple: []*ResolvedType,
    // ── User-defined types ────────────────────────────────────────────────
    /// A resolved struct type.
    struct_: *StructInfo,
    /// A resolved enum type.
    enum_: *EnumInfo,
    // ── Asset types ───────────────────────────────────────────────────────
    /// A declared asset, identified by name.
    asset: []const u8,
    // ── Void ──────────────────────────────────────────────────────────────
    void_,
    // ── Linear types (for asset tracking) ─────────────────────────────────
    /// Wraps an asset type for linear (move-only) semantics.
    linear: *ResolvedType,
    // ── Capability types (Novel Idea 6) ───────────────────────────────────
    /// SPEC: Novel Idea 6 — Capability Token Types (Structural Authority).
    /// A resolved capability type, always linear. Identified by definition name.
    capability: []const u8,
    // ── ZK / Privacy ──────────────────────────────────────────────────────
    /// `Proof[T]` — ZK Proof payload mapped to parametric assertion type.
    proof: *ResolvedType,
};

// ============================================================================
// Section 2 — Struct and Enum Info
// ============================================================================

/// Metadata for a resolved struct type.
pub const StructInfo = struct {
    name: []const u8,
    fields: []ResolvedField,
};

/// A single resolved field within a struct or enum variant.
pub const ResolvedField = struct {
    name: []const u8,
    type_: ResolvedType,
};

/// Metadata for a resolved enum type.
pub const EnumInfo = struct {
    name: []const u8,
    variants: []EnumVariantInfo,
};

/// A single variant within a resolved enum.
pub const EnumVariantInfo = struct {
    name: []const u8,
    fields: []ResolvedField,
};

// ============================================================================
// Section 3 — Symbol Table
// ============================================================================

/// Classifies the kind of a declared symbol.
pub const SymbolKind = enum {
    local_var,
    state_field,
    constant,
    parameter,
    action,
    view,
    pure_fn,
    guard,
    event,
    error_decl,
    authority,
    account,
    type_alias,
    struct_type,
    enum_type,
    asset,
};

/// A single symbol recorded in the symbol table.
pub const Symbol = struct {
    name: []const u8,
    kind: SymbolKind,
    type_: ResolvedType,
    span: Span,
    mutable: bool,
    is_private: bool = false,
};

/// A hierarchical symbol table with parent-chain lookup.
pub const SymbolTable = struct {
    parent: ?*SymbolTable,
    symbols: std.StringHashMap(Symbol),
    allocator: std.mem.Allocator,

    /// Create a new scope, optionally chained to a parent.
    pub fn init(allocator: std.mem.Allocator, parent: ?*SymbolTable) SymbolTable {
        return .{
            .parent = parent,
            .symbols = std.StringHashMap(Symbol).init(allocator),
            .allocator = allocator,
        };
    }

    /// Release all resources held by this scope.
    pub fn deinit(self: *SymbolTable) void {
        self.symbols.deinit();
    }

    /// Define a new symbol in this scope. Errors on duplicate.
    pub fn define(self: *SymbolTable, name: []const u8, sym: Symbol) anyerror!void {
        const result = try self.symbols.getOrPut(name);
        if (result.found_existing) {
            return error.DuplicateDeclaration;
        }
        result.value_ptr.* = sym;
    }

    /// Look up a symbol by name, walking the parent chain.
    pub fn lookup(self: *const SymbolTable, name: []const u8) ?Symbol {
        if (self.symbols.get(name)) |sym| {
            return sym;
        }
        if (self.parent) |p| {
            return p.lookup(name);
        }
        return null;
    }

    /// Look up a symbol only in this scope (no parent walk).
    pub fn lookupLocal(self: *const SymbolTable, name: []const u8) ?Symbol {
        return self.symbols.get(name);
    }
};

// ============================================================================
// Section 4 — Type Resolver
// ============================================================================

/// Resolves AST type expressions into concrete `ResolvedType` values,
/// checks type compatibility, performs inference, and registers top-level
/// declarations into the global scope.
pub const TypeResolver = struct {
    global_scope: SymbolTable,
    type_aliases: std.StringHashMap(ResolvedType),
    struct_defs: std.StringHashMap(StructInfo),
    enum_defs: std.StringHashMap(EnumInfo),
    contract_defs: std.StringHashMap(ast.ContractDef),
    /// Stores all declared asset definitions by name.
    asset_defs: std.StringHashMap(ast.AssetDef),
    /// Stores all declared interfaces by name.
    /// Values are raw AST pointers — valid for the lifetime of the source AST.
    interface_defs: std.StringHashMap(ast.InterfaceDef),
    /// SPEC: Novel Idea 6 — Track capability type names for linear resolution.
    capability_names: std.StringHashMap(void),
    allocator: std.mem.Allocator,
    diagnostics: *DiagnosticList,

    /// Create a new resolver, pre-registering built-in aliases from Spec §2.1.
    pub fn init(allocator: std.mem.Allocator, diagnostics: *DiagnosticList) TypeResolver {
        var self = TypeResolver{
            .global_scope = SymbolTable.init(allocator, null),
            .type_aliases = std.StringHashMap(ResolvedType).init(allocator),
            .struct_defs = std.StringHashMap(StructInfo).init(allocator),
            .enum_defs = std.StringHashMap(EnumInfo).init(allocator),
            .contract_defs = std.StringHashMap(ast.ContractDef).init(allocator),
            .asset_defs = std.StringHashMap(ast.AssetDef).init(allocator),
            .interface_defs = std.StringHashMap(ast.InterfaceDef).init(allocator),
            .capability_names = std.StringHashMap(void).init(allocator),
            .allocator = allocator,
            .diagnostics = diagnostics,
        };
        // Spec §2.1 built-in aliases:
        //   uint    → u256
        //   int     → i256
        //   price9  → Fixed[9]
        //   price18 → Fixed[18]
        //   percent → Fixed[4]
        self.type_aliases.put("uint", .u256) catch {};
        self.type_aliases.put("int", .i256) catch {};
        self.type_aliases.put("price9", .{ .fixed_point = 9 }) catch {};
        self.type_aliases.put("price18", .{ .fixed_point = 18 }) catch {};
        self.type_aliases.put("percent", .{ .fixed_point = 4 }) catch {};
        return self;
    }

    /// Release all resources.
    pub fn deinit(self: *TypeResolver) void {
        self.global_scope.deinit();
        self.type_aliases.deinit();
        self.struct_defs.deinit();
        self.enum_defs.deinit();
        self.contract_defs.deinit();
        self.asset_defs.deinit();
        self.interface_defs.deinit();
        self.capability_names.deinit();
    }

    pub fn lookupInterface(self: *const TypeResolver, name: []const u8) ?ast.InterfaceDef {
        return self.interface_defs.get(name);
    }

    pub fn lookupContract(self: *const TypeResolver, name: []const u8) ?ast.ContractDef {
        return self.contract_defs.get(name);
    }

    /// Allocate a single `ResolvedType` on the heap and return a pointer.
    pub fn allocResolvedType(self: *TypeResolver, rt: ResolvedType) anyerror!*ResolvedType {
        const ptr = try self.allocator.create(ResolvedType);
        ptr.* = rt;
        return ptr;
    }

    /// Resolve a `TypeExpr` from the AST into a concrete `ResolvedType`.
    pub fn resolve(self: *TypeResolver, expr: TypeExpr) anyerror!ResolvedType {
        return switch (expr) {
            .u8 => .u8,
            .u16 => .u16,
            .u32 => .u32,
            .u64 => .u64,
            .u128 => .u128,
            .u256 => .u256,
            .uint => .u256,
            .i8 => .i8,
            .i16 => .i16,
            .i32 => .i32,
            .i64 => .i64,
            .i128 => .i128,
            .i256 => .i256,
            .int => .i256,
            .fixed => |f| .{ .fixed_point = f.decimals },
            .price9 => .{ .fixed_point = 9 },
            .price18 => .{ .fixed_point = 18 },
            .percent => .{ .fixed_point = 4 },
            .bool => .bool,
            .account => .account,
            .wallet => .wallet,
            .program => .program,
            .system_acc => .system_acc,
            .hash => .hash,
            .hash20 => .{ .bytes_n = 20 },
            .commitment => .commitment,
            .byte => .u8,
            .bytes => .bytes,
            .bytes32 => .{ .bytes_n = 32 },
            .bytes64 => .{ .bytes_n = 64 },
            .signature => .signature,
            .pubkey => .pubkey,
            .timestamp => .timestamp,
            .duration => .duration,
            .block_number => .block_number,
            .epoch => .u64,
            .slot => .u32,
            .string => .string,
            .short_str => .short_str,
            .label => .string,
            .maybe => |inner| {
                const resolved_inner = try self.resolve(inner.*);
                const ptr = try self.allocResolvedType(resolved_inner);
                return .{ .maybe = ptr };
            },
            .result => |r| {
                const ok = try self.resolve(r.ok.*);
                const err_t = try self.resolve(r.err.*);
                return .{ .result = .{
                    .ok = try self.allocResolvedType(ok),
                    .err = try self.allocResolvedType(err_t),
                } };
            },
            .map => |m| {
                const k = try self.resolve(m.key.*);
                const v = try self.resolve(m.value.*);
                return .{ .map = .{
                    .key = try self.allocResolvedType(k),
                    .value = try self.allocResolvedType(v),
                } };
            },
            .enum_map => |m| {
                const k = try self.resolve(m.key.*);
                const v = try self.resolve(m.value.*);
                return .{ .enum_map = .{
                    .key = try self.allocResolvedType(k),
                    .value = try self.allocResolvedType(v),
                } };
            },
            .list => |inner| {
                const resolved_inner = try self.resolve(inner.*);
                return .{ .list = try self.allocResolvedType(resolved_inner) };
            },
            .set => |inner| {
                const resolved_inner = try self.resolve(inner.*);
                return .{ .set = try self.allocResolvedType(resolved_inner) };
            },
            .array => |a| {
                const elem = try self.resolve(a.elem.*);
                return .{ .array = .{
                    .elem = try self.allocResolvedType(elem),
                    .size = a.size,
                } };
            },
            .tuple => |elems| {
                const resolved = try self.allocator.alloc(*ResolvedType, elems.len);
                for (elems, 0..) |e, i| {
                    const r = try self.resolve(e.*);
                    resolved[i] = try self.allocResolvedType(r);
                }
                return .{ .tuple = resolved };
            },
            .named => |name| {
                if (self.type_aliases.get(name)) |aliased| {
                    return aliased;
                }
                // SPEC: Novel Idea 6 — Capabilities resolve as capability type.
                if (self.capability_names.contains(name)) {
                    return .{ .capability = name };
                }
                if (self.struct_defs.getPtr(name)) |info| {
                    return .{ .struct_ = info };
                }
                if (self.enum_defs.getPtr(name)) |info| {
                    return .{ .enum_ = info };
                }
                return .{ .asset = name };
            },
            .generic => |g| {
                if (std.mem.eql(u8, g.name, "Fixed") and g.params.len == 1) {
                    const inner = try self.resolve(g.params[0].*);
                    _ = inner;
                    return .{ .fixed_point = 18 };
                }
                if (std.mem.eql(u8, g.name, "Proof") and g.params.len == 1) {
                    const inner = try self.resolve(g.params[0].*);
                    const ptr = try self.allocator.create(ResolvedType);
                    ptr.* = inner;
                    return .{ .proof = ptr };
                }
                return .void_;
            },
            .span => .void_,
        };
    }

    /// Check if two resolved types are assignment-compatible.
    /// Handles subtype relationships per Spec §2.1.
    pub fn isCompatible(self: *TypeResolver, from: ResolvedType, to: ResolvedType) bool {
        // Exact match via tag comparison
        const from_tag = std.meta.activeTag(from);
        const to_tag = std.meta.activeTag(to);
        if (from_tag == to_tag) {
            return switch (from) {
                .fixed_point => |fd| fd == to.fixed_point,
                .bytes_n => |fn_| fn_ == to.bytes_n,
                .asset => |n| std.mem.eql(u8, n, to.asset),
                .proof => |p| self.isCompatible(p.*, to.proof.*),
                else => true,
            };
        }
        // Subtype: Wallet <: Account
        if (from_tag == .wallet and to_tag == .account) return true;
        // Subtype: Program <: Account
        if (from_tag == .program and to_tag == .account) return true;
        // Subtype: System <: Account
        if (from_tag == .system_acc and to_tag == .account) return true;
        // Numeric widening
        if (isWidenableTo(from, to)) return true;
        // Fixed-point subtypes: price9/price18/percent → fixed_point
        if (to_tag == .fixed_point) {
            if (from_tag == .fixed_point) return from.fixed_point == to.fixed_point;
        }
        return false;
    }

    /// Check if `from` is a numeric type that can be widened to `to`.
    pub fn isWidenableTo(from: ResolvedType, to: ResolvedType) bool {
        const from_tag = std.meta.activeTag(from);
        const to_tag = std.meta.activeTag(to);
        const from_rank = unsignedRank(from_tag) orelse (signedRank(from_tag) orelse return false);
        const to_rank_u = unsignedRank(to_tag);
        const to_rank_s = signedRank(to_tag);
        // Unsigned → unsigned widening
        if (unsignedRank(from_tag) != null and to_rank_u != null) {
            return from_rank < to_rank_u.?;
        }
        // Signed → signed widening
        if (signedRank(from_tag) != null and to_rank_s != null) {
            return from_rank < to_rank_s.?;
        }
        return false;
    }

    /// Infer the type of an expression given a symbol table scope.
    pub fn inferExpr(
        self: *TypeResolver,
        expr: *const Expr,
        scope: *const SymbolTable,
    ) anyerror!ResolvedType {
        return switch (expr.kind) {
            .int_lit => .u256,
            .float_lit => .{ .fixed_point = 18 },
            .bool_lit => .bool,
            .string_lit => .string,
            .nothing => return error.TypeMismatch,
            .something => |inner| {
                const inner_ty = try self.inferExpr(inner, scope);
                return .{ .maybe = try self.allocResolvedType(inner_ty) };
            },
            .identifier => |name| {
                if (scope.lookup(name)) |sym| {
                    return sym.type_;
                }
                return error.UndeclaredIdentifier;
            },
            .field_access => |fa| {
                const obj_ty = try self.inferExpr(fa.object, scope);
                switch (obj_ty) {
                    .struct_ => |info| {
                        for (info.fields) |field| {
                            if (std.mem.eql(u8, field.name, fa.field)) {
                                return field.type_;
                            }
                        }
                        return error.UndeclaredIdentifier;
                    },
                    else => return error.InvalidTypeForOperation,
                }
            },
            .bin_op => |op| {
                const left_ty = try self.inferExpr(op.left, scope);
                const right_ty = try self.inferExpr(op.right, scope);
                switch (op.op) {
                    .plus, .minus, .times, .divided_by, .mod => {
                        if (self.isCompatible(left_ty, right_ty)) return left_ty;
                        if (self.isCompatible(right_ty, left_ty)) return right_ty;
                        return error.TypeMismatch;
                    },
                    .equals, .not_equals, .less, .less_eq, .greater, .greater_eq => return .bool,
                    .and_, .or_ => return .bool,
                    .has => return .bool,
                    .duration_add, .duration_sub => return .timestamp,
                }
            },
            .unary_op => |op| {
                const operand_ty = try self.inferExpr(op.operand, scope);
                switch (op.op) {
                    .not_ => return .bool,
                    .negate => return operand_ty,
                }
            },
            .call => |c| {
                const callee_ty = try self.inferExpr(c.callee, scope);
                _ = callee_ty;
                return .void_;
            },
            .struct_lit => |sl| {
                if (self.struct_defs.getPtr(sl.type_name)) |info| {
                    return .{ .struct_ = info };
                }
                return error.UndeclaredType;
            },
            .tuple_lit => |elems| {
                const resolved = try self.allocator.alloc(*ResolvedType, elems.len);
                for (elems, 0..) |e, i| {
                    const r = try self.inferExpr(e, scope);
                    resolved[i] = try self.allocResolvedType(r);
                }
                return .{ .tuple = resolved };
            },
            .builtin => |b| {
                return switch (b) {
                    .caller => .wallet,
                    .value => .u256,
                    .deployer => .account,
                    .this_address => .program,
                    .zero_address => .account,
                    .now => .timestamp,
                    .current_block => .block_number,
                    .gas_remaining => .u64,
                };
            },
            .cast => |c| {
                return try self.resolve(c.to);
            },
            .try_propagate => |inner| {
                return try self.inferExpr(inner, scope);
            },
            else => .void_,
        };
    }

    /// Register all top-level declarations into the global scope.
    /// Call this before type-checking any function bodies.
    pub fn registerTopLevel(self: *TypeResolver, tops: []const TopLevel) anyerror!void {
        for (tops) |top| {
            switch (top) {
                .struct_def => |sd| {
                    const fields = try self.allocator.alloc(ResolvedField, sd.fields.len);
                    for (sd.fields, 0..) |f, i| {
                        fields[i] = .{
                            .name = f.name,
                            .type_ = try self.resolve(f.type_),
                        };
                    }
                    try self.struct_defs.put(sd.name, .{ .name = sd.name, .fields = fields });
                    try self.global_scope.define(sd.name, .{
                        .name = sd.name,
                        .kind = .struct_type,
                        .type_ = .void_,
                        .span = sd.span,
                        .mutable = false,
                    });
                },
                .enum_def => |ed| {
                    const variants = try self.allocator.alloc(EnumVariantInfo, ed.variants.len);
                    for (ed.variants, 0..) |v, i| {
                        const vfields = try self.allocator.alloc(ResolvedField, v.fields.len);
                        for (v.fields, 0..) |f, j| {
                            vfields[j] = .{
                                .name = f.name,
                                .type_ = try self.resolve(f.type_),
                            };
                        }
                        variants[i] = .{ .name = v.name, .fields = vfields };
                    }
                    try self.enum_defs.put(ed.name, .{ .name = ed.name, .variants = variants });
                    try self.global_scope.define(ed.name, .{
                        .name = ed.name,
                        .kind = .enum_type,
                        .type_ = .void_,
                        .span = ed.span,
                        .mutable = false,
                    });
                },
                .type_alias => |ta| {
                    const resolved = try self.resolve(ta.type_);
                    try self.type_aliases.put(ta.name, resolved);
                    try self.global_scope.define(ta.name, .{
                        .name = ta.name,
                        .kind = .type_alias,
                        .type_ = resolved,
                        .span = ta.span,
                        .mutable = false,
                    });
                },
                .constant => |cd| {
                    try self.global_scope.define(cd.name, .{
                        .name = cd.name,
                        .kind = .constant,
                        .type_ = if (cd.type_) |t| try self.resolve(t) else .u256,
                        .span = cd.span,
                        .mutable = false,
                    });
                },
                .contract => |ct| {
                    // Store the full ContractDef so child contracts can inherit from it.
                    try self.contract_defs.put(ct.name, ct);

                    for (ct.state) |sf| {
                        const resolved = try self.resolve(sf.type_);
                        try self.global_scope.define(sf.name, .{
                            .name = sf.name,
                            .kind = .state_field,
                            .type_ = resolved,
                            .span = sf.span,
                            .mutable = true,
                        });
                    }
                    for (ct.events) |ev| {
                        try self.global_scope.define(ev.name, .{
                            .name = ev.name,
                            .kind = .event,
                            .type_ = .void_,
                            .span = ev.span,
                            .mutable = false,
                        });
                    }
                    for (ct.errors_) |er| {
                        try self.global_scope.define(er.name, .{
                            .name = er.name,
                            .kind = .error_decl,
                            .type_ = .void_,
                            .span = er.span,
                            .mutable = false,
                        });
                    }
                    for (ct.actions) |ac| {
                        try self.global_scope.define(ac.name, .{
                            .name = ac.name,
                            .kind = .action,
                            .type_ = if (ac.return_type) |rt| try self.resolve(rt) else .void_,
                            .span = ac.span,
                            .mutable = false,
                        });
                    }
                    for (ct.views) |vw| {
                        try self.global_scope.define(vw.name, .{
                            .name = vw.name,
                            .kind = .view,
                            .type_ = if (vw.return_type) |rt| try self.resolve(rt) else .void_,
                            .span = vw.span,
                            .mutable = false,
                        });
                    }
                    for (ct.pures) |pu| {
                        try self.global_scope.define(pu.name, .{
                            .name = pu.name,
                            .kind = .pure_fn,
                            .type_ = if (pu.return_type) |rt| try self.resolve(rt) else .void_,
                            .span = pu.span,
                            .mutable = false,
                        });
                    }
                    for (ct.guards) |gd| {
                        try self.global_scope.define(gd.name, .{
                            .name = gd.name,
                            .kind = .guard,
                            .type_ = .void_,
                            .span = gd.span,
                            .mutable = false,
                        });
                    }
                    for (ct.authorities) |au| {
                        try self.global_scope.define(au.name, .{
                            .name = au.name,
                            .kind = .authority,
                            .type_ = .void_,
                            .span = au.span,
                            .mutable = false,
                        });
                    }
                },
                .asset_def => |ad| {
                    // Record the AST pointer for the checker.
                    try self.asset_defs.put(ad.name, ad);
                    // Also define as a type in the global scope.
                    try self.global_scope.define(ad.name, .{
                        .name = ad.name,
                        .kind = .asset,
                        .type_ = .{ .linear = try self.allocResolvedType(.{ .asset = ad.name }) },
                        .span = ad.span,
                        .mutable = false,
                    });
                },
                .record_def => |rd| {
                    const fields = try self.allocator.alloc(ResolvedField, rd.fields.len);
                    for (rd.fields, 0..) |f, i| {
                        fields[i] = .{
                            .name = f.name,
                            .type_ = try self.resolve(f.type_),
                        };
                    }
                    try self.struct_defs.put(rd.name, .{ .name = rd.name, .fields = fields });
                    try self.global_scope.define(rd.name, .{
                        .name = rd.name,
                        .kind = .struct_type,
                        .type_ = .void_,
                        .span = rd.span,
                        .mutable = false,
                    });
                },
                .version => {},
                .use_import => {},
                .interface_def => |iface| {
                    // Store the interface definition for later conformance checking.
                    try self.interface_defs.put(iface.name, iface);
                    // Also register the name in the global scope so the type system
                    // can resolve `implements InterfaceName` references.
                    try self.global_scope.define(iface.name, .{
                        .name    = iface.name,
                        .kind    = .type_alias,
                        .type_   = .void_,
                        .span    = iface.span,
                        .mutable = false,
                    });
                },
                .capability_def => |cap| {
                    // SPEC: Novel Idea 6 — Capability Token Types.
                    // Register capability as a struct-like type in the global scope.
                    const fields = try self.allocator.alloc(ResolvedField, cap.fields.len);
                    for (cap.fields, 0..) |f, i| {
                        fields[i] = .{
                            .name = f.name,
                            .type_ = try self.resolve(f.type_),
                        };
                    }
                    try self.struct_defs.put(cap.name, .{ .name = cap.name, .fields = fields });
                    try self.capability_names.put(cap.name, {});
                    try self.global_scope.define(cap.name, .{
                        .name = cap.name,
                        .kind = .struct_type,
                        .type_ = .void_,
                        .span = cap.span,
                        .mutable = false,
                    });
                },
                .global_invariant => {},
            }
        }
    }
};

// ============================================================================
// Section 5 — Numeric Rank Helpers
// ============================================================================

/// Return rank for unsigned integer tags, or null if not unsigned.
fn unsignedRank(tag: std.meta.Tag(ResolvedType)) ?u8 {
    return switch (tag) {
        .u8 => 0,
        .u16 => 1,
        .u32 => 2,
        .u64 => 3,
        .u128 => 4,
        .u256 => 5,
        else => null,
    };
}

/// Return rank for signed integer tags, or null if not signed.
fn signedRank(tag: std.meta.Tag(ResolvedType)) ?u8 {
    return switch (tag) {
        .i8 => 0,
        .i16 => 1,
        .i32 => 2,
        .i64 => 3,
        .i128 => 4,
        .i256 => 5,
        else => null,
    };
}

// ============================================================================
// Section 6 — Tests
// ============================================================================

test "resolve primitive types" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    // Unsigned
    try std.testing.expectEqual(ResolvedType.u8, try resolver.resolve(.u8));
    try std.testing.expectEqual(ResolvedType.u16, try resolver.resolve(.u16));
    try std.testing.expectEqual(ResolvedType.u32, try resolver.resolve(.u32));
    try std.testing.expectEqual(ResolvedType.u64, try resolver.resolve(.u64));
    try std.testing.expectEqual(ResolvedType.u128, try resolver.resolve(.u128));
    try std.testing.expectEqual(ResolvedType.u256, try resolver.resolve(.u256));
    // uint → u256
    try std.testing.expectEqual(ResolvedType.u256, try resolver.resolve(.uint));

    // Signed
    try std.testing.expectEqual(ResolvedType.i8, try resolver.resolve(.i8));
    try std.testing.expectEqual(ResolvedType.i16, try resolver.resolve(.i16));
    try std.testing.expectEqual(ResolvedType.i32, try resolver.resolve(.i32));
    try std.testing.expectEqual(ResolvedType.i64, try resolver.resolve(.i64));
    try std.testing.expectEqual(ResolvedType.i128, try resolver.resolve(.i128));
    try std.testing.expectEqual(ResolvedType.i256, try resolver.resolve(.i256));
    // int → i256
    try std.testing.expectEqual(ResolvedType.i256, try resolver.resolve(.int));

    // Bool, address, time, text
    try std.testing.expectEqual(ResolvedType.bool, try resolver.resolve(.bool));
    try std.testing.expectEqual(ResolvedType.account, try resolver.resolve(.account));
    try std.testing.expectEqual(ResolvedType.wallet, try resolver.resolve(.wallet));
    try std.testing.expectEqual(ResolvedType.timestamp, try resolver.resolve(.timestamp));
    try std.testing.expectEqual(ResolvedType.string, try resolver.resolve(.string));
}

test "wallet is subtype of account" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    try std.testing.expect(resolver.isCompatible(.wallet, .account));
    try std.testing.expect(resolver.isCompatible(.program, .account));
    try std.testing.expect(resolver.isCompatible(.system_acc, .account));
}

test "account is not subtype of wallet" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    try std.testing.expect(!resolver.isCompatible(.account, .wallet));
    try std.testing.expect(!resolver.isCompatible(.account, .program));
    try std.testing.expect(!resolver.isCompatible(.account, .system_acc));
}

test "maybe not assignable to plain" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    const inner = try resolver.allocResolvedType(.u256);
    const maybe_u256 = ResolvedType{ .maybe = inner };
    defer allocator.destroy(inner);

    try std.testing.expect(!resolver.isCompatible(maybe_u256, .u256));
    try std.testing.expect(!resolver.isCompatible(.u256, maybe_u256));
}

test "infer binary plus expression" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var scope = SymbolTable.init(allocator, null);
    defer scope.deinit();

    // Build: left(u256 literal) plus right(u256 literal)
    var left_expr = Expr{ .kind = .{ .int_lit = "100" }, .span = .{ .line = 1, .col = 1, .len = 3 } };
    var right_expr = Expr{ .kind = .{ .int_lit = "200" }, .span = .{ .line = 1, .col = 7, .len = 3 } };
    var bin_expr = Expr{
        .kind = .{ .bin_op = .{ .op = .plus, .left = &left_expr, .right = &right_expr } },
        .span = .{ .line = 1, .col = 1, .len = 9 },
    };
    const result = try resolver.inferExpr(&bin_expr, &scope);
    try std.testing.expectEqual(ResolvedType.u256, result);
}

test "infer field access on struct" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var scope = SymbolTable.init(allocator, null);
    defer scope.deinit();

    // Register a struct with a u256 field called "amount"
    var fields_buf = [_]ResolvedField{
        .{ .name = "amount", .type_ = .u256 },
        .{ .name = "active", .type_ = .bool },
    };
    const info = StructInfo{ .name = "Position", .fields = &fields_buf };
    try resolver.struct_defs.put("Position", info);

    // Define a variable "pos" of type struct_ → Position
    try scope.define("pos", .{
        .name = "pos",
        .kind = .local_var,
        .type_ = .{ .struct_ = resolver.struct_defs.getPtr("Position").? },
        .span = .{ .line = 1, .col = 1, .len = 3 },
        .mutable = false,
    });

    // Build: pos.amount
    var obj_expr = Expr{ .kind = .{ .identifier = "pos" }, .span = .{ .line = 2, .col = 1, .len = 3 } };
    var access_expr = Expr{
        .kind = .{ .field_access = .{ .object = &obj_expr, .field = "amount" } },
        .span = .{ .line = 2, .col = 1, .len = 10 },
    };
    const result = try resolver.inferExpr(&access_expr, &scope);
    try std.testing.expectEqual(ResolvedType.u256, result);

    // Access "active" field → bool
    var access_bool = Expr{
        .kind = .{ .field_access = .{ .object = &obj_expr, .field = "active" } },
        .span = .{ .line = 3, .col = 1, .len = 10 },
    };
    const result2 = try resolver.inferExpr(&access_bool, &scope);
    try std.testing.expectEqual(ResolvedType.bool, result2);
}

test "registerTopLevel stores interface_def" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var params = [_]ast.Param{.{
        .name = "to",
        .declared_type = .account,
        .is_private = false,
        .span = .{ .line = 1, .col = 1, .len = 2 },
    }};

    const action = ast.InterfaceAction{
        .name = "transfer",
        .params = &params,
        .return_type = null,
        .span = .{ .line = 1, .col = 1, .len = 8 },
    };

    var members = [_]ast.InterfaceMember{.{ .action = action }};

    const iface = ast.InterfaceDef{
        .name = "Transferable",
        .members = &members,
        .span = .{ .line = 1, .col = 1, .len = 12 },
    };

    const tops = [_]TopLevel{.{ .interface_def = iface }};
    try resolver.registerTopLevel(&tops);

    const lookup = resolver.lookupInterface("Transferable");
    try std.testing.expect(lookup != null);
    try std.testing.expectEqualSlices(u8, "Transferable", lookup.?.name);
    try std.testing.expectEqual(@as(usize, 1), lookup.?.members.len);
}

test "lookupInterface returns null for unknown interface" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    const lookup = resolver.lookupInterface("DoesNotExist");
    try std.testing.expectEqual(@as(?ast.InterfaceDef, null), lookup);
}

test "interface name is defined in global scope" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    const iface = ast.InterfaceDef{
        .name = "Transferable",
        .members = &[_]ast.InterfaceMember{},
        .span = .{ .line = 1, .col = 1, .len = 12 },
    };

    const tops = [_]TopLevel{.{ .interface_def = iface }};
    try resolver.registerTopLevel(&tops);

    const sym = resolver.global_scope.lookup("Transferable");
    try std.testing.expect(sym != null);
    try std.testing.expectEqual(SymbolKind.type_alias, sym.?.kind);
}

test "registerTopLevel handles multiple interfaces without error" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    const iface1 = ast.InterfaceDef{ .name = "A", .members = &[_]ast.InterfaceMember{}, .span = .{ .line = 1, .col = 1, .len = 1 } };
    const iface2 = ast.InterfaceDef{ .name = "B", .members = &[_]ast.InterfaceMember{}, .span = .{ .line = 2, .col = 1, .len = 1 } };
    const iface3 = ast.InterfaceDef{ .name = "C", .members = &[_]ast.InterfaceMember{}, .span = .{ .line = 3, .col = 1, .len = 1 } };

    const tops = [_]TopLevel{
        .{ .interface_def = iface1 },
        .{ .interface_def = iface2 },
        .{ .interface_def = iface3 },
    };
    try resolver.registerTopLevel(&tops);

    try std.testing.expect(resolver.lookupInterface("A") != null);
    try std.testing.expect(resolver.lookupInterface("B") != null);
    try std.testing.expect(resolver.lookupInterface("C") != null);

    try std.testing.expect(resolver.global_scope.lookup("A") != null);
    try std.testing.expect(resolver.global_scope.lookup("B") != null);
    try std.testing.expect(resolver.global_scope.lookup("C") != null);
}

test "registerTopLevel stores contract_def" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    const contract = ast.ContractDef{
        .name = "MyToken",
        .inherits = null,
        .config = &[_]ast.ConfigField{},
        .state = &[_]ast.StateField{},
        .always = &[_]ast.ConstDecl{},
        .computed = &[_]ast.ComputedField{},
        .setup = null,
        .events = &[_]ast.EventDecl{},
        .errors_ = &[_]ast.ErrorDecl{},
        .helpers = &[_]ast.HelperDecl{},
        .actions = &[_]ast.ActionDecl{},
        .views = &[_]ast.ViewDecl{},
        .pures = &[_]ast.PureDecl{},
        .guards = &[_]ast.GuardDecl{},
        .authorities = &[_]ast.AuthorityDecl{},
        .upgrade = null,
        .implements = &[_][]const u8{},
        .namespaces = &[_][]const u8{},
        .accounts = &[_]ast.AccountDecl{},
        .invariants = &[_]ast.InvariantDecl{},
        .conserves = &[_]ast.ConservationExpr{},
        .adversary_blocks = &[_]ast.AdversaryBlock{},
        .fallback = null,
        .receive_ = null,
        .span = Span{ .line = 1, .col = 1, .len = 7 },
    };

    const tops = [_]TopLevel{.{ .contract = contract }};
    try resolver.registerTopLevel(&tops);

    const lookup = resolver.lookupContract("MyToken");
    try std.testing.expect(lookup != null);
    try std.testing.expectEqualSlices(u8, "MyToken", lookup.?.name);
}
