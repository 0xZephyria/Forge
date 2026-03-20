// ============================================================================
// Forge Compiler — Semantic Checker
// ============================================================================
//
// Walks the full AST, type-checks every expression and statement, enforces
// all of ZEPH's safety rules, and produces verified access lists per action.
//
// SPEC REFERENCE:
//   Part 3.9  — Access Isolation Rules (all 5 rules)
//   Part 4    — Authority System
//   Part 6.4  — Assertions (need/ensure)
//   Part 7    — Access Control (only/guard)
//   Part 8.2  — Linear Asset Types
//   Part 9.1  — Access List Annotations
//
// This is a library file. No main() function is present.

const std = @import("std");
const ast = @import("ast.zig");
const errors = @import("errors.zig");
const types = @import("types.zig");

const Span = ast.Span;
const Expr = ast.Expr;
const ExprKind = ast.ExprKind;
const Stmt = ast.Stmt;
const StmtKind = ast.StmtKind;
const BinOp = ast.BinOp;
const TopLevel = ast.TopLevel;
const ContractDef = ast.ContractDef;
const ActionDecl = ast.ActionDecl;
const AccountDecl = ast.AccountDecl;
const OnlyStmt = ast.OnlyStmt;
const EachLoop = ast.EachLoop;
const Annotation = ast.Annotation;
const AnnotationKind = ast.AnnotationKind;

const DiagnosticList = errors.DiagnosticList;
const CompileError = errors.CompileError;
const TypeResolver = types.TypeResolver;
const ResolvedType = types.ResolvedType;
const SymbolTable = types.SymbolTable;
const Symbol = types.Symbol;
const SymbolKind = types.SymbolKind;

// ============================================================================
// Section 1 — Access List
// ============================================================================

/// The kind of access performed on an account field.
pub const AccessKind = enum {
    read,
    write,
    debit,
    credit,
};

/// A single record of an account field access.
pub const AccessEntry = struct {
    account_name: []const u8,
    /// `null` means the whole account is accessed.
    field: ?[]const u8,
    access_kind: AccessKind,
};

/// Collected read and write access entries for one action.
pub const AccessList = struct {
    reads: std.ArrayList(AccessEntry),
    writes: std.ArrayList(AccessEntry),
    allocator: std.mem.Allocator,

    /// Create an empty access list.
    pub fn init(allocator: std.mem.Allocator) AccessList {
        return .{
            .reads = .{},
            .writes = .{},
            .allocator = allocator,
        };
    }

    /// Release all resources.
    pub fn deinit(self: *AccessList) void {
        self.reads.deinit(self.allocator);
        self.writes.deinit(self.allocator);
    }

    /// Record a read access on `account.field`.
    pub fn addRead(self: *AccessList, account: []const u8, field: ?[]const u8) anyerror!void {
        try self.reads.append(self.allocator, .{
            .account_name = account,
            .field = field,
            .access_kind = .read,
        });
    }

    /// Record a write access on `account.field`.
    pub fn addWrite(self: *AccessList, account: []const u8, field: ?[]const u8) anyerror!void {
        try self.writes.append(self.allocator, .{
            .account_name = account,
            .field = field,
            .access_kind = .write,
        });
    }

    /// Check if this access list conflicts with `other` (shared write targets).
    pub fn conflictsWith(self: *const AccessList, other: *const AccessList) bool {
        for (self.writes.items) |w1| {
            for (other.writes.items) |w2| {
                if (std.mem.eql(u8, w1.account_name, w2.account_name)) {
                    // Both write same account — check field overlap
                    if (w1.field == null or w2.field == null) return true;
                    if (w1.field != null and w2.field != null) {
                        if (std.mem.eql(u8, w1.field.?, w2.field.?)) return true;
                    }
                }
            }
        }
        return false;
    }
};

// ============================================================================
// Section 2 — Checked Contract
// ============================================================================

/// The output of successful semantic checking for one contract.
pub const CheckedContract = struct {
    name: []const u8,
    action_lists: std.StringHashMap(AccessList),
    type_map: std.StringHashMap(ResolvedType),
    scope: SymbolTable,
    allocator: std.mem.Allocator,

    /// Release all resources held by the checked contract.
    pub fn deinit(self: *CheckedContract) void {
        var it = self.action_lists.iterator();
        while (it.next()) |entry| {
            var al = entry.value_ptr;
            al.deinit();
        }
        self.action_lists.deinit();
        self.type_map.deinit();
        self.scope.deinit();
    }
};

// ============================================================================
// Section 3 — Linear Asset Tracker
// ============================================================================

/// Tracks consumption of linear (move-only) asset values within a scope.
pub const LinearTracker = struct {
    /// Maps variable name → whether it has been consumed.
    consumed: std.StringHashMap(bool),
    allocator: std.mem.Allocator,

    /// Create an empty tracker.
    pub fn init(allocator: std.mem.Allocator) LinearTracker {
        return .{
            .consumed = std.StringHashMap(bool).init(allocator),
            .allocator = allocator,
        };
    }

    /// Release all resources.
    pub fn deinit(self: *LinearTracker) void {
        self.consumed.deinit();
    }

    /// Mark a linear variable as consumed. Errors if already consumed.
    pub fn markConsumed(
        self: *LinearTracker,
        name: []const u8,
        span: Span,
        diag: *DiagnosticList,
    ) anyerror!void {
        if (self.consumed.get(name)) |already| {
            if (already) {
                const msg = try std.fmt.allocPrint(
                    diag.allocator,
                    "linear asset '{s}' consumed more than once",
                    .{name},
                );
                try diag.add(.{
                    .file = "",
                    .line = span.line,
                    .col = span.col,
                    .len = span.len,
                    .kind = CompileError.LinearAssetUsedTwice,
                    .message = msg,
                    .source_line = "",
                });
                return;
            }
        }
        try self.consumed.put(name, true);
    }

    /// At end of scope, verify all linear variables were consumed.
    pub fn checkAllConsumed(
        self: *LinearTracker,
        scope: *SymbolTable,
        diag: *DiagnosticList,
    ) anyerror!void {
        var sym_it = scope.symbols.iterator();
        while (sym_it.next()) |entry| {
            const sym = entry.value_ptr;
            switch (sym.type_) {
                .linear => {
                    if (self.consumed.get(sym.name) == null) {
                        const msg = try std.fmt.allocPrint(
                            diag.allocator,
                            "linear asset '{s}' dropped without consumption",
                            .{sym.name},
                        );
                        try diag.add(.{
                            .file = "",
                            .line = sym.span.line,
                            .col = sym.span.col,
                            .len = sym.span.len,
                            .kind = CompileError.LinearAssetDropped,
                            .message = msg,
                            .source_line = "",
                        });
                    }
                },
                else => {},
            }
        }
    }
};

// ============================================================================
// Section 4 — Checker
// ============================================================================

/// The main semantic checker. Drives type-checking and rule enforcement.
pub const Checker = struct {
    resolver: *TypeResolver,
    diagnostics: *DiagnosticList,
    allocator: std.mem.Allocator,

    /// Create a new checker bound to a type resolver and diagnostic sink.
    pub fn init(
        resolver: *TypeResolver,
        diagnostics: *DiagnosticList,
        allocator: std.mem.Allocator,
    ) Checker {
        return .{
            .resolver = resolver,
            .diagnostics = diagnostics,
            .allocator = allocator,
        };
    }

    // ── Rule 1: Undeclared = Inaccessible (Part 3.9) ─────────────────────

    /// Verify that `access_name` is declared in the contract's accounts block.
    fn checkAccountAccess(
        self: *Checker,
        accounts: []const AccountDecl,
        access_name: []const u8,
        span: Span,
    ) anyerror!void {
        for (accounts) |acct| {
            if (std.mem.eql(u8, acct.name, access_name)) return;
        }
        const msg = try std.fmt.allocPrint(
            self.allocator,
            "account '{s}' is not declared in accounts block",
            .{access_name},
        );
        try self.diagnostics.add(.{
            .file = "",
            .line = span.line,
            .col = span.col,
            .len = span.len,
            .kind = CompileError.AccountNotDeclared,
            .message = msg,
            .source_line = "",
        });
    }

    // ── Rule 2: Read-Only = No Writes (Part 3.9) ─────────────────────────

    /// Verify that a readonly account is not being written to.
    fn checkReadonlyViolation(
        self: *Checker,
        account: *const AccountDecl,
        is_write: bool,
        span: Span,
    ) anyerror!void {
        if (account.readonly and is_write) {
            const msg = try std.fmt.allocPrint(
                self.allocator,
                "account '{s}' is declared readonly, cannot write",
                .{account.name},
            );
            try self.diagnostics.add(.{
                .file = "",
                .line = span.line,
                .col = span.col,
                .len = span.len,
                .kind = CompileError.CannotAssignToReadonly,
                .message = msg,
                .source_line = "",
            });
        }
    }

    // ── Rule 3: Capability = Only Named Fields (Part 3.9) ────────────────

    /// Verify a field access is permitted by the account's capability list.
    fn checkCapabilityField(
        self: *Checker,
        account: *const AccountDecl,
        field_name: []const u8,
        is_write: bool,
        span: Span,
    ) anyerror!void {
        if (account.capabilities.len == 0) return;
        for (account.capabilities) |cap| {
            const mode_match = switch (cap.access) {
                .read => !is_write,
                .write => is_write,
                .debit => is_write,
                .credit => is_write,
            };
            if (!mode_match) continue;
            if (cap.fields) |fields| {
                for (fields) |f| {
                    if (std.mem.eql(u8, f, field_name)) return;
                }
            } else {
                return; // all_fields
            }
        }
        const msg = try std.fmt.allocPrint(
            self.allocator,
            "field '{s}' not in capability list for account '{s}'",
            .{ field_name, account.name },
        );
        try self.diagnostics.add(.{
            .file = "",
            .line = span.line,
            .col = span.col,
            .len = span.len,
            .kind = CompileError.FieldNotInCapabilityList,
            .message = msg,
            .source_line = "",
        });
    }

    // ── Rule 4: Cross-Program State Isolation (Part 3.9) ─────────────────

    /// Verify that a write to a cross-program account is not attempted.
    fn checkCrossProgramAccess(
        self: *Checker,
        account: *const AccountDecl,
        span: Span,
    ) anyerror!void {
        switch (account.ownership) {
            .named => {
                const msg = try std.fmt.allocPrint(
                    self.allocator,
                    "cannot write to account '{s}' owned by another program",
                    .{account.name},
                );
                try self.diagnostics.add(.{
                    .file = "",
                    .line = span.line,
                    .col = span.col,
                    .len = span.len,
                    .kind = CompileError.CrossProgramStateAccess,
                    .message = msg,
                    .source_line = "",
                });
            },
            .global => {
                const msg = try std.fmt.allocPrint(
                    self.allocator,
                    "cannot write to global account '{s}'",
                    .{account.name},
                );
                try self.diagnostics.add(.{
                    .file = "",
                    .line = span.line,
                    .col = span.col,
                    .len = span.len,
                    .kind = CompileError.CrossProgramStateAccess,
                    .message = msg,
                    .source_line = "",
                });
            },
            else => {},
        }
    }

    // ── Rule 5: Parallel Safety (Part 3.9) ───────────────────────────────

    /// Verify an action marked #[parallel] has no shared-state writes.
    fn checkParallelSafety(
        self: *Checker,
        action: *const ActionDecl,
        access_list: *const AccessList,
    ) anyerror!void {
        var is_parallel = false;
        for (action.annotations) |ann| {
            if (ann.kind == .parallel) {
                is_parallel = true;
                break;
            }
        }
        if (!is_parallel) return;
        for (access_list.writes.items) |w| {
            if (w.field) |f| {
                if (std.mem.indexOf(u8, f, "caller") != null) continue;
                if (std.mem.indexOf(u8, f, "params.") != null) continue;
            }
            const msg = try std.fmt.allocPrint(
                self.allocator,
                "action '{s}' is #[parallel] but writes shared state '{s}'",
                .{ action.name, w.account_name },
            );
            try self.diagnostics.add(.{
                .file = "",
                .line = action.span.line,
                .col = action.span.col,
                .len = action.span.len,
                .kind = CompileError.UndeclaredWrite,
                .message = msg,
                .source_line = "",
            });
        }
    }

    // ── Authority Checking (Part 4) ──────────────────────────────────────

    /// Verify that all authority references in an `only` stmt are declared.
    fn checkOnlyStmt(
        self: *Checker,
        stmt: *const OnlyStmt,
        contract: *const ContractDef,
        span: Span,
    ) anyerror!void {
        switch (stmt.requirement) {
            .authority => |name| {
                try self.verifyAuthorityExists(name, contract, span);
            },
            .either => |pair| {
                try self.verifyAuthorityExists(pair.left, contract, span);
                try self.verifyAuthorityExists(pair.right, contract, span);
            },
            .any_signer => |name| {
                try self.verifyAuthorityExists(name, contract, span);
            },
            .address_list => {},
        }
    }

    /// Check a single authority name against the contract's authorities block.
    fn verifyAuthorityExists(
        self: *Checker,
        name: []const u8,
        contract: *const ContractDef,
        span: Span,
    ) anyerror!void {
        for (contract.authorities) |auth| {
            if (std.mem.eql(u8, auth.name, name)) return;
        }
        const msg = try std.fmt.allocPrint(
            self.allocator,
            "authority '{s}' is not declared in authorities block",
            .{name},
        );
        try self.diagnostics.add(.{
            .file = "",
            .line = span.line,
            .col = span.col,
            .len = span.len,
            .kind = CompileError.UnknownAuthority,
            .message = msg,
            .source_line = "",
        });
    }

    // ── Loop Annotation Enforcement (Part 6.3) ──────────────────────────

    /// Verify loops iterating over user params have #[max_iterations].
    fn checkLoopAnnotation(
        self: *Checker,
        loop: *const EachLoop,
        span: Span,
    ) anyerror!void {
        if (loop.max_iters != null) return;
        const is_user_param = switch (loop.collection.kind) {
            .field_access => |fa| blk: {
                switch (fa.object.kind) {
                    .identifier => |id| {
                        break :blk std.mem.eql(u8, id, "params");
                    },
                    else => break :blk false,
                }
            },
            .identifier => |id| std.mem.startsWith(u8, id, "params."),
            else => false,
        };
        if (is_user_param) {
            const msg = try std.fmt.allocPrint(
                self.allocator,
                "loop over user-supplied parameter requires #[max_iterations] annotation",
                .{},
            );
            try self.diagnostics.add(.{
                .file = "",
                .line = span.line,
                .col = span.col,
                .len = span.len,
                .kind = CompileError.UnboundedLoopMissingAnnotation,
                .message = msg,
                .source_line = "",
            });
        }
    }

    // ── Expression Type Checking ─────────────────────────────────────────

    /// Type-check an expression and return its resolved type.
    fn checkExpr(
        self: *Checker,
        expr: *const Expr,
        scope: *const SymbolTable,
    ) anyerror!ResolvedType {
        return switch (expr.kind) {
            .int_lit => .u256,
            .float_lit => .{ .fixed_point = 18 },
            .bool_lit => .bool,
            .string_lit => .string,
            .nothing => .void_,
            .something => |inner| {
                const inner_ty = try self.checkExpr(inner, scope);
                return .{ .maybe = try self.resolver.allocResolvedType(inner_ty) };
            },
            .identifier => |name| {
                // GAP-1: 'mine' is a special keyword referring to the
                // contract's own state — not a regular identifier.
                // It's always valid as the object of a field_access expr.
                if (std.mem.eql(u8, name, "mine")) return .void_;
                if (scope.lookup(name)) |sym| return sym.type_;
                const msg = try std.fmt.allocPrint(
                    self.allocator,
                    "identifier '{s}' is not declared in this scope",
                    .{name},
                );
                try self.diagnostics.add(.{
                    .file = "",
                    .line = expr.span.line,
                    .col = expr.span.col,
                    .len = expr.span.len,
                    .kind = CompileError.UndeclaredIdentifier,
                    .message = msg,
                    .source_line = "",
                });
                return .void_;
            },
            .field_access => |fa| {
                const obj_ty = try self.checkExpr(fa.object, scope);
                switch (obj_ty) {
                    .struct_ => |info| {
                        for (info.fields) |field| {
                            if (std.mem.eql(u8, field.name, fa.field)) return field.type_;
                        }
                        return .void_;
                    },
                    else => return .void_,
                }
            },
            .index_access => |ia| {
                const obj_ty = try self.checkExpr(ia.object, scope);
                switch (obj_ty) {
                    .map => |m| return m.value.*,
                    .enum_map => |m| return m.value.*,
                    .list => |inner| return inner.*,
                    .array => |a| return a.elem.*,
                    else => return .void_,
                }
            },
            .bin_op => |op| {
                const left_ty = try self.checkExpr(op.left, scope);
                const right_ty = try self.checkExpr(op.right, scope);
                switch (op.op) {
                    .plus, .minus, .times, .divided_by, .mod => {
                        if (!isNumeric(left_ty) or !isNumeric(right_ty)) {
                            const msg = try std.fmt.allocPrint(
                                self.allocator,
                                "arithmetic requires numeric types",
                                .{},
                            );
                            try self.diagnostics.add(.{
                                .file = "",
                                .line = expr.span.line,
                                .col = expr.span.col,
                                .len = expr.span.len,
                                .kind = CompileError.InvalidTypeForOperation,
                                .message = msg,
                                .source_line = "",
                            });
                        }
                        return left_ty;
                    },
                    .equals, .not_equals => {
                        if (!self.resolver.isCompatible(left_ty, right_ty) and
                            !self.resolver.isCompatible(right_ty, left_ty))
                        {
                            const msg = try std.fmt.allocPrint(
                                self.allocator,
                                "equality comparison requires same types",
                                .{},
                            );
                            try self.diagnostics.add(.{
                                .file = "",
                                .line = expr.span.line,
                                .col = expr.span.col,
                                .len = expr.span.len,
                                .kind = CompileError.TypeMismatch,
                                .message = msg,
                                .source_line = "",
                            });
                        }
                        return .bool;
                    },
                    .less, .less_eq, .greater, .greater_eq => return .bool,
                    .and_, .or_ => return .bool,
                    .has => return .bool,
                    .duration_add, .duration_sub => return .timestamp,
                }
            },
            .unary_op => |op| {
                const operand_ty = try self.checkExpr(op.operand, scope);
                return switch (op.op) {
                    .not_ => .bool,
                    .negate => operand_ty,
                };
            },
            .call => |c| {
                _ = try self.checkExpr(c.callee, scope);
                for (c.args) |arg| {
                    _ = try self.checkExpr(arg.value, scope);
                }
                return .void_;
            },
            .struct_lit => |sl| {
                for (sl.fields) |fi| {
                    _ = try self.checkExpr(fi.value, scope);
                }
                if (self.resolver.struct_defs.getPtr(sl.type_name)) |info| {
                    return .{ .struct_ = info };
                }
                return .void_;
            },
            .tuple_lit => |elems| {
                for (elems) |e| {
                    _ = try self.checkExpr(e, scope);
                }
                return .void_;
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
            .match_expr => |m| {
                _ = try self.checkExpr(m.subject, scope);
                return .void_;
            },
            .inline_when => |iw| {
                _ = try self.checkExpr(iw.cond, scope);
                const then_ty = try self.checkExpr(iw.then_, scope);
                _ = try self.checkExpr(iw.else_, scope);
                return then_ty;
            },
            .cast => |c| {
                _ = try self.checkExpr(c.expr, scope);
                return try self.resolver.resolve(c.to);
            },
            .try_propagate => |inner| {
                return try self.checkExpr(inner, scope);
            },
            else => .void_,
        };
    }

    // ── Access List Construction (Part 9.1) ──────────────────────────────

    /// Build the access list for an action by walking its body.
    fn buildAccessList(
        self: *Checker,
        action: *const ActionDecl,
        contract: *const ContractDef,
    ) anyerror!AccessList {
        var al = AccessList.init(self.allocator);
        // Walk annotations for manual overrides
        for (action.annotations) |ann| {
            switch (ann.kind) {
                .reads => {
                    for (ann.args) |arg| {
                        const field = extractMineField(arg);
                        if (field) |f| try al.addRead("mine", f);
                    }
                },
                .writes => {
                    for (ann.args) |arg| {
                        const field = extractMineField(arg);
                        if (field) |f| try al.addWrite("mine", f);
                    }
                },
                else => {},
            }
        }
        // Walk statement body for mine.X access
        for (action.body) |stmt| {
            try self.collectAccessFromStmt(&stmt, &al, contract);
        }
        return al;
    }

    /// Recursively collect access entries from a statement.
    fn collectAccessFromStmt(
        self: *Checker,
        stmt: *const Stmt,
        al: *AccessList,
        contract: *const ContractDef,
    ) anyerror!void {
        switch (stmt.kind) {
            .assign => |asg| {
                const field = extractMineFieldFromExpr(asg.target);
                if (field) |f| try al.addWrite("mine", f);
                self.collectAccessFromExpr(asg.value, al);
            },
            .aug_assign => |aug| {
                const field = extractMineFieldFromExpr(aug.target);
                if (field) |f| {
                    try al.addRead("mine", f);
                    try al.addWrite("mine", f);
                }
            },
            .let_bind => |lb| {
                self.collectAccessFromExpr(lb.init, al);
            },
            .when => |w| {
                self.collectAccessFromExpr(w.cond, al);
                for (w.then_body) |s| {
                    try self.collectAccessFromStmt(&s, al, contract);
                }
                if (w.else_body) |eb| {
                    for (eb) |s| {
                        try self.collectAccessFromStmt(&s, al, contract);
                    }
                }
            },
            .call_stmt => |expr| {
                self.collectAccessFromExpr(expr, al);
            },
            .give_back => |expr| {
                self.collectAccessFromExpr(expr, al);
            },
            else => {},
        }
    }

    /// Collect read accesses from an expression (mine.X reads).
    fn collectAccessFromExpr(self: *Checker, expr: *const Expr, al: *AccessList) void {
        _ = self;
        switch (expr.kind) {
            .field_access => |fa| {
                if (fa.object.kind == .identifier) {
                    const id = fa.object.kind.identifier;
                    if (std.mem.eql(u8, id, "mine")) {
                        al.addRead("mine", fa.field) catch {};
                    }
                }
            },
            else => {},
        }
    }

    // ── Invariant Checking ───────────────────────────────────────────────

    /// Verify each invariant expression resolves to bool.
    fn checkInvariants(
        self: *Checker,
        contract: *const ContractDef,
    ) anyerror!void {
        for (contract.invariants) |inv| {
            const ty = try self.checkExpr(inv.cond, &self.resolver.global_scope);
            if (std.meta.activeTag(ty) != .bool) {
                const msg = try std.fmt.allocPrint(
                    self.allocator,
                    "invariant '{s}' must evaluate to bool",
                    .{inv.name},
                );
                try self.diagnostics.add(.{
                    .file = "",
                    .line = inv.span.line,
                    .col = inv.span.col,
                    .len = inv.span.len,
                    .kind = CompileError.TypeMismatch,
                    .message = msg,
                    .source_line = "",
                });
            }
        }
    }

    // ── Statement Type Checking ──────────────────────────────────────────

    /// Type-check a single statement within a scope.
    fn checkStmt(
        self: *Checker,
        stmt: *const Stmt,
        scope: *SymbolTable,
        contract: *const ContractDef,
    ) anyerror!void {
        switch (stmt.kind) {
            .let_bind => |lb| {
                const init_ty = try self.checkExpr(lb.init, scope);
                const declared_ty = if (lb.declared_type) |dt|
                    try self.resolver.resolve(dt)
                else
                    init_ty;
                if (lb.declared_type != null) {
                    if (!self.resolver.isCompatible(init_ty, declared_ty)) {
                        const msg = try std.fmt.allocPrint(
                            self.allocator,
                            "type mismatch in let binding '{s}'",
                            .{lb.name},
                        );
                        try self.diagnostics.add(.{
                            .file = "",
                            .line = lb.span.line,
                            .col = lb.span.col,
                            .len = lb.span.len,
                            .kind = CompileError.TypeMismatch,
                            .message = msg,
                            .source_line = "",
                        });
                    }
                }
                try scope.define(lb.name, .{
                    .name = lb.name,
                    .kind = .local_var,
                    .type_ = declared_ty,
                    .span = lb.span,
                    .mutable = lb.mutable,
                });
            },
            .assign => |asg| {
                _ = try self.checkExpr(asg.target, scope);
                _ = try self.checkExpr(asg.value, scope);
            },
            .aug_assign => |aug| {
                _ = try self.checkExpr(aug.target, scope);
                _ = try self.checkExpr(aug.value, scope);
            },
            .when => |w| {
                _ = try self.checkExpr(w.cond, scope);
                for (w.then_body) |s| {
                    try self.checkStmt(&s, scope, contract);
                }
                for (w.else_ifs) |eif| {
                    _ = try self.checkExpr(eif.cond, scope);
                    for (eif.body) |s| {
                        try self.checkStmt(&s, scope, contract);
                    }
                }
                if (w.else_body) |eb| {
                    for (eb) |s| {
                        try self.checkStmt(&s, scope, contract);
                    }
                }
            },
            .each => |loop| {
                try self.checkLoopAnnotation(&loop, stmt.span);
                for (loop.body) |s| {
                    try self.checkStmt(&s, scope, contract);
                }
            },
            .repeat => |rep| {
                _ = try self.checkExpr(rep.count, scope);
                for (rep.body) |s| {
                    try self.checkStmt(&s, scope, contract);
                }
            },
            .while_ => |wl| {
                _ = try self.checkExpr(wl.cond, scope);
                for (wl.body) |s| {
                    try self.checkStmt(&s, scope, contract);
                }
            },
            .need => |n| {
                _ = try self.checkExpr(n.cond, scope);
            },
            .ensure => |e| {
                _ = try self.checkExpr(e.cond, scope);
            },
            .give_back => |expr| {
                _ = try self.checkExpr(expr, scope);
            },
            .call_stmt => |expr| {
                _ = try self.checkExpr(expr, scope);
            },
            .tell => |t| {
                for (t.args) |arg| {
                    _ = try self.checkExpr(arg.value, scope);
                }
            },
            .only => |o| {
                try self.checkOnlyStmt(&o, contract, stmt.span);
            },
            .match => |m| {
                _ = try self.checkExpr(m.subject, scope);
                for (m.arms) |arm| {
                    for (arm.body) |s| {
                        try self.checkStmt(&s, scope, contract);
                    }
                }
            },
            else => {},
        }
    }

    /// Walk a statement tree and recursively track where linear assets are consumed.
    fn trackLinearInStmt(
        self: *Checker,
        stmt: *const Stmt,
        tracker: *LinearTracker,
    ) anyerror!void {
        switch (stmt.kind) {
            .send => |s| {
                if (s.asset.kind == .identifier) {
                    try tracker.markConsumed(s.asset.kind.identifier, stmt.span, self.diagnostics);
                }
            },
            .move_asset => |m| {
                if (m.asset.kind == .identifier) {
                    try tracker.markConsumed(m.asset.kind.identifier, stmt.span, self.diagnostics);
                }
            },
            .call_stmt => |expr| {
                if (expr.kind == .call) {
                    const c = expr.kind.call;
                    if (c.callee.kind == .identifier and std.mem.eql(u8, c.callee.kind.identifier, "burn")) {
                        if (c.args.len >= 1 and c.args[0].value.kind == .identifier) {
                            try tracker.markConsumed(c.args[0].value.kind.identifier, stmt.span, self.diagnostics);
                        }
                    }
                }
            },
            .when => |w| {
                for (w.then_body) |s| {
                    try self.trackLinearInStmt(&s, tracker);
                }
                for (w.else_ifs) |eif| {
                    for (eif.body) |s| {
                        try self.trackLinearInStmt(&s, tracker);
                    }
                }
                if (w.else_body) |eb| {
                    for (eb) |s| {
                        try self.trackLinearInStmt(&s, tracker);
                    }
                }
            },
            .match => |m| {
                for (m.arms) |arm| {
                    for (arm.body) |s| {
                        try self.trackLinearInStmt(&s, tracker);
                    }
                }
            },
            .each => |loop| {
                for (loop.body) |s| {
                    try self.trackLinearInStmt(&s, tracker);
                }
            },
            .repeat => |rep| {
                for (rep.body) |s| {
                    try self.trackLinearInStmt(&s, tracker);
                }
            },
            .while_ => |wl| {
                for (wl.body) |s| {
                    try self.trackLinearInStmt(&s, tracker);
                }
            },
            .attempt => |att| {
                for (att.body) |s| {
                    try self.trackLinearInStmt(&s, tracker);
                }
                for (att.on_error) |oe| {
                    for (oe.body) |s| {
                        try self.trackLinearInStmt(&s, tracker);
                    }
                }
                if (att.always_body) |ab| {
                    for (ab) |s| {
                        try self.trackLinearInStmt(&s, tracker);
                    }
                }
            },
            .let_bind => {
                // Asset introductions do not consume assets, only usage.
            },
            else => {},
        }
    }

    // ── Built-in identifier injection (GAP-7) ───────────────────────────

    /// Inject standard built-in identifiers into a function scope so that
    /// identifiers like `caller`, `deployer`, `value`, `this`, `now`, and
    /// `zero_address` are always resolvable without emitting an
    /// UndeclaredIdentifier error, regardless of whether the parser emitted
    /// them as BuiltinExpr or plain identifier nodes.
    fn injectBuiltins(self: *Checker, scope: *SymbolTable, span: Span) anyerror!void {
        _ = self;
        const builtins = [_]struct { name: []const u8, type_: ResolvedType }{
            .{ .name = "caller",        .type_ = .wallet },
            .{ .name = "deployer",      .type_ = .account },
            .{ .name = "value",         .type_ = .u256 },
            .{ .name = "this",          .type_ = .program },
            .{ .name = "zero_address",  .type_ = .account },
            .{ .name = "now",           .type_ = .timestamp },
            .{ .name = "current_block", .type_ = .block_number },
            .{ .name = "gas_remaining", .type_ = .u64 },
        };
        for (builtins) |b| {
            scope.define(b.name, .{
                .name    = b.name,
                .kind    = .parameter,
                .type_   = b.type_,
                .span    = span,
                .mutable = false,
            }) catch |err| switch (err) {
                // Silently ignore duplicate — user param with same name shadows builtin
                error.DuplicateDeclaration => {},
                else => return err,
            };
        }
    }

    // ── Interface Verification (Part 2.9) ────────────────────────────────

    fn checkInterfaceConformance(
        self: *Checker,
        contract: *const ContractDef,
    ) anyerror!void {
        for (contract.implements) |interface_name| {
            const iface_opt = self.resolver.lookupInterface(interface_name);
            if (iface_opt == null) {
                const msg = try std.fmt.allocPrint(
                    self.allocator,
                    "interface '{s}' is not declared in this file",
                    .{interface_name},
                );
                try self.diagnostics.add(.{
                    .file = "",
                    .line = contract.span.line,
                    .col = contract.span.col,
                    .len = contract.span.len,
                    .kind = CompileError.UndeclaredType,
                    .message = msg,
                    .source_line = "",
                });
                continue;
            }
            const iface = iface_opt.?;

            for (iface.members) |member| {
                switch (member) {
                    .action => |iface_action| {
                        var found = false;
                        for (contract.actions) |contract_action| {
                            if (std.mem.eql(u8, contract_action.name, iface_action.name)) {
                                found = true;
                                if (contract_action.params.len != iface_action.params.len) {
                                    const msg = try std.fmt.allocPrint(
                                        self.allocator,
                                        "action '{s}' has {d} params but interface '{s}' requires {d}",
                                        .{ contract_action.name, contract_action.params.len, iface.name, iface_action.params.len },
                                    );
                                    try self.diagnostics.add(.{
                                        .file = "",
                                        .line = contract_action.span.line,
                                        .col = contract_action.span.col,
                                        .len = contract_action.span.len,
                                        .kind = CompileError.TypeMismatch,
                                        .message = msg,
                                        .source_line = "",
                                    });
                                } else {
                                    for (contract_action.params, 0..) |cparam, i| {
                                        const iparam = iface_action.params[i];
                                        const ctype = try self.resolver.resolve(cparam.declared_type);
                                        const itype = try self.resolver.resolve(iparam.declared_type);
                                        if (!self.resolver.isCompatible(ctype, itype)) {
                                            const msg = try std.fmt.allocPrint(
                                                self.allocator,
                                                "parameter '{s}' of action '{s}' does not match interface '{s}'",
                                                .{ cparam.name, contract_action.name, iface.name },
                                            );
                                            try self.diagnostics.add(.{
                                                .file = "",
                                                .line = cparam.span.line,
                                                .col = cparam.span.col,
                                                .len = cparam.span.len,
                                                .kind = CompileError.TypeMismatch,
                                                .message = msg,
                                                .source_line = "",
                                            });
                                        }
                                    }
                                }

                                if (iface_action.return_type != null) {
                                    if (contract_action.return_type == null) {
                                        const msg = try std.fmt.allocPrint(
                                            self.allocator,
                                            "action '{s}' must return a value per interface",
                                            .{contract_action.name},
                                        );
                                        try self.diagnostics.add(.{
                                            .file = "",
                                            .line = contract_action.span.line,
                                            .col = contract_action.span.col,
                                            .len = contract_action.span.len,
                                            .kind = CompileError.TypeMismatch,
                                            .message = msg,
                                            .source_line = "",
                                        });
                                    } else {
                                        const cret = try self.resolver.resolve(contract_action.return_type.?);
                                        const iret = try self.resolver.resolve(iface_action.return_type.?);
                                        if (!self.resolver.isCompatible(cret, iret)) {
                                            const msg = try std.fmt.allocPrint(
                                                self.allocator,
                                                "return type of action '{s}' does not match interface '{s}'",
                                                .{ contract_action.name, iface.name },
                                            );
                                            try self.diagnostics.add(.{
                                                .file = "",
                                                .line = contract_action.span.line,
                                                .col = contract_action.span.col,
                                                .len = contract_action.span.len,
                                                .kind = CompileError.TypeMismatch,
                                                .message = msg,
                                                .source_line = "",
                                            });
                                        }
                                    }
                                }
                                break;
                            }
                        }
                        if (!found) {
                            const msg = try std.fmt.allocPrint(
                                self.allocator,
                                "contract '{s}' claims to implement '{s}' but is missing required action '{s}'",
                                .{ contract.name, iface.name, iface_action.name },
                            );
                            try self.diagnostics.add(.{
                                .file = "",
                                .line = contract.span.line,
                                .col = contract.span.col,
                                .len = contract.span.len,
                                .kind = CompileError.UndeclaredIdentifier,
                                .message = msg,
                                .source_line = "",
                            });
                        }
                    },
                    .view => |iface_view| {
                        var found = false;
                        for (contract.views) |contract_view| {
                            if (std.mem.eql(u8, contract_view.name, iface_view.name)) {
                                found = true;
                                if (contract_view.params.len != iface_view.params.len) {
                                    const msg = try std.fmt.allocPrint(
                                        self.allocator,
                                        "view '{s}' has {d} params but interface '{s}' requires {d}",
                                        .{ contract_view.name, contract_view.params.len, iface.name, iface_view.params.len },
                                    );
                                    try self.diagnostics.add(.{
                                        .file = "",
                                        .line = contract_view.span.line,
                                        .col = contract_view.span.col,
                                        .len = contract_view.span.len,
                                        .kind = CompileError.TypeMismatch,
                                        .message = msg,
                                        .source_line = "",
                                    });
                                } else {
                                    for (contract_view.params, 0..) |cparam, i| {
                                        const iparam = iface_view.params[i];
                                        const ctype = try self.resolver.resolve(cparam.declared_type);
                                        const itype = try self.resolver.resolve(iparam.declared_type);
                                        if (!self.resolver.isCompatible(ctype, itype)) {
                                            const msg = try std.fmt.allocPrint(
                                                self.allocator,
                                                "parameter '{s}' of view '{s}' does not match interface '{s}'",
                                                .{ cparam.name, contract_view.name, iface.name },
                                            );
                                            try self.diagnostics.add(.{
                                                .file = "",
                                                .line = cparam.span.line,
                                                .col = cparam.span.col,
                                                .len = cparam.span.len,
                                                .kind = CompileError.TypeMismatch,
                                                .message = msg,
                                                .source_line = "",
                                            });
                                        }
                                    }
                                }

                                if (iface_view.return_type != null) {
                                    if (contract_view.return_type == null) {
                                        const msg = try std.fmt.allocPrint(
                                            self.allocator,
                                            "view '{s}' must return a value per interface",
                                            .{contract_view.name},
                                        );
                                        try self.diagnostics.add(.{
                                            .file = "",
                                            .line = contract_view.span.line,
                                            .col = contract_view.span.col,
                                            .len = contract_view.span.len,
                                            .kind = CompileError.TypeMismatch,
                                            .message = msg,
                                            .source_line = "",
                                        });
                                    } else {
                                        const cret = try self.resolver.resolve(contract_view.return_type.?);
                                        const iret = try self.resolver.resolve(iface_view.return_type.?);
                                        if (!self.resolver.isCompatible(cret, iret)) {
                                            const msg = try std.fmt.allocPrint(
                                                self.allocator,
                                                "return type of view '{s}' does not match interface '{s}'",
                                                .{ contract_view.name, iface.name },
                                            );
                                            try self.diagnostics.add(.{
                                                .file = "",
                                                .line = contract_view.span.line,
                                                .col = contract_view.span.col,
                                                .len = contract_view.span.len,
                                                .kind = CompileError.TypeMismatch,
                                                .message = msg,
                                                .source_line = "",
                                            });
                                        }
                                    }
                                }
                                break;
                            }
                        }
                        if (!found) {
                            const msg = try std.fmt.allocPrint(
                                self.allocator,
                                "contract '{s}' claims to implement '{s}' but is missing required view '{s}'",
                                .{ contract.name, iface.name, iface_view.name },
                            );
                            try self.diagnostics.add(.{
                                .file = "",
                                .line = contract.span.line,
                                .col = contract.span.col,
                                .len = contract.span.len,
                                .kind = CompileError.UndeclaredIdentifier,
                                .message = msg,
                                .source_line = "",
                            });
                        }
                    },
                    .event => |iface_event| {
                        var found = false;
                        for (contract.events) |contract_event| {
                            if (std.mem.eql(u8, contract_event.name, iface_event.name)) {
                                if (contract_event.fields.len == iface_event.fields.len) {
                                    found = true;
                                }
                                break;
                            }
                        }
                        if (!found) {
                            const msg = try std.fmt.allocPrint(
                                self.allocator,
                                "contract '{s}' claims to implement '{s}' but is missing required event '{s}'",
                                .{ contract.name, iface.name, iface_event.name },
                            );
                            try self.diagnostics.add(.{
                                .file = "",
                                .line = contract.span.line,
                                .col = contract.span.col,
                                .len = contract.span.len,
                                .kind = CompileError.UndeclaredIdentifier,
                                .message = msg,
                                .source_line = "",
                            });
                        }
                    },
                    .error_ => |iface_error| {
                        var found = false;
                        for (contract.errors_) |contract_error| {
                            if (std.mem.eql(u8, contract_error.name, iface_error.name)) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            const msg = try std.fmt.allocPrint(
                                self.allocator,
                                "contract '{s}' claims to implement '{s}' but is missing required error '{s}'",
                                .{ contract.name, iface.name, iface_error.name },
                            );
                            try self.diagnostics.add(.{
                                .file = "",
                                .line = contract.span.line,
                                .col = contract.span.col,
                                .len = contract.span.len,
                                .kind = CompileError.UndeclaredIdentifier,
                                .message = msg,
                                .source_line = "",
                            });
                        }
                    },
                }
            }
        }
    }

    // ── Contract Inheritance (Part B) ────────────────────────────────────

    fn resolveInheritedScope(
        self: *Checker,
        contract: *const ContractDef,
        scope: *SymbolTable,
        depth: u32,
    ) anyerror!void {
        if (depth > 16) {
            return error.InternalError;
        }
        if (contract.inherits) |parent_name| {
            const parent_opt = self.resolver.lookupContract(parent_name);
            if (parent_opt == null) {
                const msg = try std.fmt.allocPrint(
                    self.allocator,
                    "contract '{s}' inherits from '{s}' which is not declared in this file",
                    .{contract.name, parent_name},
                );
                try self.diagnostics.add(.{
                    .file = "",
                    .line = contract.span.line,
                    .col = contract.span.col,
                    .len = contract.span.len,
                    .kind = CompileError.UndeclaredType,
                    .message = msg,
                    .source_line = "",
                });
                return;
            }
            const parent_contract = parent_opt.?;

            try self.resolveInheritedScope(&parent_contract, scope, depth + 1);

            for (parent_contract.state) |sf| {
                const resolved = try self.resolver.resolve(sf.type_);
                scope.define(sf.name, .{
                    .name = sf.name,
                    .kind = .state_field,
                    .type_ = resolved,
                    .span = sf.span,
                    .mutable = true,
                }) catch |err| switch (err) {
                    error.DuplicateDeclaration => {},
                    else => return err,
                };
            }

            for (parent_contract.authorities) |au| {
                scope.define(au.name, .{
                    .name = au.name,
                    .kind = .authority,
                    .type_ = .void_,
                    .span = au.span,
                    .mutable = false,
                }) catch |err| switch (err) {
                    error.DuplicateDeclaration => {},
                    else => return err,
                };
            }

            for (parent_contract.actions) |ac| {
                const resolved = if (ac.return_type) |rt| try self.resolver.resolve(rt) else ResolvedType.void_;
                scope.define(ac.name, .{
                    .name = ac.name,
                    .kind = .action,
                    .type_ = resolved,
                    .span = ac.span,
                    .mutable = false,
                }) catch |err| switch (err) {
                    error.DuplicateDeclaration => {},
                    else => return err,
                };
            }

            for (parent_contract.views) |vw| {
                const resolved = if (vw.return_type) |rt| try self.resolver.resolve(rt) else ResolvedType.void_;
                scope.define(vw.name, .{
                    .name = vw.name,
                    .kind = .view,
                    .type_ = resolved,
                    .span = vw.span,
                    .mutable = false,
                }) catch |err| switch (err) {
                    error.DuplicateDeclaration => {},
                    else => return err,
                };
            }

            for (parent_contract.events) |ev| {
                scope.define(ev.name, .{
                    .name = ev.name,
                    .kind = .event,
                    .type_ = .void_,
                    .span = ev.span,
                    .mutable = false,
                }) catch |err| switch (err) {
                    error.DuplicateDeclaration => {},
                    else => return err,
                };
            }

            for (parent_contract.guards) |gd| {
                scope.define(gd.name, .{
                    .name = gd.name,
                    .kind = .guard,
                    .type_ = .void_,
                    .span = gd.span,
                    .mutable = false,
                }) catch |err| switch (err) {
                    error.DuplicateDeclaration => {},
                    else => return err,
                };
            }
        }
    }

    // ── Main Contract Check ──────────────────────────────────────────────

    /// Check a full contract — type-check all bodies, enforce all rules,
    /// build access lists, verify invariants.
    pub fn checkContract(
        self: *Checker,
        contract: *const ContractDef,
    ) anyerror!CheckedContract {
        var result = CheckedContract{
            .name = contract.name,
            .action_lists = std.StringHashMap(AccessList).init(self.allocator),
            .type_map = std.StringHashMap(ResolvedType).init(self.allocator),
            .scope = SymbolTable.init(self.allocator, &self.resolver.global_scope),
            .allocator = self.allocator,
        };

        // Resolve inherited symbols into the contract scope.
        // Must happen BEFORE registering this contract's own state fields,
        // so that child definitions correctly shadow parent definitions.
        try self.resolveInheritedScope(contract, &result.scope, 0);

        // Register state fields into the contract scope
        for (contract.state) |sf| {
            const resolved = try self.resolver.resolve(sf.type_);
            result.scope.define(sf.name, .{
                .name = sf.name,
                .kind = .state_field,
                .type_ = resolved,
                .span = sf.span,
                .mutable = true,
            }) catch |err| switch (err) {
                error.DuplicateDeclaration => {
                    try result.scope.symbols.put(sf.name, .{
                        .name = sf.name,
                        .kind = .state_field,
                        .type_ = resolved,
                        .span = sf.span,
                        .mutable = true,
                    });
                },
                else => return err,
            };
            try result.type_map.put(sf.name, resolved);
        }
        // Check each action
        for (contract.actions) |action| {
            var action_scope = SymbolTable.init(self.allocator, &result.scope);
            defer action_scope.deinit();
            // GAP-7: inject built-in identifiers available in every action
            try self.injectBuiltins(&action_scope, action.span);
            // Register parameters
            for (action.params) |param| {
                const param_ty = try self.resolver.resolve(param.declared_type);
                try action_scope.define(param.name, .{
                    .name = param.name,
                    .kind = .parameter,
                    .type_ = param_ty,
                    .span = param.span,
                    .mutable = false,
                });
            }
            // Type-check body AND track linear asset consumption
            var linear_tracker = LinearTracker.init(self.allocator);
            defer linear_tracker.deinit();

            for (action.body) |stmt| {
                try self.checkStmt(&stmt, &action_scope, contract);
                try self.trackLinearInStmt(&stmt, &linear_tracker);
            }

            // At end of action scope: verify all linear variables were consumed
            try linear_tracker.checkAllConsumed(&action_scope, self.diagnostics);

            // Build access list and enforce rules
            var al = try self.buildAccessList(&action, contract);
            try self.checkParallelSafety(&action, &al);
            try result.action_lists.put(action.name, al);
        }
        // Check views
        for (contract.views) |view| {
            var view_scope = SymbolTable.init(self.allocator, &result.scope);
            defer view_scope.deinit();
            // GAP-7: built-in identifiers available in views too
            try self.injectBuiltins(&view_scope, view.span);
            for (view.params) |param| {
                const param_ty = try self.resolver.resolve(param.declared_type);
                try view_scope.define(param.name, .{
                    .name = param.name,
                    .kind = .parameter,
                    .type_ = param_ty,
                    .span = param.span,
                    .mutable = false,
                });
            }
            for (view.body) |stmt| {
                try self.checkStmt(&stmt, &view_scope, contract);
            }
        }
        // Check pure functions
        for (contract.pures) |pure| {
            var pure_scope = SymbolTable.init(self.allocator, &result.scope);
            defer pure_scope.deinit();
            for (pure.params) |param| {
                const param_ty = try self.resolver.resolve(param.declared_type);
                try pure_scope.define(param.name, .{
                    .name = param.name,
                    .kind = .parameter,
                    .type_ = param_ty,
                    .span = param.span,
                    .mutable = false,
                });
            }
            for (pure.body) |stmt| {
                try self.checkStmt(&stmt, &pure_scope, contract);
            }
        }
        // Check setup block if present
        if (contract.setup) |setup| {
            var setup_scope = SymbolTable.init(self.allocator, &result.scope);
            defer setup_scope.deinit();
            try self.injectBuiltins(&setup_scope, setup.span);
            for (setup.params) |param| {
                const param_ty = try self.resolver.resolve(param.declared_type);
                try setup_scope.define(param.name, .{
                    .name = param.name,
                    .kind = .parameter,
                    .type_ = param_ty,
                    .span = param.span,
                    .mutable = false,
                });
            }
            for (setup.body) |stmt| {
                try self.checkStmt(&stmt, &setup_scope, contract);
            }
        }
        // Verify interface conformance for all declared implementations
        try self.checkInterfaceConformance(contract);

        // Check invariants
        try self.checkInvariants(contract);
        return result;
    }
};

// ============================================================================
// Section 5 — Free-Standing Helpers
// ============================================================================

/// Extract a field name from a `mine.field` expression node.
fn extractMineField(expr: *const Expr) ?[]const u8 {
    switch (expr.kind) {
        .field_access => |fa| {
            switch (fa.object.kind) {
                .identifier => |id| {
                    if (std.mem.eql(u8, id, "mine")) return fa.field;
                },
                else => {},
            }
        },
        else => {},
    }
    return null;
}

/// Extract a field name from an expression pointer (alias for consistency).
fn extractMineFieldFromExpr(expr: *const Expr) ?[]const u8 {
    return extractMineField(expr);
}

/// Check if a resolved type is numeric (integer or fixed-point).
fn isNumeric(ty: ResolvedType) bool {
    const tag = std.meta.activeTag(ty);
    return switch (tag) {
        .u8, .u16, .u32, .u64, .u128, .u256 => true,
        .i8, .i16, .i32, .i64, .i128, .i256 => true,
        .fixed_point => true,
        else => false,
    };
}

/// Find an account declaration by name within a contract.
fn findAccount(contract: *const ContractDef, name: []const u8) ?AccountDecl {
    for (contract.accounts) |acct| {
        if (std.mem.eql(u8, acct.name, name)) return acct;
    }
    return null;
}

// ============================================================================
// Section 6 — Tests
// ============================================================================

test "undeclared account access error" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var checker = Checker.init(&resolver, &diags, allocator);

    const empty_accounts: []const AccountDecl = &.{};
    const span = Span{ .line = 10, .col = 5, .len = 7 };
    try checker.checkAccountAccess(empty_accounts, "treasury", span);

    try std.testing.expect(diags.hasErrors());
    const d = diags.items.items[0];
    try std.testing.expectEqual(CompileError.AccountNotDeclared, d.kind);
    try std.testing.expect(std.mem.indexOf(u8, d.message, "treasury") != null);
}

test "readonly write error" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var checker = Checker.init(&resolver, &diags, allocator);

    const acct = AccountDecl{
        .name = "oracle",
        .kind = .oracle,
        .type_param = null,
        .ownership = .global,
        .seeds = &.{},
        .readonly = true,
        .capabilities = &.{},
        .create_if_missing = false,
        .initial_size = null,
        .known_address = null,
        .child_of = null,
        .span = .{ .line = 5, .col = 1, .len = 6 },
    };
    const span = Span{ .line = 20, .col = 9, .len = 5 };
    try checker.checkReadonlyViolation(&acct, true, span);

    try std.testing.expect(diags.hasErrors());
    try std.testing.expectEqual(CompileError.CannotAssignToReadonly, diags.items.items[0].kind);
}

test "unknown authority error" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var checker = Checker.init(&resolver, &diags, allocator);

    const contract = makeEmptyContract("TestContract");
    const only = OnlyStmt{
        .requirement = .{ .authority = "ghost_authority" },
        .span = .{ .line = 15, .col = 9, .len = 15 },
    };
    const span = Span{ .line = 15, .col = 9, .len = 15 };
    try checker.checkOnlyStmt(&only, &contract, span);

    try std.testing.expect(diags.hasErrors());
    try std.testing.expectEqual(CompileError.UnknownAuthority, diags.items.items[0].kind);
}

test "parallel action with shared write error" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();
    var checker = Checker.init(&resolver, &diags, allocator);

    var al = AccessList.init(allocator);
    defer al.deinit();
    try al.addWrite("mine", "total_supply");

    var annotations_buf = [_]Annotation{.{
        .kind = .parallel,
        .args = &.{},
        .span = .{ .line = 1, .col = 1, .len = 10 },
    }};
    const action = ActionDecl{
        .name = "transfer",
        .visibility = .shared,
        .type_params = &.{},
        .params = &.{},
        .return_type = null,
        .annotations = &annotations_buf,
        .accounts = &.{},
        .body = &.{},
        .span = .{ .line = 1, .col = 1, .len = 8 },
    };
    try checker.checkParallelSafety(&action, &al);

    try std.testing.expect(diags.hasErrors());
    try std.testing.expectEqual(CompileError.UndeclaredWrite, diags.items.items[0].kind);
}

test "linear asset double use error" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var tracker = LinearTracker.init(allocator);
    defer tracker.deinit();

    const span = Span{ .line = 30, .col = 5, .len = 5 };
    try tracker.markConsumed("token", span, &diags);
    try std.testing.expect(!diags.hasErrors());

    try tracker.markConsumed("token", span, &diags);
    try std.testing.expect(diags.hasErrors());
    try std.testing.expectEqual(CompileError.LinearAssetUsedTwice, diags.items.items[0].kind);
}

test "linear asset dropped error" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var tracker = LinearTracker.init(allocator);
    defer tracker.deinit();

    // Create a scope with a linear variable that is NOT consumed
    var scope = SymbolTable.init(allocator, null);
    defer scope.deinit();

    const inner_ptr = try allocator.create(ResolvedType);
    defer allocator.destroy(inner_ptr);
    inner_ptr.* = .u256;
    try scope.define("my_asset", .{
        .name = "my_asset",
        .kind = .local_var,
        .type_ = .{ .linear = inner_ptr },
        .span = .{ .line = 40, .col = 5, .len = 8 },
        .mutable = false,
    });

    try tracker.checkAllConsumed(&scope, &diags);
    try std.testing.expect(diags.hasErrors());
    try std.testing.expectEqual(CompileError.LinearAssetDropped, diags.items.items[0].kind);
}

test "access list build for simple transfer action" {
    const allocator = std.testing.allocator;
    var al = AccessList.init(allocator);
    defer al.deinit();

    // Simulate a simple transfer: read sender balance, write sender & recipient
    try al.addRead("mine", "balances");
    try al.addWrite("mine", "balances");

    try std.testing.expectEqual(@as(usize, 1), al.reads.items.len);
    try std.testing.expectEqual(@as(usize, 1), al.writes.items.len);
    try std.testing.expect(std.mem.eql(u8, al.reads.items[0].account_name, "mine"));
    try std.testing.expect(std.mem.eql(u8, al.writes.items[0].field.?, "balances"));

    // Two access lists writing same field should conflict
    var al2 = AccessList.init(allocator);
    defer al2.deinit();
    try al2.addWrite("mine", "balances");
    try std.testing.expect(al.conflictsWith(&al2));

    // Non-overlapping writes should not conflict
    var al3 = AccessList.init(allocator);
    defer al3.deinit();
    try al3.addWrite("mine", "prices");
    try std.testing.expect(!al.conflictsWith(&al3));
}

// ── Test Helper ──────────────────────────────────────────────────────────────

/// Create an empty ContractDef for testing purposes.
fn makeEmptyContract(name: []const u8) ContractDef {
    return .{
        .name = name,
        .inherits = null,
        .implements = &.{},
        .accounts = &.{},
        .authorities = &.{},
        .config = &.{},
        .always = &.{},
        .state = &.{},
        .computed = &.{},
        .setup = null,
        .guards = &.{},
        .actions = &.{},
        .views = &.{},
        .pures = &.{},
        .helpers = &.{},
        .events = &.{},
        .errors_ = &.{},
        .upgrade = null,
        .namespaces = &.{},
        .invariants = &.{},
        .span = .{ .line = 1, .col = 1, .len = 12 },
    };
}

test "linear asset consumed by send is not an error" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    // Setup a linear type alias
    const inner_ptr = try allocator.create(ResolvedType);
    defer allocator.destroy(inner_ptr);
    inner_ptr.* = .u256;
    try resolver.type_aliases.put("LinearToken", .{ .linear = inner_ptr });

    var checker = Checker.init(&resolver, &diags, allocator);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Pre-declare 'source_asset' so we can initialize 'token' with it
    try checker.resolver.global_scope.define("source_asset", .{
        .name = "source_asset",
        .kind = .constant,
        .type_ = .{ .linear = inner_ptr },
        .span = Span{ .line=1, .col=1, .len=10 },
        .mutable = false,
    });

    var contract = makeEmptyContract("TestContract");

    var init_expr = Expr{ .kind = .{ .identifier = "source_asset" }, .span = Span{ .line=1, .col=1, .len=12 } };
    var asset_expr = Expr{ .kind = .{ .identifier = "token" }, .span = Span{ .line=2, .col=1, .len=5 } };
    var recipient_expr = Expr{ .kind = .{ .builtin = .zero_address }, .span = Span{ .line=2, .col=10, .len=12 } };

    var body = try alloc.alloc(Stmt, 2);
    body[0] = Stmt{
        .kind = .{ .let_bind = .{
            .name = "token",
            .declared_type = .{ .named = "LinearToken" },
            .init = &init_expr,
            .mutable = false,
            .span = Span{ .line=1, .col=1, .len=10 },
        }},
        .span = Span{ .line=1, .col=1, .len=10 }
    };
    body[1] = Stmt{
        .kind = .{ .send = .{ .asset = &asset_expr, .recipient = &recipient_expr } },
        .span = Span{ .line=2, .col=1, .len=20 }
    };

    const action = ast.ActionDecl{
        .name = "do_send",
        .visibility = .shared,
        .type_params = &.{},
        .params = &.{},
        .return_type = null,
        .annotations = &.{},
        .accounts = &.{},
        .body = body,
        .span = Span{ .line=1, .col=1, .len=30 },
    };
    
    contract.actions = try alloc.alloc(ast.ActionDecl, 1);
    contract.actions[0] = action;

    var checked = try checker.checkContract(&contract);
    defer checked.deinit();

    try std.testing.expect(!diags.hasErrors());
}

test "linear asset dropped without send is an error" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    const inner_ptr = try allocator.create(ResolvedType);
    defer allocator.destroy(inner_ptr);
    inner_ptr.* = .u256;
    try resolver.type_aliases.put("LinearToken", .{ .linear = inner_ptr });

    var checker = Checker.init(&resolver, &diags, allocator);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Pre-declare 'source_asset'
    try checker.resolver.global_scope.define("source_asset", .{
        .name = "source_asset",
        .kind = .constant,
        .type_ = .{ .linear = inner_ptr },
        .span = Span{ .line=1, .col=1, .len=10 },
        .mutable = false,
    });

    var contract = makeEmptyContract("TestContract");

    var init_expr = Expr{ .kind = .{ .identifier = "source_asset" }, .span = Span{ .line=1, .col=1, .len=12 } };

    var body = try alloc.alloc(Stmt, 1);
    body[0] = Stmt{
        .kind = .{ .let_bind = .{
            .name = "token",
            .declared_type = .{ .named = "LinearToken" },
            .init = &init_expr,
            .mutable = false,
            .span = Span{ .line=1, .col=1, .len=10 },
        }},
        .span = Span{ .line=1, .col=1, .len=10 }
    };

    const action = ast.ActionDecl{
        .name = "do_drop",
        .visibility = .shared,
        .type_params = &.{},
        .params = &.{},
        .return_type = null,
        .annotations = &.{},
        .accounts = &.{},
        .body = body,
        .span = Span{ .line=1, .col=1, .len=30 },
    };
    contract.actions = try alloc.alloc(ast.ActionDecl, 1);
    contract.actions[0] = action;

    var checked = try checker.checkContract(&contract);
    defer checked.deinit();

    try std.testing.expect(diags.hasErrors());
    try std.testing.expectEqual(CompileError.LinearAssetDropped, diags.items.items[0].kind);
}

test "linear asset consumed twice is an error" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    const inner_ptr = try allocator.create(ResolvedType);
    defer allocator.destroy(inner_ptr);
    inner_ptr.* = .u256;
    try resolver.type_aliases.put("LinearToken", .{ .linear = inner_ptr });

    var checker = Checker.init(&resolver, &diags, allocator);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Pre-declare 'source_asset'
    try checker.resolver.global_scope.define("source_asset", .{
        .name = "source_asset",
        .kind = .constant,
        .type_ = .{ .linear = inner_ptr },
        .span = Span{ .line=1, .col=1, .len=10 },
        .mutable = false,
    });

    var contract = makeEmptyContract("TestContract");

    var init_expr = Expr{ .kind = .{ .identifier = "source_asset" }, .span = Span{ .line=1, .col=1, .len=12 } };
    var asset_expr = Expr{ .kind = .{ .identifier = "token" }, .span = Span{ .line=2, .col=1, .len=5 } };
    var recipient_expr = Expr{ .kind = .{ .builtin = .zero_address }, .span = Span{ .line=2, .col=10, .len=12 } };

    var body = try alloc.alloc(Stmt, 3);
    body[0] = Stmt{
        .kind = .{ .let_bind = .{
            .name = "token",
            .declared_type = .{ .named = "LinearToken" },
            .init = &init_expr,
            .mutable = false,
            .span = Span{ .line=1, .col=1, .len=10 },
        }},
        .span = Span{ .line=1, .col=1, .len=10 }
    };
    body[1] = Stmt{
        .kind = .{ .send = .{ .asset = &asset_expr, .recipient = &recipient_expr } },
        .span = Span{ .line=2, .col=1, .len=20 }
    };
    body[2] = Stmt{
        .kind = .{ .send = .{ .asset = &asset_expr, .recipient = &recipient_expr } },
        .span = Span{ .line=3, .col=1, .len=20 }
    };

    const action = ast.ActionDecl{
        .name = "do_send_twice",
        .visibility = .shared,
        .type_params = &.{},
        .params = &.{},
        .return_type = null,
        .annotations = &.{},
        .accounts = &.{},
        .body = body,
        .span = Span{ .line=1, .col=1, .len=30 },
    };
    contract.actions = try alloc.alloc(ast.ActionDecl, 1);
    contract.actions[0] = action;

    var checked = try checker.checkContract(&contract);
    defer checked.deinit();

    try std.testing.expect(diags.hasErrors());
    try std.testing.expectEqual(CompileError.LinearAssetUsedTwice, diags.items.items[0].kind);
}

test "views do not enforce linear tracking" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    const inner_ptr = try allocator.create(ResolvedType);
    defer allocator.destroy(inner_ptr);
    inner_ptr.* = .u256;
    try resolver.type_aliases.put("LinearToken", .{ .linear = inner_ptr });

    var checker = Checker.init(&resolver, &diags, allocator);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Pre-declare 'source_asset'
    try checker.resolver.global_scope.define("source_asset", .{
        .name = "source_asset",
        .kind = .constant,
        .type_ = .{ .linear = inner_ptr },
        .span = Span{ .line=1, .col=1, .len=10 },
        .mutable = false,
    });

    var contract = makeEmptyContract("TestContract");

    var init_expr = Expr{ .kind = .{ .identifier = "source_asset" }, .span = Span{ .line=1, .col=1, .len=12 } };

    var body = try alloc.alloc(Stmt, 1);
    body[0] = Stmt{
        .kind = .{ .let_bind = .{
            .name = "token",
            .declared_type = .{ .named = "LinearToken" },
            .init = &init_expr,
            .mutable = false,
            .span = Span{ .line=1, .col=1, .len=10 },
        }},
        .span = Span{ .line=1, .col=1, .len=10 }
    };

    const view_decl = ast.ViewDecl{
        .name = "read_asset",
        .visibility = .shared,
        .type_params = &.{},
        .params = &.{},
        .return_type = null,
        .accounts = &.{},
        .body = body,
        .span = Span{ .line=1, .col=1, .len=30 },
    };
    contract.views = try alloc.alloc(ast.ViewDecl, 1);
    contract.views[0] = view_decl;

    var checked = try checker.checkContract(&contract);
    defer checked.deinit();

    var has_dropped = false;
    for (diags.items.items) |d| {
        if (d.kind == CompileError.LinearAssetDropped) {
            has_dropped = true;
        }
    }
    try std.testing.expect(!has_dropped);
}

test "child contract can access parent state fields" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var base_contract = makeEmptyContract("BaseToken");
    var base_state = [_]ast.StateField{
        .{ .name = "total_supply", .type_ = .u256, .span = Span{ .line = 1, .col = 1, .len = 12 }, .namespace = null },
    };
    base_contract.state = &base_state;
    const tops = [_]ast.TopLevel{.{ .contract = base_contract }};
    try resolver.registerTopLevel(&tops);

    var checker = Checker.init(&resolver, &diags, allocator);

    var child = makeEmptyContract("Token");
    child.inherits = "BaseToken";

    // Action that reads "total_supply"
    var read_expr = ast.Expr{ .kind = .{ .identifier = "total_supply" }, .span = Span{ .line = 2, .col = 1, .len = 12 } };
    var stmts = [_]ast.Stmt{
        .{ .kind = .{ .let_bind = .{ .name = "_", .declared_type = null, .init = &read_expr, .mutable = false, .span = Span{ .line = 2, .col = 1, .len = 12 } } }, .span = Span{ .line = 2, .col = 1, .len = 12 } },
    };
    const act = ast.ActionDecl{
        .name = "read_supply",
        .visibility = .shared,
        .type_params = &.{},
        .params = &.{},
        .return_type = null,
        .annotations = &.{},
        .accounts = &.{},
        .body = &stmts,
        .span = Span{ .line = 1, .col = 1, .len = 12 },
    };
    var child_actions = [_]ast.ActionDecl{act};
    child.actions = &child_actions;

    var checked = try checker.checkContract(&child);
    defer checked.deinit();

    try std.testing.expect(!diags.hasErrors());
}

test "child contract state shadows parent state" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var parent = makeEmptyContract("Parent");
    var parent_state = [_]ast.StateField{
        .{ .name = "owner", .type_ = .account, .span = Span{ .line = 1, .col = 1, .len = 5 }, .namespace = null },
    };
    parent.state = &parent_state;
    const tops = [_]ast.TopLevel{.{ .contract = parent }};
    try resolver.registerTopLevel(&tops);

    var checker = Checker.init(&resolver, &diags, allocator);

    var child = makeEmptyContract("Child");
    child.inherits = "Parent";
    var child_state = [_]ast.StateField{
        .{ .name = "owner", .type_ = .account, .span = Span{ .line = 2, .col = 1, .len = 5 }, .namespace = null },
    };
    child.state = &child_state;

    var checked = try checker.checkContract(&child);
    defer checked.deinit();

    try std.testing.expect(!diags.hasErrors());
}

test "inheriting from unknown contract emits UndeclaredType" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var checker = Checker.init(&resolver, &diags, allocator);

    var child = makeEmptyContract("Child");
    child.inherits = "GhostContract";

    var checked = try checker.checkContract(&child);
    defer checked.deinit();

    try std.testing.expect(diags.hasErrors());
    try std.testing.expectEqual(CompileError.UndeclaredType, diags.items.items[0].kind);
}

test "inheritance chain: grandchild sees grandparent fields" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    var grand = makeEmptyContract("GrandParent");
    var grand_state = [_]ast.StateField{
        .{ .name = "x", .type_ = .u64, .span = Span{ .line = 1, .col = 1, .len = 1 }, .namespace = null },
    };
    grand.state = &grand_state;

    var parent = makeEmptyContract("Parent");
    parent.inherits = "GrandParent";

    const tops = [_]ast.TopLevel{
        .{ .contract = grand },
        .{ .contract = parent },
    };
    try resolver.registerTopLevel(&tops);

    var checker = Checker.init(&resolver, &diags, allocator);

    var child = makeEmptyContract("Child");
    child.inherits = "Parent";

    var read_expr = ast.Expr{ .kind = .{ .identifier = "x" }, .span = Span{ .line = 2, .col = 1, .len = 1 } };
    var stmts = [_]ast.Stmt{
        .{ .kind = .{ .let_bind = .{ .name = "_", .declared_type = null, .init = &read_expr, .mutable = false, .span = Span{ .line = 2, .col = 1, .len = 1 } } }, .span = Span{ .line = 2, .col = 1, .len = 1 } },
    };
    const act = ast.ActionDecl{
        .name = "read_x",
        .visibility = .shared,
        .type_params = &.{},
        .params = &.{},
        .return_type = null,
        .annotations = &.{},
        .accounts = &.{},
        .body = &stmts,
        .span = Span{ .line = 3, .col = 1, .len = 1 },
    };
    var child_actions = [_]ast.ActionDecl{act};
    child.actions = &child_actions;

    var checked = try checker.checkContract(&child);
    defer checked.deinit();

    try std.testing.expect(!diags.hasErrors());
}

test "resolveInheritedScope depth limit prevents stack overflow" {
    const allocator = std.testing.allocator;
    var diags = DiagnosticList.init(allocator);
    defer diags.deinit();
    var resolver = TypeResolver.init(allocator, &diags);
    defer resolver.deinit();

    const names = [_][]const u8{"C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13", "C14", "C15", "C16", "C17", "C18", "C19"};
    
    var contract_array: [20]ast.ContractDef = undefined;
    var tops_list: [20]ast.TopLevel = undefined;
    
    for (0..20) |i| {
        contract_array[i] = makeEmptyContract(names[i]);
        if (i > 0) {
            contract_array[i].inherits = names[i-1];
        }
        tops_list[i] = .{ .contract = contract_array[i] };
    }
    
    try resolver.registerTopLevel(&tops_list);

    var checker = Checker.init(&resolver, &diags, allocator);

    const result = checker.checkContract(&contract_array[19]);
    try std.testing.expectError(error.InternalError, result);
}
